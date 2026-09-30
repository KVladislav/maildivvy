# Administration guide

This guide is for the person who runs an installed Maildivvy machine: backup and
restore, the outside probe, health and monitoring, the ban, re-running and upgrading,
and what never to do. Installing it is in [the installation guide](installation.md).

Placeholders are written `<like this>`.

## 1. Backup and restore

The product backs up the database and the fetcher's state, in one run, every day. It
does not copy the mail store or the index. You do, with your own command, and the
product runs that command at the right moment.

### What a run does

`maildivvy-backup.timer` runs `maildivvy-backup.service` daily, with up to an hour of
jitter. A run, as root:

1. pauses collection and fan-out: it stops both timers and waits for a fetch or pass
   already running to finish. It never kills one;
2. dumps the database and archives `/var/lib/maildivvy/fetch`, checks both by what they
   hold, and only then keeps them as `/var/backups/maildivvy/<stamp>/` (the stamp is the
   dump's UTC moment, shaped `YYYYMMDDTHHMMSSZ`);
3. removes the runs beyond `maildivvy_backup_keep`, never the one a failed upgrade holds as
   its way back (`/etc/maildivvy/upgrade-held`), which is kept beside the count;
4. runs your store copy, if one is set, as root in a transient unit of its own,
   `maildivvy-store-copy.service`, with `MAILDIVVY_BACKUP_STAMP=<stamp>` in its
   environment. It runs after the dump, still inside the pause, so the copy is never
   older than the dump it pairs with;
5. starts again the timers that were running, whatever happened above. A run killed
   inside the pause has them started again by its unit's `ExecStopPost`.

A store copy that exits non-zero fails the run and keeps the dump.
`/var/lib/maildivvy/backup/status.json` then says `failed, exit <n>`.

⚠️ **Health reports the dump, never the store copy.** A daily run whose store copy fails
still leaves `backup` PASS. Watch the unit's result (`systemctl show -p Result
maildivvy-backup.service`) or `store_copy` in `status.json` in your monitoring.

### What the store copy must do

- **Keep hardlinks.** Each message is one file with a name in the archive and in every
  mailbox that received it. A copy that breaks the links multiplies the store by its
  holders when it is put back. Copy all of `/srv/maildivvy/store` in one pass. GNU tar
  keeps the links.
- **Keep owners and modes.** The files belong to `vmail`, with its fixed uid.
- **Be taken inside the backup's pause, by the store-copy command.** Only such a copy
  pairs with its dump. With a dump newer than the store, mail that arrives after a
  restore can be skipped; with a dump older than the store, mail is collected and stored
  twice, and what people deleted comes back.
- **The index is optional.** `/srv/maildivvy/index` may be left out. Dovecot rebuilds it,
  at the cost of clients synchronising again.

A command of this shape keeps one tar per run, named by its stamp:

```
tar -C /srv/maildivvy -cf <copy directory>/store-$MAILDIVVY_BACKUP_STAMP.tar store
```

⛔ A copy you take on your own schedule, outside the command, is not a valid pair for any
dump.

### Restore

1. Choose the run: `ls /var/backups/maildivvy`. On a machine rebuilt from nothing,
   install it first with the same `vmail` ids, then copy the run's directory back into
   `/var/backups/maildivvy`, owned by root.
2. Put the store back first, from the copy that run made inside its pause, and no other.
   End open IMAP sessions (`doveadm kick '*'`), empty the store filesystem (it is a mount
   point: remove what is in it, not the directory), and extract with owners and modes
   kept, for the tar above `tar -C /srv/maildivvy -xpf <copy directory>/store-<stamp>.tar`.
   Check that a message a person received has a link count above 1
   (`stat -c %h <file>`).
3. `sudo /opt/maildivvy/bin/maildivvy-backup --restore <stamp>`. It pauses collection and
   fan-out, unpacks the fetch state beside the live one and checks it, restores the
   database in one transaction, and only then swaps the state in. A database that will
   not restore leaves the state as it was. It does not touch the store.

The database and the fetch state are always restored together. Without the fetch state,
the fetcher collects every provider mailbox's whole window again, and every message in it
is stored twice.

## 2. The outside probe

Health reads publication PASS only from a probe run outside the machine's network. The
probe is [`tools/outside-probe/maildivvy_outside_probe.py`](../tools/outside-probe/maildivvy_outside_probe.py),
one file that needs nothing but Python 3's standard library.

### Where to run it from

From a machine outside the installation's network, reaching the machine the way a mail
client on the internet does. A vantage point is invalid when:

- it is inside the machine's own network. Without hairpin NAT it reads the public address
  as closed whether publication works or not, and the probe cannot tell;
- its network answers the mail ports itself, as some networks do. The probe sees a
  connection with no TLS, no banner, or a certificate that is not ours, and reports
  INVALID;
- it is inside an administrator network. There 443 answers, which the probe reports as a
  FAIL, because 443 must be unreachable from the internet.

### When your public address serves something else on 443

Maildivvy's administration interface must never answer from outside. Your public
address's 443 may still belong to another service, when your router forwards it to
another machine: a web server, or even an SSH server. The probe tells the two apart. On
443 it fails when something answers:

- with the machine's certificate for the mail hostname;
- with the same certificate 993 and 465 served;
- with Maildivvy's sign-in page, behind another certificate or in the clear.

Anything else on 443 is another service, and the check passes. Its reading says
`answers, and not as this machine` and what answered: another certificate, or no TLS at
all. Read it to be sure the service is yours. This holds only when 993 and 465 completed
TLS with the machine's certificate in the same run. Without that, the probe cannot tell
your other service from the vantage point's network answering 443 itself, and reports
INVALID.

The machine keeps 443 closed to everyone but the administrator networks at its own
firewall, and health's firewall check reads that rule. The outside probe confirms it
from outside.

### Running it and recording the result

```
python3 maildivvy_outside_probe.py <mail hostname> [--address <public address>] > probe-result.json
```

`--address` probes a public address other than what the name resolves to. For a
certificate your clients' trust store does not know, add `--cafile` with a copy of
`/etc/ssl/certs/<mail hostname>.crt`.

It checks that 993 and 465 complete TLS with the machine's certificate; that the ports
not meant to be published do not answer, and 443 does not answer as this machine (see
above); and that an unauthenticated SMTP
dialogue on 465 is refused `554 5.7.1` at `RCPT TO`, not earlier. It exits 0 for PASS, 2
for FAIL, 3 for INVALID. Then copy `probe-result.json` to the machine and record it:

```
sudo maildivvy-publication record < probe-result.json
```

The record is refused, and nothing changes, for an INVALID result, a result for another
name or another certificate than the one published on this machine, one dated before the
ports were opened, in the future or older than the result already recorded, and any
result while the ports are not published. A FAIL is recorded, and health then reads
publication FAIL.

Health reads publication UNKNOWN again 30 days after the last PASS, and FAIL as soon as
the recorded result names another certificate than the machine's current one. ⚠️ So every
renewal turns publication FAIL until the probe is run again. Run the probe after each
renewal, at least every 30 days, and after any change to the router or the firewall.

## 3. Health

One command checks fifteen subsystems. Run it as its own user:

```
sudo runuser -u maildivvy-health -- /opt/maildivvy/bin/maildivvy-health
```

| form | what it does |
|---|---|
| `maildivvy-health` | runs every subsystem, prints the text, writes `/var/lib/maildivvy/health/health.json` |
| `maildivvy-health --subsystem <name>` | runs one subsystem; writes no file |
| `maildivvy-health --cached [--subsystem <name>]` | runs nothing: reads the JSON file, as a collector should |
| `maildivvy-health --quiet` | the first line and only what is not PASS |
| `maildivvy-health --format prometheus` | any of the above, printed in Prometheus's text format instead of text |
| `maildivvy-health --textfile-dir <dir>` | a run of every subsystem also writes `<dir>/maildivvy.prom`, for node_exporter |

- **States.** Each check is PASS, WARN, FAIL or UNKNOWN. A subsystem takes its worst
  check and the report its worst subsystem, in the order PASS < WARN < UNKNOWN < FAIL.
  UNKNOWN means a reading could not be taken; it is never a PASS.
- **Exit code**: 0 PASS, 1 WARN, 2 FAIL, 3 UNKNOWN, the monitoring-plugin convention. A
  run that cannot run at all exits 3 and writes no file.
- **JSON**: `{"format", "taken_at", "state", "subsystems": [{"name", "state", "checks":
  [{"name", "state", "reading", "problem"}]}], "complete": true}`, replaced whole, `0644`.
- `maildivvy-health.timer` runs the full command every five minutes. The file is stale
  after 15 minutes: `--cached` then adds an UNKNOWN `freshness` check to every subsystem,
  so a stale PASS reads UNKNOWN and a stale FAIL stays FAIL.
- To move a bound from its default, write `<key>=<whole number>` lines in
  `/etc/maildivvy/health.conf`, readable by `maildivvy-health`, by your collector and by
  the interface's user `maildivvy-admin`; it holds no secret, so `0644` does. The keys are
  the defaults in `src/maildivvy/health/settings.py`. A key the program does not know
  stops it, rather than being ignored.

### In the administration interface

The interface's **Health** screen, last in the sidebar, shows the report the timer last
wrote: every subsystem with its state, and every check with its reading and, when not
PASS, what is wrong. It reads `health.json` as `--cached` does and runs nothing, so it
says what the timer last found, never what is true this second; it always shows the
report's time and age. A report older than 15 minutes (the `stale_minutes` bound) is
shown as stale, every subsystem then reading UNKNOWN at best and a FAIL staying FAIL, and
a report that is missing or damaged is shown as no report at all. Each state has its own
colour, with its word beside it: FAIL red, WARN amber, UNKNOWN indigo, PASS green.

Every page's top bar carries the same reading in a few words, linking to the screen:
`Health: PASS · 3 minutes ago`, `Health: FAIL · stale, 42 minutes old` for a stale
report (never PASS), or `Health: no report`, in red like a FAIL, since then nothing is
known.

The overview lists under **Needs attention** every subsystem that is FAIL, with the
report's time, and a report that is stale or cannot be read. WARN and UNKNOWN are not
listed there, since a fresh machine reads UNKNOWN until mail flows: the overview's
**Health** row counts them. The interface is not monitoring: it alerts nobody, so keep
your monitoring connected as below.

Health fails an IMAP login from 127.0.0.1 every five minutes, for a login that cannot
exist. That line in Dovecot's log is health, not an attack.

### How a monitoring system reads it

The product pushes nothing. Your monitoring runs, as any user:

```
/opt/maildivvy/bin/maildivvy-health --cached --subsystem <name>
```

one item per subsystem, and alerts on exit 2 (FAIL) and exit 3 (UNKNOWN), which covers a
stale report. Or it reads `health.json` itself and alerts on `state` and on `taken_at`
older than 15 minutes. Two things to know:

- a fresh machine reads UNKNOWN in `collection`, `store` and `search` until mail has
  arrived, been fanned out and indexed;
- ⚠️ `network/listeners` FAILs on anything listening off loopback other than 22, 443, 993
  and 465, TCP or UDP. A monitoring agent that listens on the network trips it. Use one
  that connects out, or listens on loopback only.

### Monitoring systems

Each of these connects to the machine or reads a file there; none needs a port the
firewall does not already open. Keep every agent you add off the network, as above.

#### Prometheus

Health writes a file for node_exporter's textfile collector when you name a directory in
the settings and run the installation again:

```yaml
maildivvy_health_textfile_dir: /var/lib/node-exporter
```

When the directory does not exist, the health step creates it, the `maildivvy-health`
user's (`0755`). An existing directory must already be `maildivvy-health`'s: step 1
refuses one that is not, and the installation never re-owns a directory it did not
create. Every run of the timer replaces `maildivvy.prom` in it whole. node_exporter reads
one textfile directory: if it already reads one, make that directory `maildivvy-health`'s
yourself (`sudo chown maildivvy-health: <directory>`; root's collectors go on writing
there) and name it here. Point node_exporter at it, on loopback only:

```
node_exporter --collector.textfile.directory=/var/lib/node-exporter --web.listen-address=127.0.0.1:9100
```

Your Prometheus then needs a way in that is not a new listening port: an agent on the
machine that scrapes `127.0.0.1:9100` and sends out, such as Prometheus in agent mode with
`remote_write` (its own web address bound to `127.0.0.1` as well), or a scrape through an
SSH tunnel from an administrator network.

The file, and `maildivvy-health --format prometheus`, carry:

| metric | labels | value |
|---|---|---|
| `maildivvy_check_state` | `subsystem`, `check` | 0 PASS, 1 WARN, 2 FAIL, 3 UNKNOWN |
| `maildivvy_subsystem_state` | `subsystem` | the subsystem's worst check, the same numbers |
| `maildivvy_health_last_run_timestamp_seconds` | none | when the checks were taken |

⚠️ The numbers are the exit codes, not the order of severity: FAIL is 2 and UNKNOWN 3.
Compare with `==`, never `>`. The file says nothing about its own age: a timer that has
stopped leaves the last states in place, so alert on the timestamp too. Alert rules:

```yaml
groups:
  - name: maildivvy
    rules:
      - alert: MaildivvyFail
        expr: maildivvy_subsystem_state == 2
        labels: {severity: critical}
        annotations:
          summary: "Maildivvy {{ $labels.subsystem }} is FAIL"
          description: "Run maildivvy-health --subsystem {{ $labels.subsystem }} on the machine for the reason."
      - alert: MaildivvyUnknown
        expr: maildivvy_subsystem_state == 3
        for: 15m
        labels: {severity: critical}
        annotations:
          summary: "Maildivvy {{ $labels.subsystem }} cannot be read"
      - alert: MaildivvyWarn
        expr: maildivvy_subsystem_state == 1
        for: 1h
        labels: {severity: warning}
        annotations:
          summary: "Maildivvy {{ $labels.subsystem }} is WARN"
      - alert: MaildivvyHealthStale
        expr: time() - maildivvy_health_last_run_timestamp_seconds > 900
        labels: {severity: critical}
        annotations:
          summary: "Maildivvy health has not run for 15 minutes"
      - alert: MaildivvyHealthAbsent
        expr: absent(maildivvy_health_last_run_timestamp_seconds)
        for: 15m
        labels: {severity: critical}
        annotations:
          summary: "No Maildivvy health metrics are scraped"
```

`MaildivvyUnknown` waits 15 minutes because a fresh machine reads UNKNOWN until mail has
arrived; lengthen it until then, rather than dropping it.

#### Zabbix

Run the Zabbix agent with active checks only, so it listens on no port
(`StartAgents=0`, `ServerActive=<your Zabbix server>`), and add a user parameter that
reads the report file:

```
# /etc/zabbix/zabbix_agentd.d/maildivvy.conf
UserParameter=maildivvy.health[*],/opt/maildivvy/bin/maildivvy-health --cached --subsystem $1 >/dev/null 2>&1; echo $?
```

Create one active item per subsystem, `maildivvy.health[host]`, `maildivvy.health[tls]`
and so on, numeric, every five minutes, and triggers on each:

```
last(/<host>/maildivvy.health[tls])=2    FAIL, high
last(/<host>/maildivvy.health[tls])=3    UNKNOWN, high (a stale report included)
last(/<host>/maildivvy.health[tls])=1    WARN, warning
nodata(/<host>/maildivvy.health[tls],15m)=1    the agent has stopped reporting
```

The item's value is the exit code; the reason is in `maildivvy-health --subsystem <name>`
on the machine.

#### Nagios and Icinga

The command is a monitoring plugin already: its exit code is the service state and its
first line the output. Reach it through SSH, which the firewall opens to the administrator
networks, rather than through an agent that listens. Give your monitoring host a key for
a user of its own on the machine, then:

```
# Nagios
define command {
    command_name    check_maildivvy
    command_line    $USER1$/check_by_ssh -H $HOSTADDRESS$ -l nagios -C "/opt/maildivvy/bin/maildivvy-health --cached --subsystem $ARG1$"
}
define service {
    use                     generic-service
    host_name               mail
    service_description     maildivvy tls
    check_command           check_maildivvy!tls
}
```

```
// Icinga 2
apply Service "maildivvy-" for (subsystem in ["host", "network", "ban", "tls", "dovecot",
    "postfix", "milter", "antivirus", "spam", "search", "collection", "store", "database",
    "interface", "backup"]) {
  check_command = "by_ssh"
  vars.by_ssh_logname = "nagios"
  vars.by_ssh_command = "/opt/maildivvy/bin/maildivvy-health --cached --subsystem " + subsystem
  check_interval = 5m
  assign where host.vars.maildivvy
}
```

Nagios and Icinga treat exit 3 as UNKNOWN, as health does, so a stale report is an
UNKNOWN service there too.

### The subsystems

| subsystem | checks | common WARN and FAIL causes |
|---|---|---|
| `host` | store and index mount, free space on each, memory, swap | FAIL: a data filesystem not mounted (with one disk: a data directory not on the shared ext4 or xfs filesystem); under 10 % free (15 % with one disk); under 256 MiB available. WARN: under 20 % free (30 % with one disk), under 512 MiB, no swap, swap over half used |
| `network` | listeners, firewall, containers, publication | FAIL: a listener off loopback that is not expected; incoming traffic not dropped by default; 22 or 443 open to anywhere; 993 or 465 open without step 19's record; a container publishing a port; the last probe failed, or it proved another certificate. UNKNOWN: no probe result recorded, or older than 30 days |
| `ban` | fail2ban, jails, filter, rate limits | FAIL: fail2ban not running, a jail not loaded, the Dovecot filter not matching a real failure line, the rate-limit chain missing |
| `tls` | mode, expiry, renewal | WARN: a test certificate mode; under 21 days left (under 30 for a provided certificate, which nothing renews). FAIL: under 7 days; a port serving another certificate than the published one; the renewal timer stopped or its last run failed |
| `dovecot` | IMAP login, configuration, Sent hook | FAIL: no answer on 993; the password database not answering; the effective configuration not the product's. WARN: a sent message got no archive name in the last 24 h |
| `postfix` | submission, transports, milter binding, queue | FAIL: 465 not greeting or not offering AUTH; the milter not bound on submission; a message queued over 24 h. WARN: over 60 min, usually a provider refusing the relay (`postqueue -p`) |
| `milter` | running, socket, answers | FAIL: not running, socket missing or of the wrong group, no negotiation. Every submission is deferred meanwhile |
| `antivirus` | daemon, signatures, held mail, upstream release | FAIL: ClamAV not answering (mail waits at the provider); a mailbox held; signatures over 7 days old; a newer upstream release unshipped for over 7 days. WARN: signatures over 48 h; a newer upstream release |
| `spam` | scores, sender rule, container, modules, configuration log, repin | FAIL: no probe score; the product's own rule did not run; the container down; a required module off; a configuration error since start; a newer rspamd patch released, so repin ([the roles' README](../ansible/README.md)) |
| `search` | index plugin, search | FAIL: the full-text plugin not loaded, or a search that read the messages instead of the index. UNKNOWN until an archive holds mail |
| `collection` | each external mailbox, fetch runs, deletion windows, fetcher, collection timer | FAIL: the provider refused the stored password; the last fetch failed; a mailbox not fetched for 30 min; a mailbox frozen (only **Resume** on the fetch screen ends it); the fetch timer stopped. WARN: a message skipped after an hour of failures, naming the date the provider deletes it; paused while a backup runs |
| `store` | ledger, link classes, fan-out timer, fan-out, requests | FAIL: a name in a mailbox with no delivery row; the pass failed or has not run for 10 min. WARN: a request failed in the last 24 h (its reason is on its row) |
| `database` | answers, schema | FAIL: PostgreSQL not answering; a migration missing or unknown |
| `interface` | through the proxy | FAIL: no answer on 443, or the application behind nginx not answering |
| `backup` | newest run, backup timer | FAIL: no run yet, or the newest older than 48 h; the timer stopped |

## 4. The ban

fail2ban watches Dovecot and Postfix through the journal, in two jails: `dovecot`
(failed IMAP logins) and `postfix` (failed SASL logins on 465). Five failures in ten
minutes ban the source for an hour (`maxretry`, `findtime` and `bantime`, role defaults
in `ansible/roles/ban/defaults/main.yml`).

- A ban blocks **every TCP port** of the source, in fail2ban's own nftables table.
- Loopback and every administrator network are never banned.
- Per-source rate limits also apply to new connections to 993 (30 a minute, burst 60)
  and 465 (10 a minute, burst 20). Administrator networks and loopback are not limited.

**To see who is banned**: `sudo fail2ban-client status dovecot` and
`sudo fail2ban-client status postfix`.

**To lift a ban**: `sudo fail2ban-client set <jail> unbanip <address>`, for each jail
that lists it. Fix the cause first, usually a device with an old password: failures for
an address stay counted for ten minutes even across an unban, so one more failure bans
it again.

## 5. Re-running and upgrading

Re-running the installation over an installed machine is safe and is how the product is
changed: it checks every setting, proves every step again, and changes only what
differs. New code in `/opt/maildivvy` is written whole, the schema applier adds only the
migrations the database lacks, and the milter and the interface restart when their code
is newer than the running process.

### Upgrades

Maildivvy is released as 0.x versions. The machine records the version it runs in
`/etc/maildivvy/version`, and the release carries its own in `VERSION`. To upgrade,
unpack the new release beside the old one and run its installer, as for the first
installation, inside `tmux` or `screen` so that the upgrade goes on if your SSH session
drops:

```
tar -xzf <new release tarball>
cd <new release directory>
sudo ./maildivvy-install
```

The installer reads the installed version before anything changes, and:

| On the machine | This release | What it does |
|---|---|---|
| no Maildivvy | any | installs it |
| a first installation that did not finish (`/etc/maildivvy/installing`) | any | installs it again |
| X.Y.Z | the same X.Y.Z | runs every step again, which proves the machine; no backup |
| any version | an older one | refuses: a release is never installed over a newer one |
| 0.N.x | a newer 0.N.y or 0.(N+1).y | upgrades it |
| 0.N.x | 0.(N+2) or later, or 1.0 or later | refuses: upgrade to 0.(N+1) first, so each step between versions is one that was tested |
| M.N.x, from 1.0 | any newer M.y.z | upgrades it |
| M.N.x, from 1.0 | a newer major | refuses: that release's notes say how to reach it |
| our database, no version file | a 0.1 release | upgrades it: the machine was installed before 0.1.0, which recorded no version |
| our database, no version file | any other release | refuses: upgrade it with a 0.1 release first |

A refusal says why and changes nothing.

An upgrade runs in this order:

1. step 1 of the new release checks the settings, the disks and the certificate, and
   refuses before it changes anything (once they pass, it installs any base package the
   new release adds), so a problem there stops the upgrade before any change;
2. collection and fan-out are paused, as a backup pauses them. The pause is recorded in
   `/etc/maildivvy/upgrade-paused.json`, so a run that was killed has them started again
   by the next one;
3. a backup is taken, as a run of `maildivvy-backup.service`, your store copy included
   when one is set ([backup and restore](#1-backup-and-restore)). The installer prints
   its stamp: `backup <stamp> taken before the upgrade`. Without
   `maildivvy_backup_store_copy` it warns first that the backup will not hold the store:
   copy the store yourself before you go on, if you may need to go back;
4. the new release's migrations are applied, each in its own transaction, with the
   applier of the new release;
5. every installation step runs, as on any re-run. Collection and fan-out stay paused
   through every step;
6. the new version is written to `/etc/maildivvy/version`;
7. collection and fan-out are started again, those that were running before.

The upgrade stops at the first failure.

- **If step 1 refuses or the backup fails**, nothing else has run: the installer says
  `The upgrade stopped before any change`, collection and fan-out run as before, and
  the machine runs the version it ran. Fix what it names (for the backup, usually its store
  copy: `journalctl -u maildivvy-backup.service`) and run the installer again.
- **If a migration or a step fails**, the version file still names the old version, and
  the installer prints the backup's stamp and the way back. Once a migration was applied,
  collection and fan-out **stay paused**, since the database may be ahead of the programs
  that run: they start again at the end of the next installer run that finishes (the old
  release's, after a restore, or the new one's). The installer records that backup's stamp
  in `/etc/maildivvy/upgrade-held`: until an upgrade finishes, every later run keeps
  collection paused whatever fails, and names that backup as the way back, since its own
  backup already holds the new migrations; the backup keeps that run beside
  `maildivvy_backup_keep` until an upgrade finishes. On a machine from before 0.1.0 the
  first version's backup runs until the upgrade installs the new one, and it does not know
  the hold, so the installer also keeps a hard-linked copy of that run as
  `/var/backups/maildivvy/.held-<stamp>`; if the run itself is gone, the installer prints
  the `cp -al` that puts it back. Either fix what failed and run the new
  installer again, which takes a new backup and goes on; or go back:
  1. restore that run as [Restore](#restore) says: the store from the copy that run made
     (from your own copy of it when no store copy is set), then
     `sudo /opt/maildivvy/bin/maildivvy-backup --restore <stamp>`;
  2. run the installer of the old release again, from its unpacked tarball. It finds its
     own version installed, runs every step again, which starts collection and fan-out,
     and removes `/etc/maildivvy/upgrade-paused.json` and `/etc/maildivvy/upgrade-held`.
     For a machine from before 0.1.0, the way back is its own installation run from the
     control machine, which does not know these two files: remove them, and the
     `.held-<stamp>` copy, after it (the installer prints the command).

Keep the unpacked tarball of the release you run until the next upgrade has passed: it is
the way back.

A machine installed from a control machine is upgraded the same way: the control-machine
run recorded its version ([the installation guide](installation.md#from-a-control-machine)).
From then on, run the upgrade with `maildivvy-install`: a control-machine run of another
version is refused, and so is any control-machine run of this release on a machine from
before 0.1.0 (our database, no version file, no unfinished installation), which
`maildivvy-install` alone upgrades, or one with neither record whose database does not answer.

From 0.1.0 on, the initial schema never changes; every change to the database is a new
migration, applied by the upgrade.

### The fetch period

The fetcher runs every three minutes. The period is a role default,
`maildivvy_fetch_minutes` (`ansible/roles/programs/defaults/main.yml`), which the
settings file may override ([the installation guide § 2](installation.md#2-install-time-settings))
as a whole number of minutes that divides an hour (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30
or 60). Before you raise the frequency against a
provider, read the provider's declared login delay (`LOGIN-DELAY` in its POP3
capabilities). An enforced delay shows as refused logins in the `collection` subsystem.

## 6. Local mail is not delivered

Postfix accepts mail only on authenticated submission, port 465. Nothing listens on
port 25, only root may use `sendmail`, and nothing on the machine delivers mail to a
local user. So cron output, and any other mail a system service addresses to a local
user, is not delivered anywhere. Send it to the journal instead (`MAILTO=""` in a
crontab), and let your monitoring read health.

## 7. What changes nothing, and what you must never do

These are safe at any time:

- re-running the installer of the release the machine runs: every setting is checked
  again, and a step whose work is in place changes nothing. It takes no backup. From a
  control machine, the same version may also be run again with `--tags <role>`, those
  steps alone; `maildivvy-install` has no `--tags` and always runs every step;
- `maildivvy-health` in any form: it writes only its own report;
- `maildivvy-backup` by hand, or starting its unit: it pauses and resumes collection;
- running the outside probe and recording its result.

Never do these:

- ⛔ **Never change Dovecot's `mailbox_list_storage_escape_char` on a machine that holds
  mail.** Folder names map to directories through it; changing it moves every folder
  with a dot in its name out from under its mail.
- ⛔ **Never run `ufw disable`, `ufw reload` or `ufw default ...` on an installed
  machine.** Each one leaves every port open for a moment. Change the firewall through
  the settings and a re-run.
- ⛔ **Never open 993 or 465 by hand.** Step 19 opens them, and only after the ban is
  proved. Health reads them open without that step as a FAIL.
- ⛔ **Never run `apt autoremove`.** mpop is built on the machine and its libraries are
  held only by being marked manual.
- ⛔ **Never change `vmail`'s uid or gid.** The store belongs to them, and the install
  refuses a machine whose `vmail` has other ids.
- ⛔ **Never configure a provider host by IP address.** The forms refuse one, and so does
  the database.
- ⛔ **Never restore a dump with a store older than it**, or without its fetch state.
- **Do not edit the files the install writes** (`/etc/dovecot/conf.d`, Postfix's
  parameters, `/etc/clamav/clamd.conf`, `/etc/maildivvy/rspamd`, the fail2ban files). A
  re-run puts them back. Change the settings instead.
- **Do not repin rspamd other than through its installation step**, digest and tag
  changed together ([the roles' README](../ansible/README.md)).
