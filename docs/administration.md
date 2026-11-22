# Administration guide

This guide is for the person who runs an installed Maildivvy machine: backup and
restore, the outside probe, health and monitoring, the ban, re-running and upgrading,
collection over IMAP and its snapshots, importing mail from message files, and what never
to do. Installing it is in
[the installation guide](installation.md).

Placeholders are written `<like this>`.

## 1. Backup and restore

The product backs up the database and the fetcher's state, in one run, every day. It
does not copy the mail store or the index. You do, with your own command, and the
product runs that command at the right moment. A mailbox collected over IMAP keeps its
fetcher's state, where its collection stands, on its row in the database.

⚠️ **The run stays on the machine.** `/var/backups/maildivvy` is on the system disk, so
your command must copy the run's directory off the machine with the store. A store copy
without it restores mail with no accounts, passwords, credentials or delivery record.

### What a run does

`maildivvy-backup.timer` runs `maildivvy-backup.service` daily, with up to an hour of
jitter. A run, as root:

1. pauses collection, fan-out and the snapshots of IMAP mailboxes: it stops their three
   timers, `maildivvy-fetch.timer`, `maildivvy-pass.timer` and `maildivvy-snapshot.timer`,
   and waits for a fetch, a pass or a run of snapshot slices already running to finish.
   It never kills one. A run of slices ends within about an hour, so the pause may wait
   that long ([snapshots](#a-snapshot-of-every-folder));
2. dumps the database and archives `/var/lib/maildivvy/fetch`, checks both by what they
   hold, and only then keeps them as `/var/backups/maildivvy/<stamp>/` (the stamp is the
   dump's UTC moment, shaped `YYYYMMDDTHHMMSSZ`);
3. removes the runs beyond `maildivvy_backup_keep`. Two are kept beside the count: the one
   a failed upgrade holds as its way back (`/etc/maildivvy/upgrade-held`), and the newest
   whose store copy succeeded, so nights of a failing copy never remove the last run
   that has a store to restore with;
4. runs your store copy, if one is set, as root in a transient unit of its own,
   `maildivvy-store-copy.service`, with `MAILDIVVY_BACKUP_STAMP=<stamp>` in its
   environment. It runs after the dump, still inside the pause, so the copy is never
   older than the dump it pairs with. A copy that exits 0 leaves `store-copied` in the
   run's directory;
5. starts again the timers that were running, whatever happened above. A run killed
   inside the pause has them started again by its unit's `ExecStopPost`.

The pause is recorded in `/var/lib/maildivvy/backup/paused.json` for as long as it lasts,
and the record is the pause itself: while it is there, the fetch, pass and snapshot units
refuse to start whoever starts them (a reboot, a re-run of the installer, you by hand), and
the installer's re-run leaves the timers to the backup that holds them. Health reads a
record left with no backup running as WARN and says how to end it.

A store copy that exits non-zero fails the run and keeps the dump.
`/var/lib/maildivvy/backup/status.json` then says `failed, exit <n>`, and
`newest_store_copied` names the newest run that has `store-copied` (null when none kept
has).

⚠️ **Health reports whether the store copy ran, never the copy itself.** A run whose
store copy failed reads `backup/newest run` WARN, naming the newest run with a store copy
and its age, the restore point you actually have; with none kept it says no dump can be
restored with the store. The command's own output is in
`journalctl -u maildivvy-backup.service`. A copy that exits 0 but wrote nothing usable is
still PASS: check the copy where it landed.

### What the store copy must do

- **Take the run with it.** Copy `/var/backups/maildivvy/$MAILDIVVY_BACKUP_STAMP`, the
  run the copy pairs with, to the same place as the store, off the machine.
- **Keep hardlinks.** Each message is one file with a name in the archive and in every
  mailbox that received it. A copy that breaks the links multiplies the store by its
  holders when it is put back. Copy all of `/srv/maildivvy/store` in one pass. GNU tar
  keeps the links.
- **Keep owners and modes.** The files belong to `vmail`, with its fixed uid.
- **Be taken inside the backup's pause, by the store-copy command.** Only such a copy
  pairs with its dump. With a dump newer than the store, mail that arrives after a
  restore can be skipped; with a dump older than the store, mail is collected and stored
  twice, and what people deleted comes back.
- **Know that it carries the snapshots.** The snapshots of IMAP mailboxes are in the
  store, under `/srv/maildivvy/store/_snapshots`, and in no dump: a copy of the whole
  store carries them, and grows by them until they are discarded
  ([snapshots](#a-snapshot-of-every-folder)).
- **Leave the index out, or copy it whole with the store.** `/srv/maildivvy/index` may
  be left out: Dovecot rebuilds it, at the cost of clients synchronising again and the
  archive's folders numbered again, which the pass sets right on its next tick by each
  file's name (restore step 4). Copying a part of it costs the same: an archive whose
  `ctl/` tree is lost and whose `idx/` tree is kept numbers every message again.

A command of this shape keeps, in a directory off the machine, one tar per run named by
its stamp, and the run beside it:

```
tar -C /srv/maildivvy -cf <copy directory>/store-$MAILDIVVY_BACKUP_STAMP.tar store && cp -a /var/backups/maildivvy/$MAILDIVVY_BACKUP_STAMP <copy directory>/
```

⛔ A copy you take on your own schedule, outside the command, is not a valid pair for any
dump.

### Restore

1. Choose the run: `ls /var/backups/maildivvy/*/store-copied` names the runs whose store
   copy succeeded. On a machine rebuilt from nothing, choose among the runs your command
   copied (the copy holds no `store-copied`: it is taken before the mark), install the
   machine first with the same `vmail` ids and the release that took the run, which its
   `manifest.json` names as `release`, then copy the run's directory back, for the
   command above `cp -a <copy directory>/<stamp> /var/backups/maildivvy/`, owned by root.
   Upgrade after the restore, as usual.
2. Put the store back first, from the copy that run made inside its pause, and no other.
   End open IMAP sessions (`doveadm kick '*'`), empty the store filesystem (it is a mount
   point: remove what is in it, not the directory), and extract with owners and modes
   kept, for the tar above `tar -C /srv/maildivvy -xpf <copy directory>/store-<stamp>.tar`.
   Check that a message a person received has a link count above 1
   (`stat -c %h <file>`). Emptying the store removes `_snapshots` too: when the copy
   holds none, `maildivvy-snapshot.service` cannot start (systemd reports `226/NAMESPACE`,
   since its one writable path is missing) until the installer runs again or you make it:
   `sudo install -d -o vmail -g vmail -m 0700 /srv/maildivvy/store/_snapshots`.
3. `sudo /opt/maildivvy/bin/maildivvy-backup --restore <stamp>`. It pauses collection and
   fan-out, unpacks the fetch state beside the live one and checks it, swaps the state
   in, and only then restores the database in one transaction: a restore stopped between
   the two leaves the state older than the database, which fetches mail again, never
   newer, which would skip it. The transaction replaces everything the database holds, so
   what a failed upgrade's migrations added goes too, and reads the grants back before it
   commits. A database that refuses the restore gets the state back as it was. One that
   may have committed (psql lost its server or was stopped after the COMMIT went out)
   keeps the restored state, leaves collection and fan-out stopped and says so: run the
   same restore again. Until then the daily backup refuses to run and names that
   restore, and nothing starts collection. It does not touch the store. Before it pauses
   anything it compares the run's `manifest.json` with the machine: a run whose
   migrations are not the ones the installed programs ship is refused, unless the release
   that took it is the one `/etc/maildivvy/version` names (the way back from a failed
   upgrade) and it was not taken while a failed upgrade was held. A run from before 0.3.0
   names neither and is restored with a warning: restore it only on the release that took
   it. Run it inside `tmux` or `screen`: a
   run whose terminal closes, or that is stopped with Ctrl-C, stops where it is, and the
   restore must then be run again.
4. After the next pass, read `store/fan-out skips` in health. A machine rebuilt from
   nothing has no index for the store you put back, so Dovecot numbers each archive
   folder's messages again. The pass finds every row's file by its name, gives the row
   the file's new number, records and links a message it had not read yet, and takes the
   folder's new numbering, in its first tick; `store/fan-out skips` warns of each folder
   it set right, naming it (`journalctl -u maildivvy-pass.service -g 'maildivvy-pass:
   renumbered:'`). Nothing is for you to run. A row whose file is not in the store you
   put back keeps no number, and the line counts it.

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
`/etc/maildivvy/tls/<mail hostname>.crt`.

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
- The `store` subsystem's `ledger` check holds to the ledger only the names in people's
  mailboxes that changed since the last run, and keeps a finding until it is resolved.
  `maildivvy-health-ledger.timer` runs `maildivvy-health --ledger-pass` every night at
  03:30, which reads every name; its result is the `daily ledger` and `link classes`
  checks, with their age, UNKNOWN once older than 48 hours (`ledger_pass_hours`). The
  same pass holds each domain archive to the ledger: a message the pass moved past
  without recording is in the archive and nobody has it, and `daily ledger` is FAIL
  naming its domain, folder and UID for as long as that lasts, with the command that
  records it. A defect it found stays FAIL until the next pass: once you have resolved
  it, run `systemctl start maildivvy-health-ledger.service`.
- To move a bound from its default, write `<key>=<whole number>` lines in
  `/etc/maildivvy/health.conf`, readable by `maildivvy-health`, by your collector, by
  the interface's user `maildivvy-admin` and by `vmail`, as which the snapshot's slices
  read their reserve from it (unreadable, every slice pauses); it holds no secret, so
  `0644` does. The keys are
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
colour, with its word beside it: FAIL red, WARN amber, UNKNOWN grey, PASS green.

Every page's top bar carries the same reading in a few words, linking to the screen:
`Health: PASS · 3 minutes ago`, `Health: FAIL · stale, 42 minutes old` for a stale
report (never PASS), or `Health: no report`, since then nothing is known. Whenever the
report reads FAIL or is missing, that badge is solid red, the one solid badge in the
interface.

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
| `host` | store and index mount, free space on each and on the root and backup filesystems (read once where they share one), memory, swap | FAIL: a data filesystem not mounted (with one disk: a data directory not on the shared ext4 or xfs filesystem); under 10 % free (15 % with one disk); under 256 MiB available. WARN: under 20 % free (30 % with one disk), under 512 MiB, no swap, swap over half used |
| `network` | listeners, firewall, containers, publication | FAIL: a listener off loopback that is not expected; incoming traffic not dropped by default; 22 or 443 open to anywhere; 993 or 465 open without step 19's record; a container publishing a port; the last probe failed, or it proved another certificate. UNKNOWN: no probe result recorded, or older than 30 days |
| `ban` | fail2ban, jails, filter, rate limits | FAIL: fail2ban not running, a jail not loaded, the Dovecot filter not matching a real failure line, the rate-limit chain missing |
| `tls` | mode, expiry, renewal | WARN: a test certificate mode; under 21 days left (under 30 for a provided certificate, which nothing renews). FAIL: under 7 days; a port serving another certificate than the published one; the renewal timer stopped or its last run failed |
| `dovecot` | IMAP login, configuration, Sent hook | FAIL: no answer on 993; the password database not answering; the effective configuration not the product's. WARN: a sent message got no archive name in the last 24 h |
| `postfix` | submission, transports, milter binding, queue | FAIL: 465 not greeting or not offering AUTH; the milter not bound on submission; a message queued over 24 h. WARN: over 60 min, usually a provider refusing the relay (`postqueue -p`) |
| `milter` | running, socket, answers | FAIL: not running, socket missing or of the wrong group, no negotiation. Every submission is deferred meanwhile |
| `antivirus` | daemon, signatures, held mail, upstream release | FAIL: ClamAV not answering (mail waits at the provider), or answering but not scanning a clean sample clean (mail it fails on is withheld as unscanned); a mailbox held; signatures over 7 days old; a newer upstream release unshipped for over 7 days. WARN: signatures over 48 h; a newer upstream release |
| `spam` | scores, sender rule, container, modules, configuration log, repin | FAIL: no probe score; the product's own rule did not run; the container down; a required module off; a configuration error since start; a newer rspamd patch released, so repin ([the roles' README](../ansible/README.md)); the install prints this one and does not stop on it |
| `search` | index plugin, search | FAIL: the full-text plugin not loaded, or a search that read the messages instead of the index. UNKNOWN until an archive holds mail |
| `collection` | each external mailbox, fetch runs, deletion windows, fetcher, collection timer, snapshots | FAIL: the provider refused the stored password; the last fetch failed, an IMAP mailbox's with the cause `mark` included ([§ 6](#when-an-imap-mailbox-stops-with-mark)); a mailbox not fetched for 30 min; a mailbox frozen (only **Resume** on the fetch screen ends it); the fetch timer stopped. WARN: a message skipped after an hour of failures, naming the date the provider deletes it (a mailbox that keeps its mail at the provider, as every IMAP one does, names the skip in its reading and passes); paused while a backup runs; a snapshot of an IMAP mailbox failed, paused for longer than a day, done without messages the provider refused to send or folders it left out, or asked for or under way for longer than 7 days (its mailbox disabled, unmapped or switched to POP3, or its timer stopped) ([§ 6](#a-snapshot-of-every-folder)) |
| `store` | store hold, ledger, daily ledger, link classes, directories, fan-out timer, fan-out, provider requests, fan-out skips, requests, requests left running, request queue | FAIL: a mailbox whose last fetch was held because the archive's store could not take mail - full, read-only, a folder the mail owner may not write, or Dovecot not answering, or the delivery filter failing on a message of its own as well as on the one in hand - so its mail waits at the provider until a delivery succeeds (for a POP3 mailbox `journalctl -u maildivvy-fetch.service -g 'store cannot take mail'`, for an IMAP one the mailbox's detail on the fetch screen); a name in a mailbox with no delivery row; a message in a domain archive at or below the pass's cursor that no row holds, which the pass skipped and nobody has (`daily ledger` names the domain, the folder and the UIDs: record each with `runuser -u vmail -- /opt/maildivvy/bin/maildivvy-pass --only <domain> --folder <folder> --uid <UID>`, then start the daily pass again; a message that command cannot record either stays FAIL, and the command's own error says why); the pass failed or has not run for 10 min, and when it failed because Dovecot numbered an archive folder again before the pass had named the previous release's rows of it, the folders, which nothing is linked from until you go back to the previous release, run its `maildivvy-pass --only <domain> --folder <folder> --renumber` and upgrade again (`journalctl -u maildivvy-pass.service -g 'maildivvy-pass: no archive names:'`); the last run of the requests that wait on a provider failed, which leaves them queued (`journalctl -u maildivvy-requests.service`); a request left `running` by a pass that was stopped while performing it (below). WARN: a top-up, connect, transfer, deliver-one or release still linking in a domain, whose names have no committed row yet: `ledger` and `daily ledger` name the request and how many names, and list none of them (read again after it; the daily pass waits up to 15 min for it first); a pass or a run of the requests that wait on a provider going for more than 10 min; a mailbox or domain directory no row holds, which a mailbox made later for that person would inherit: one a failed deletion left is removed by the next run of the pass, once what its request names is fixed (its reason is on its row); any other is yours to look at and remove; a message the pass could not record in the last 24 h, which nobody has until you record it with the command its line names (`journalctl -u maildivvy-pass.service -g 'maildivvy-pass: skipped:'`); a day later its line is out of that window, and the daily pass's FAIL above is what still names it; an archive folder Dovecot numbered again in the last 24 h, which the pass set right by each file's name, recording any file no row named: an index tree was lost or put back (`journalctl -u maildivvy-pass.service -g 'maildivvy-pass: renumbered:'`); a request failed in the last 24 h (its reason is on its row); a request queued over 60 min while the pass's timer runs (`journalctl -u maildivvy-pass.service` and `-u maildivvy-requests.service`) |
| `database` | answers, schema | FAIL: PostgreSQL not answering; a migration missing or unknown |
| `interface` | through the proxy | FAIL: no answer on 443, or the application behind nginx not answering |
| `backup` | newest run, backup timer | FAIL: no run yet, or the newest older than 48 h; the timer stopped. WARN: the newest run's store copy failed, naming the newest run that has one, or saying none kept has |

### A request left running

The pass takes a request from the queue before it performs it. A pass stopped in the
middle, by a reboot or a kill, leaves that request `running` until the pass runs again:
`store/requests left running` names each such request and its number. The next run marks
it failed, "the pass was stopped while performing it", followed by what the request
had said until then, for a top-up how many messages it had linked; then ask for it
again on its screen: a top-up goes on from what is linked. The requests that wait on a provider are marked by the next run of
`maildivvy-requests.service`. A request still `running` after that run is the run's own
failure: read its journal.

A pass you run by hand while another run drains the queue leaves the queue to that run
and says so. One run by hand, outside its unit, while health reads, can make this reading
FAIL for a request it is still performing: read again once it has finished.

## 4. The ban

fail2ban watches Dovecot and Postfix through the journal, in two jails: `dovecot`
(failed IMAP logins) and `postfix` (failed SASL logins on 465). Five failures in ten
minutes ban the source for an hour (`maxretry`, `findtime` and `bantime`, role defaults
in `ansible/roles/ban/defaults/main.yml`).

- A ban blocks **every TCP port** of the source, in fail2ban's own nftables table.
- `nftables.service` is masked: its configuration begins with `flush ruleset`, so starting
  it would remove ufw's rules, the bans and Docker's rules at once. Do not unmask it.
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
or their unit file is newer than the running process, even when an earlier run wrote it
and stopped before the restart.

### Upgrades

Maildivvy is released as 0.x versions. The machine records the version it runs in
`/etc/maildivvy/version`, and the release carries its own in `VERSION`. An upgrade is
four things, in this order.

**Read the release's notes.** Read the new version's section of `CHANGELOG.md`, and of
every version between yours and it, before you start. Its **Changed** part names every
setting or behaviour the release changes and what you do about it, and some of those are
yours to do by hand, before or after the upgrade.

**Get and verify the release**, exactly as for the first installation
([the installation guide](installation.md#getting-and-verifying-the-release)): download
the tarball, its `.minisig` and `SHA256SUMS`, check the signature with the key the README
publishes and the sums, and install nothing that fails either.

**Run the new release's installer.** Unpack the new release beside the old one and run
its installer, as for the first installation, inside `tmux` or `screen` so that the
upgrade goes on if your SSH session drops:

```
tar -xzf <new release tarball>
cd <new release directory>
sudo ./maildivvy-install
```

**Check the machine afterwards.**

- `cat /etc/maildivvy/version` names the new version. An upgrade that failed leaves the
  old one there.
- Health reads every subsystem PASS, or UNKNOWN only where it did before:

  ```
  sudo runuser -u maildivvy-health -- /opt/maildivvy/bin/maildivvy-health --quiet
  ```

- Collection runs again:
  `systemctl is-active maildivvy-fetch.timer maildivvy-pass.timer maildivvy-snapshot.timer`
  reads `active` three times, unless you had stopped one yourself.
- When the release's notes mention the outside probe or publication, run the probe again
  from outside and record its result ([the outside probe](#2-the-outside-probe)).

The installer reads the installed version before anything changes, and:

| On the machine | This release | What it does |
|---|---|---|
| no Maildivvy | any | installs it |
| a first installation of X.Y.Z that did not finish (`/etc/maildivvy/installing`) | the same X.Y.Z, or any release while no account, domain or external mailbox exists | installs it again |
| a first installation of X.Y.Z that did not finish, used anyway (an account, a domain or an external mailbox exists) | another release | as for X.Y.Z installed, by the rows below: upgrades it with a backup first, or refuses |
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
2. collection, fan-out and the snapshots' slices are paused, as a backup pauses them,
   after the installer waited for a backup already running to finish. The pause is recorded in
   `/etc/maildivvy/upgrade-paused.json`, so a run that was killed has them started again
   by the next one; while the record is there, a backup starts none of them;
3. a backup is taken, as a run of `maildivvy-backup.service`, your store copy included
   when one is set ([backup and restore](#1-backup-and-restore)). The installer prints
   its stamp: `backup <stamp> taken before the upgrade`. Without
   `maildivvy_backup_store_copy` it warns first that the backup will not hold the store:
   copy the store yourself before you go on, if you may need to go back;
4. the new release's migrations are applied, each in its own transaction, with the
   applier of the new release;
5. every installation step runs, as on any re-run. Collection, fan-out and the
   snapshots' slices stay paused through every step;
6. the new version is written to `/etc/maildivvy/version`;
7. collection, fan-out and the snapshots' slices are started again, those that were
   running before, and a timer the new release installed.

The upgrade stops at the first failure.

- **If step 1 refuses or the backup fails**, nothing else has run: the installer says
  `The upgrade stopped before any change`, collection, fan-out and the snapshots' slices
  run as before, and
  the machine runs the version it ran. Fix what it names (for the backup, usually its store
  copy: `journalctl -u maildivvy-backup.service`) and run the installer again.
- **If a migration or a step fails**, the version file still names the old version, and
  the installer prints the backup's stamp and the way back. Once a migration was applied,
  collection, fan-out and the snapshots' slices **stay paused**, since the database may be
  ahead of the programs
  that run: they start again at the end of the next installer run that finishes (the old
  release's, after a restore, or the new one's). A reboot meanwhile starts their timers,
  but the fetch, pass and snapshot units refuse to run while
  `/etc/maildivvy/upgrade-paused.json` is there. The installer records that backup's stamp
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
     `.held-<stamp>` copy, after it (the installer prints the command);
  3. going back to a release that did not have a timer the new one added (0.2.1 has no
     `maildivvy-snapshot.timer`), stop and disable that timer: the installer prints the
     `systemctl disable --now` that does it.

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

## 6. Collection over IMAP and snapshots

An external mailbox collected over IMAP
([the installation guide](installation.md#a-mailbox-collected-over-imap)) is only read.
Maildivvy opens every folder read-only and reads every message without marking it as
read; it never deletes, moves or flags anything at the provider, and its client refuses
to send any command that could. Its INBOX is collected from where it stood when the
mailbox was enabled, on the fetch's own timer, with the same outcomes, holds and bounded
retry as a POP3 mailbox. Disabling the mailbox keeps that starting point, so enabling it
again collects what arrived while it was disabled. A message skipped after an hour of
failures stays at the provider: health names it in the mailbox's reading and does not
warn, and the journal records it as `auto_skip_message`. Over IMAP that hour is an hour
of runs that stopped on the message, and at least ten of them: a dropped connection over
a message counts as its failure, so the time in which the provider was unreachable, the
timer stopped or a backup paused collection is not counted, and the fetch screen's
"minutes before the automatic skip" stand still through it; past the hour it names the
runs still to come.

### When an IMAP mailbox stops with `mark`

A fetch of an IMAP mailbox that has no starting point it can trust collects nothing and
records the cause `mark`. The fetch screen reads *stopped — no starting point that
matches the provider's INBOX, so nothing is collected until the mailbox is disabled and
enabled again*, and health's `collection` reads FAIL for the mailbox. It follows:

- a new IMAP host or login saved while the mailbox was enabled: the starting point
  belonged to the old server and login, and the change cleared it;
- the provider numbering its INBOX afresh (a new `UIDVALIDITY`), as a migration or a
  restore on its side can: the old starting point no longer names the same messages.

It does not end by itself. After a new host, the password was cleared too: enter it
again in the mailbox's Settings first, or enabling fails with *no password is stored*.
Disable the mailbox and enable it again: enabling checks the password and records where
the INBOX stands now, and collection goes on from there. The journal records it as
`imap_mark_set`, or `imap_mark_reset` with the old starting point and the mailbox's last
fetch, its time and status, so what arrived around then can be looked for at the
provider. Mail that arrived in the INBOX between the last fetch and the new starting
point is not collected; a snapshot copies it.

A new host, login or protocol clears the starting point on a disabled mailbox too, and
the page says so when you save: enabling then sets a new one where the INBOX stands, so
mail that arrived since the last fetch comes in only through a snapshot. Disabling alone
keeps the starting point. The journal's `set_provider_servers`, `set_pop3_login` and
`set_protocol` rows carry the starting point the change cleared, as `mark_cleared`
(`{"uidvalidity": …, "last_uid": …}`), when it cleared one.

Switching an IMAP mailbox back to POP3 is not a way out of a lost starting point: IMAP
left every message at the provider, and the POP3 fetcher has no record of what IMAP
collected, so its first fetch takes every message the provider offers that it has not
taken before, mail already collected over IMAP included. Each is filed again and reaches
every person of the domain a second time, which cannot be undone. The mailbox's form
says so beside the protocol, and the page again when you save.

### A snapshot of every folder

An IMAP mailbox's history, its INBOX from before it was enabled and every other folder,
is not collected. A snapshot copies it, read-only, into the store, for an import of
existing mail to read later; no version yet imports it. Nothing in a snapshot goes
through the scanners or reaches anyone's mailbox. Dovecot can read the tree as a mail
location.

- **Asking for one.** An IMAP mailbox's page has a section, **Snapshot of every folder**.
  **Take a snapshot of every folder** is offered while the mailbox is enabled and has its
  starting point in the INBOX, one snapshot at a time: a done or failed snapshot is
  discarded before another is asked for.
- **How it runs.** Every ten minutes `maildivvy-snapshot.timer` starts a run of
  `maildivvy-snapshot.service`, as the mail owner `vmail`, which gives each snapshot under
  way one slice in turn, the one advanced longest ago first. Each slice takes a lock of
  its own, so a large mailbox never holds up the fetch of the others. A slice runs for up
  to ten minutes, and a large mailbox takes many. A run starts no slice that could end
  more than 55 minutes after the run began, so it ends within an hour; snapshots it had
  no time for go first in the next run. A disabled mailbox's snapshot waits until it is
  enabled again. To take a slice now: `sudo systemctl start maildivvy-snapshot.service`.
  The section's badge says where the snapshot stands, *asked*, *under way*, *a slice
  running*, *paused*, *done* or *failed*, beside the last slice's own words: the folders
  taken of the total, the messages and bytes, and what was left out.
- **What it takes.** Every folder that can be opened, the provider's All Mail, Junk and
  Trash included: some providers keep an archived message in All Mail alone.
  A message the provider shows in several folders is copied once for each. The INBOX is
  taken up to the last message collected, and every other folder up to its last message,
  as they stand when the snapshot starts: mail collected since the mailbox was enabled is
  in both places, and mail moved during the snapshot may be missed or copied twice. The
  first slice lists the folders and reads where each ends; on an account with many
  folders that may take more than one slice. A folder the provider refuses to open or
  search, then or on any later slice, whatever its answer says (a code such as
  `[UNAVAILABLE]` or `[NOPERM]`, none, or a `BAD`), is passed for the others, the slice
  then pauses, and each later slice asks again, up to six times; but a refusal counts
  only when the provider opens and searches the INBOX right after it, so a provider
  refusing the whole account, however long, leaves no folder out, and a slice that
  opens the folder starts the count again. One still refused when six later slices in a
  row have asked again is left out and named, with the server's answer. What was copied
  of it stays, and the manifest's entry for it says where and how much, which the
  slice's words count. A connection that fails while a folder is opened or searched
  counts for nothing: the slice pauses, and the next slice to try that folder opens and
  searches the INBOX first; failing over the folder again then counts as a refusal to
  open it. A folder whose name cannot be a folder here
  (sent outside IMAP's own encoding of names, holding a line break or a NUL, or with `/`
  inside one part of it) is left out and named, and so is one whose directory name in the
  store would be longer than 255 bytes, which deeply nested names outside Latin letters
  reach sooner: IMAP's encoding makes them about three times longer. A folder the
  provider stops listing during the snapshot keeps what was copied of it.
- **Messages the provider refuses.** A message the provider will not send, whatever the
  code of its answer, or one it ends the session over (as Dovecot does for a message it
  cannot read), is passed and recorded in its folder's `refused` in the manifest, but
  only once the provider shows it still sends messages: it sends the next one, or, at a
  folder's end or after ten refused in a row, sends again a message already copied,
  asked in turn: one of the three smallest of that folder's copy, then of each other
  folder's, the INBOX's first (one deleted at the provider since, or refused, proves
  nothing). So a folder the provider refuses whole, or one with nothing copied yet, is
  told from an outage. When it sends none of them and refuses one, the provider is
  refusing the account, not the messages: the slice takes those refusals back and
  pauses, and the next asks for them again, so an outage marks nothing refused. With
  nothing copied in any other folder, a folder whose own copied messages are refused
  waits that way until the provider sends one again. When the session ends over one of
  those copied messages, the slice pauses the same way, but on the seventh slice in a
  row the folder's refusals stay: a copied message the provider now fails over every
  time holds its folder up for about seventy minutes, not for ever. A session ended over
  a message being taken leaves that message refused and pauses the slice: each such
  message costs a slice, so a mailbox with many of them takes hours or days longer, and
  health may warn of it as paused or slow while it still advances. When nothing at all
  is copied yet, or every copied message asked has been deleted, ten refused in a row
  stay refused and pause the slice. A message too slow to download within a whole slice
  is cut off, and so is one over which the connection fails with no answer, closed or
  silent for a minute; cut off again by the next slice, which started with it, it stays
  refused; once the provider sends it, the cut-off is forgotten. Once every folder is
  taken, each
  later slice asks for the refused messages again, up to six times, about an hour: one
  sent then is copied, one deleted meanwhile is dropped from the list. The snapshot then
  ends *done* with the rest not copied: its badge reads *done, N not copied* and health
  warns. A snapshot that left folders out reads *done, N folders left out*, and health
  warns too. To try again, discard it and ask for another.
- **Where.** `/srv/maildivvy/store/_snapshots/<id>/`, the mailbox's page shows which:
  a Maildir++ tree in `Maildir/`, with `manifest.json` beside it, owned by `vmail` with
  mode `0700`. The manifest names each folder as the provider does, with its attributes
  (`\All`, `\Junk`, `\Trash` and the rest), the server it was taken from, and what was
  left out and why, with what was copied of each folder left out.
- **Free space.** A slice stops, *paused*, before the store's filesystem would fall
  under health's warn level for its disk layout, in space or in inodes: 20 % free with
  separate disks, 30 % on one disk (`disk_warn_percent` and `single_disk_warn_percent`
  in `health.conf`). Every slice tries again, so the snapshot goes on once there is
  room. A snapshot never takes the room the mail still arriving needs.
- **Paused and failed.** A slice also pauses when the provider cannot be reached,
  refuses the login or answers with an error, when the store refuses a write, when the
  free space cannot be read (`health.conf` not valid, or not readable by `vmail`, which
  the slices run as, or `/etc/maildivvy/disks.json` missing), or while no password is
  stored, and every slice tries again. A snapshot
  fails, and nothing takes it up again, when the provider numbered its INBOX afresh, when
  the mailbox's server or login changed since the snapshot started, when the mailbox has
  no starting point at its first slice, or on a fault of Maildivvy's own; the last
  slice's words say which. A snapshot of a mailbox switched to POP3 is taken no further:
  it stays as it was, shown on the mailbox's page, until it is discarded. Health's
  `collection` warns for a snapshot failed, paused for longer than a day, or done
  without messages the provider refused or folders it left out, and for one asked for or under way for longer
  than 7 days since it began or was asked: no slice is taking it (its mailbox disabled,
  with no domain in front of it or switched to POP3, or `maildivvy-snapshot.timer`
  stopped).
- **Discard.** **Discard the snapshot…** in the mailbox's danger zone, then **Discard the
  snapshot** on its confirmation page, removes the whole tree; nothing at the provider
  changes. The pipeline does it within about a minute, or, while a slice is running,
  once that slice has ended, up to its ten minutes. Deleting the external mailbox
  removes its snapshot too.
- **A provider's cap on downloads.** Nothing limits what a snapshot downloads in a day:
  its slices take what the provider sends, one after another. Some providers cap what an
  account may download over IMAP in a day and lock the account past the cap, its web
  sign-in included, for up to a day; the mailbox's collection and its owner's own mail
  programs are then refused too. At such a provider, ask for a snapshot only of a
  mailbox whose copy stays well under the day's cap, counting the second copy of each
  message in All Mail. The mailbox's page says so beside **Take a snapshot of every
  folder**.
- **Backups.** A snapshot is in no dump. Your store copy carries it, since it copies the
  whole store ([what the store copy must do](#what-the-store-copy-must-do)). A backup and
  an upgrade pause the slices with collection: they stop the snapshot's timer and wait
  for a run of slices already going to end, up to about an hour, and never kill it.

## 7. Importing mail from a directory of message files

`maildivvy-import` files mail people kept elsewhere into the machine: a directory of
whole message files, one RFC 5322 message per file, as a migration tool parses them out
of old client stores. Incoming mail goes into a domain archive's INBOX, a person's sent
mail into a folder of its year in their Sent (`Sent/2016`). Nobody is given the incoming
mail until you top it up: people get the history afterwards with the top-up on their
mailbox's page, one request per person, in a folder of each year under `Archives`
(`Archives/2016`), never in their INBOX.

### Before you start

- **A domain for every address.** The import names a domain by its label and creates
  nothing: an address that is still collected has its domain already; one with no live
  feed gets a free domain, added in the administration interface, and is imported into
  that.
- **Stage the files on the store's filesystem**, under `/srv/maildivvy/store/_imports/`,
  which the installation makes, owned by `vmail` with mode `0700`. Files there are
  renamed into the store, so the store holds one copy and the staging tree empties as
  the import goes. Each must be owned by `vmail` with one link: copy them in, never
  hardlink them. Files anywhere else are copied instead and left where they were.
- **Room.** The import stops before a copy would take the store's filesystem under
  health's warn level (20 % free, 30 % on one disk). A rename takes no room, but the
  files need it once. While `_imports` holds files, your store copy carries them like
  the rest of the store.
- **Index size.** Measured with small messages: Dovecot's index takes about 400 bytes a
  message, and the full-text index about 3.3 KB a message once a mailbox has been
  searched. Size the index filesystem for every person's mailbox, since a top-up gives
  each person a name for every message in range.
- **The first search is slow.** A search indexes what it searches: a person given
  hundreds of thousands of messages waits minutes for their first search (12 minutes for
  500,000 on a small test machine), and their client sees failed searches until then.
  Health's `search` reading reads FAIL while the archive's index catches up.

### Running it

Run every import as `vmail`, each first with `--dry-run`, which reads the source and the
ledger and prints the results without writing anything:

```
runuser -u vmail -- /opt/maildivvy/bin/maildivvy-import incoming --domain <label> \
    --source /srv/maildivvy/store/_imports/<address>/incoming --dry-run
runuser -u vmail -- /opt/maildivvy/bin/maildivvy-import sent --domain <label> \
    --login <person> --source /srv/maildivvy/store/_imports/<address>/sent/<person>
```

- `--manifest <tsv>` reads the files a manifest names, one per line,
  `path<TAB>sha256<TAB>size<TAB>received<TAB>flags`: the path relative to `--source`, the
  received moment in ISO-8601 with `Z` or an offset (empty: the message's Date, else the
  file's modification time), the flags in Maildir's letters `S`, `R`, `F`, `D` (empty:
  none). A row whose hash or size is not the file's refuses that file. Without a manifest
  every message is read, and marked read.
- **The received moment** of a message is permanent: it is the date its mail client
  sorts by, the date a top-up selects by, and part of its file's name. None is taken from
  the future. A message whose Date is more than a day after its file's modification
  time (old spam is often dated years ahead) gets that time instead, and its line says
  so. So keep the files' modification times when you stage them (`cp -p`, `rsync -t`): a
  message with no Date it can be given is then filed when its file was written, not when
  you copied it. A manifest's `received` later than the start of the run refuses that
  file.
- Incoming mail keeps the read flag alone, since an archive keeps nothing else; its line
  says which flags it lost. Sent mail keeps every flag. `T` (deleted) refuses the file.
- **The year folder** is the year of the received moment in UTC: a message received at
  00:30 on 1 January in a zone east of UTC is in the year before. Each folder is created
  and subscribed for the person as the first message of its year is filed, so a client
  that shows subscribed folders alone shows it. The domain archive keeps its own folders:
  the history in its INBOX and the sent mail in `Sent/<person>`.
- `--scan` asks ClamAV about each file: infected is refused, too large to scan is
  imported and said so, ClamAV down stops the run. Imported mail is never given a spam
  score.
- **The result** is `<source>.import-<UTC>.tsv` beside the source (`--result` names
  another), one line per file, its path, its SHA-256, `imported`, `duplicate` or
  `refused` and why, then the totals. Keep them: they are the runs' journal.
- **Exit 0** is the source done; **75** stopped and resumable: another import of the
  domain running, a backup's or an upgrade's pause, the free-space reserve, the fan-out
  not recording the files within 30 minutes, ClamAV down under `--scan`, the store
  refusing a write, PostgreSQL restarted or its connection lost under the run ("the
  database went away"), or a deletion of the domain or of a mailbox in it asked for. Run
  the same command again: a file already in the store is never written twice, so a
  wrapper may run it again for as long as it exits 75. **1** is bad arguments or a
  fault, and what a run that cannot connect at its start exits with: look before running
  it again.
- **Pace.** The import writes 2,000 files, then waits for the fan-out, which runs once a
  minute, to record them: about 2,000 messages a minute. Live collection into the same
  archive goes on meanwhile.
- **Duplicates.** A message whose Message-ID the archive holds already is a `duplicate`;
  so is a second file with the same Message-ID or the same bytes, and a sent message the
  machine recorded when it was sent.

### Then the top-ups, and only then

Once every import is done, give each person their history with a top-up on their
mailbox's page, over the range of their old mail. An imported message reaches them
already read, as it was, in `Archives/<year>`, the year its received moment falls in;
mail collected since reaches their INBOX as it always does. `Archives` is marked as the
archive folder, so a client that archives mail by year (Thunderbird does, as
`Archives/<year>`) files its own beside the history. A top-up for a blocked person that
would give them imported mail fails, saying so: the mail server does not open a blocked
person's mailbox to create the folders. Unblock them and ask again.

A top-up is linked in batches of 10,000 messages, and each batch is kept as soon as it
is done. After two minutes of them the top-up goes back in the queue, in its place, and
the next run delivers everyone's new mail before it goes on. So while a top-up of any
size is under way, new mail is late by about two minutes, never by the top-up's length,
and a queue of many top-ups is worked off one after another while mail keeps arriving. A
request asked after a top-up still waits for it. Meanwhile the journal shows the request
the top-up asked for as `running` or `queued`, with the number of messages linked so
far, and while a batch is under way `store/ledger` in health warns, naming the request.

- **Pace.** Measured on a small test machine (two processors, 3.4 GB, one disk): a
  top-up of 400,000 messages over an archive of 400,000 took 106 s, about 3,800 a
  second; one of a million over an archive of a million took about ten minutes, its pace
  falling from 2,600 a second to 1,300 as it went. The pace falls as the archive grows,
  and past a million it has not been measured. A migration's top-ups add up: ten million
  messages in all are over two hours at 1,300 a second.
- **Memory.** A run of the fan-out that links took up to about 860 MB there. Run a
  migration's top-ups when nothing else large runs on the machine.
- **Hold the distribution's daily upgrade meanwhile.** It restarts PostgreSQL when it
  updates it, which fails the top-up under way and stops an import, to be run again.
  Before the first top-up, read when it is due and stop its timer:

  ```
  systemctl list-timers apt-daily-upgrade.timer
  systemctl stop apt-daily-upgrade.timer
  ```

  Once the last top-up reads `done`, start it again with
  `systemctl start apt-daily-upgrade.timer`; a reboot starts it by itself. The nightly
  backup pauses the fan-out, so a queue of top-ups waits for it and then goes on.

**A top-up that failed or was killed is asked for again.** A failed one says how many
messages were linked before it. They stay, and asking for the same top-up again goes on
from there: a top-up gives only what the mailbox has not been given. When PostgreSQL
restarted under it, it took back the names of the batch under way. When the machine
restarts or the fan-out is killed in the middle, nothing is taken back:

- `store/requests left running` fails, naming the request, until the next run marks the
  top-up failed, "the pass was stopped while performing it; it had said: N message(s)
  linked so far" (§ 3, A request left running);
- `store/ledger` names up to one batch of messages in that mailbox with no delivery row:
  a warning while the request still reads `running`, a failure, "N unaccounted", once it
  is marked failed.

Ask for the same top-up again, over the same range: it gives each of those messages its
row, makes no name a second time, and `store/ledger` passes once it is `done`.

Run every import first all the same: a top-up gives a person what had been imported and
recorded when it ran.

## 8. Local mail is not delivered

Postfix accepts mail only on authenticated submission, port 465. Nothing listens on
port 25, only root may use `sendmail`, and nothing on the machine delivers mail to a
local user: a person's message to a user at one of the machine's own addresses, such as
`root@[127.0.0.1]`, is refused when the recipient is given. So cron output, and any
other mail a system service addresses to a local user, is not delivered anywhere.

Where the machine's own notices go: root's mail is addressed from and to
`root@<the machine's name>`, which is no external mailbox, so Postfix refuses it and
writes a notice that is dropped in turn. Both are in the journal and nothing is kept:

```
postfix/error[...]: ...: to=<root@...>, orig_to=<root>, relay=none, ..., status=bounced (no per-sender transport for this sender)
postfix/pipe[...]: ...: to=<root@...>, relay=maildivvy-notice, ..., status=bounced (user unknown. Command output: maildivvy-notice: root@... is no external mailbox here; the notice is not filed )
```

cron mails a job's output this way, to the crontab's owner; set `MAILTO=""` in a
crontab you add and have the job write what you want kept to the journal
(`... | systemd-cat -t <name>`). unattended-upgrades, as installed, mails nothing
(`Unattended-Upgrade::Mail` is not set). Let your monitoring read health.

### When a provider refuses a sent message

The client is told a message is accepted once Postfix has queued it, and files its Sent
copy then. Postfix speaks to the provider afterwards. When the provider refuses the
message (an unknown recipient, a message larger than it takes) or Postfix gives up after
its queue lifetime (a wrong SMTP password, a provider that never answers), Postfix writes
a notice, *Undelivered Mail Returned to Sender*, to the external mailbox's address. It
is filed in the INBOX of that domain's archive, and every person of the domain gets it
as they get incoming mail. The journal shows the attempt as `status=bounced`, and the
notice's own delivery as `relay=maildivvy-notice`.

## 9. What changes nothing, and what you must never do

These are safe at any time:

- re-running the installer of the release the machine runs: every setting is checked
  again, and a step whose work is in place changes nothing. It takes no backup. From a
  control machine, the same version may also be run again with `--tags <role>`, those
  steps alone; `maildivvy-install` has no `--tags` and always runs every step;
- `maildivvy-health` in any form: it writes only its own report;
- `maildivvy-backup` by hand, or starting its unit: it pauses and resumes collection;
- asking for a snapshot of an IMAP mailbox, taking a slice of it by hand, or discarding
  it: none of them changes anything at the provider;
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
- **No compiler stays on the machine.** Every run purges the packages mpop's build brings
  (`build-essential`, `pkg-config`, the `-dev` packages and what only they need), and
  fails if one stays because something installed since depends on it. What was installed
  before the first install's build is yours and kept, by its record in
  `/var/lib/maildivvy/mpop-build-before`; a build package you want on the machine goes
  into that file by name.
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
