# Installing Maildivvy

`site.yml` runs the installation steps of `docs/architecture.md` § Installation, one
role per step, against the hosts of group `maildivvy`:

```
ansible-playbook -i <inventory> -e @<settings file> ansible/site.yml
```

The settings file is one YAML file of the settings below (the installation guide § 2).
Run it from the repository root with `ANSIBLE_CONFIG=ansible/ansible.cfg`, or from
`ansible/`. A re-run proves each step and changes nothing. A control-machine run takes no
backup and applies no version rule: step 1 refuses it on a machine whose
`/etc/maildivvy/version` names another version than the release's `VERSION`, since a
machine `maildivvy-install` manages is upgraded by `maildivvy-install`. A full run records
the release's version there at its end.

On the machine itself, `maildivvy-install` at the release's root runs the same play with
`local.yml`, the machine over a local connection, as its inventory: the
settings from `/etc/maildivvy/install.yml`, which may hold only the settings below and
the role defaults listed after them as an operator's to override (any other name, a
role's own path or a misspelling included, is refused by name, and so are the secrets and
`maildivvy_insecure_test_certificate`) and whose values, like the
secrets', are taken literally and never templated; the secrets from a root-only file under
`/run` that is removed once the play has started, and the whole output in
`/var/log/maildivvy/install-<time>.log`. It installs `ansible-core` from the Ubuntu
archive: the roles are written for and tested with Ubuntu 26.04's, 2.20.1 (read on the
test machine, 2026-09-26; a control machine's newer one, 2.21, runs them too). A local
run needs `maildivvy_firewall_confirmation` `ssh-login` or `console` (§ The firewall
steps).

Each step carries its role's name as a tag, and step 1 also `always`, so
`--tags <role>[,<role>]` re-runs those steps alone against an already installed machine
with every setting still checked first. A run without `--tags` is exactly what it was.
Tags are for iterating: only a full run without them, on a fresh machine, proves the
installation. A run with `--tags` records no version, and only a control-machine run
takes them: `maildivvy-install` always runs every step.

## Settings

Every setting is checked before anything changes, and a refusal lists every missing,
malformed or ambiguous one at once (step 1). None belongs in this repository.

| variable | what |
|---|---|
| `maildivvy_hostname` | the short hostname of the machine the settings are for. Step 1 compares it with the machine's own (its first label, in any case) and refuses a mismatch with the other refusals, so an install aimed at the wrong machine changes nothing; the install never sets the hostname |
| `maildivvy_cert_name` | the fully qualified name clients connect to; not the hostname |
| `maildivvy_vmail_uid`, `maildivvy_vmail_gid` | the mail store owner's fixed ids (100-999), the same on every rebuild of one deployment. A re-run with other ids is refused |
| `maildivvy_disk_mode` | optional, default `separate`: the store and index on disks of their own, or `single`, as directories on the filesystem that holds `/srv/maildivvy`. Fixed at the first install; a re-run with the other mode is refused |
| `maildivvy_store_disk`, `maildivvy_index_disk` | separate mode, first install only: each disk's current device path. Only an empty whole disk that is not the system disk is taken. Once formatted, the disks are recorded by filesystem UUID in `/etc/maildivvy/disks.json` and later runs never read these settings |
| `maildivvy_swap_disk` | optional, separate mode: a dedicated swap disk's device path; the installer's `/swap.img` is then removed |
| `maildivvy_single_disk_allow_reflink` | optional, default `false`: in one-disk mode, accept an xfs filesystem with reflink on |
| `maildivvy_admin_networks` | list of administrator networks in CIDR form: the only sources SSH (22) and the interface (443) accept, and exempt from every ban and rate limit. The machine running the install must be inside one, or step 3 locks it out and its timer reverts. One wider than /16 (IPv4) or /48 (IPv6) must be a private range, and none may be wider than /8 (IPv4) or /7 (IPv6): step 1 refuses it |
| `maildivvy_firewall_confirmation` | optional, default `new-session`: how steps 3 and 4 learn the administrator can still log in before they cancel their revert timers. `new-session` opens a new SSH session through the new rules (a control machine's run); `ssh-login` waits, while the timer is armed, for sshd to accept a new login from `maildivvy_admin_ssh_source`; `console` confirms nothing and says so, for an administrator who works from the console only. A run over a local connection is refused `new-session`, since its own session crosses no firewall |
| `maildivvy_admin_ssh_source` | with `ssh-login` only: the address the administrator logs in from, inside an administrator network (step 1 refuses one outside) |
| `maildivvy_container_pool` | optional, default `172.16.0.0/12` (Docker's pool): the range the container block treats as containers; must not overlap an administrator network |
| `maildivvy_breakglass_password` | at least 15 characters |
| `maildivvy_cert_mode` | optional, default `acme`: the production CA. `acme-staging` issues from the staging CA into its own store (tests only). `provided` publishes the operator's own certificate. `self-signed` is for a test machine only and needs `maildivvy_insecure_test_certificate: true`; see step 5 |
| `maildivvy_acme_dns_provider` | optional, default `desec`: lego's code for the DNS provider. deSEC is the tested one; any other is reported as untested |
| `maildivvy_acme_dns_credentials` | the provider's credentials, a mapping of the names `lego dnshelp -c <provider>` lists to their values (for deSEC, `DESEC_TOKEN`), scoped by policy to the one `_acme-challenge.<name>` TXT record where the provider allows it. Required in the ACME modes; refused in the others. Only the names lego lists under "Credentials" are accepted ("Additional Configuration" cannot be passed: the propagation timeout and polling interval are set by Maildivvy); whether every credential the provider needs was given is not checked, since some providers list alternatives, and a missing one fails step 5 inside lego. Keep it out of any committed file; the install hands it to the machine on stdin only |
| `maildivvy_acme_email` | optional, default `-` (none): the ACME account's contact address, which gets the CA's expiry mail |
| `maildivvy_provided_cert`, `maildivvy_provided_chain`, `maildivvy_provided_key` | `provided` mode: absolute paths, on the machine, of the certificate, its chain and its unencrypted key. Step 1 refuses a certificate that does not match its key, does not cover `maildivvy_cert_name` or has expired |
| `maildivvy_insecure_test_certificate` | optional, default `false`: allows `cert_mode: self-signed`, for a test machine |
| `maildivvy_backup_keep` | optional, default `8`: how many backup runs are kept, 1-1000; counted, never aged |
| `maildivvy_backup_store_copy` | optional, default none: the operator's command that copies the message store, one line, run as root after each dump and before collection resumes; it must keep hardlinks. See step 16 |
| `maildivvy_health_textfile_dir` | optional, default none: a directory for node_exporter's textfile collector; health's timer then also writes `maildivvy.prom` there. Step 17 creates the directory, the health user's, when it does not exist; an existing one must already be the health user's (step 1 refuses it otherwise), and is never re-owned. An absolute path without spaces |

Defaults an operator may override (`ansible/roles/certificate/defaults/main.yml`), in
the settings file of either mode; the installer's `install.yml` takes these and refuses
every other role default:
`maildivvy_acme_dns_propagation_timeout` (3900 s, above deSEC's 3600 s negative TTL; given to lego as the provider's own `*_PROPAGATION_TIMEOUT`),
`maildivvy_acme_dns_polling_interval` (30 s), `maildivvy_acme_dns_resolvers`,
`maildivvy_acme_dns_api_urls` (the provider APIs step 5 checks first, per provider), and
the pinned lego release (`maildivvy_lego_version`, `maildivvy_lego_sha256` per
architecture).

And for the antivirus (`ansible/roles/clamav/defaults/main.yml`):
`maildivvy_clamav_stream_max` and `maildivvy_clamav_file_max` (both `50M`: the clients
gate on the lower), `maildivvy_clamav_concurrent_reload` (`no`, tied to
the machine's memory), `maildivvy_clamav_community_feed` (on) and
`maildivvy_clamav_sanesecurity_prefix` (the feed's `https://` mirror),
`maildivvy_clamav_database_wait` (how long the first signature download may take).

And for the programs (`ansible/roles/programs/defaults/main.yml`): the fetch period,
`maildivvy_fetch_minutes` (3). It is a role default, not an install
setting: step 1 does not ask for it or check it, and the programs step refuses a value that is not a
whole number of minutes dividing an hour. The fetch timer renders its calendar and its
description from it, and the interface reads its "look again by" off that installed
timer. Read a provider's `LOGIN-DELAY` before shortening it.

And for the spam scanner (`ansible/roles/rspamd/defaults/main.yml`): the pin
(`maildivvy_rspamd_repository`, `maildivvy_rspamd_tag`, `maildivvy_rspamd_digest`) and the
image's own ids (`maildivvy_rspamd_gid`, `maildivvy_rspamd_user`), the bands
(`maildivvy_rspamd_reject_score`, `maildivvy_rspamd_add_header_score` and
`maildivvy_rspamd_greylist_score`),
`maildivvy_rspamd_provider_hosts` (empty: which provider host means what)
and `maildivvy_rspamd_rbls` (off, with the two probe names it tests a resolver with,
`maildivvy_rspamd_rbl_listed_probe` and `maildivvy_rspamd_rbl_clean_probe`).

And for Postfix (`ansible/roles/postfix/defaults/main.yml`):
`maildivvy_postfix_inet_protocols` (`ipv4`, the families actually served)
and `maildivvy_postfix_tls_protocols` (`>=TLSv1.2`, both ends).

## The firewall steps (3 and 4)

Step 3 leaves ufw enabled with incoming denied, 22 and 443 open to the administrator
networks only, and 993 and 465 closed: they open at the last step, once the ban is
proved. Every change runs under a transient `maildivvy-firewall-revert` timer
(`systemd-run`, 300 s, `maildivvy_firewall_revert_seconds`) unless a new SSH session,
opened through the new rules, cancels it first. ⛔ **The timer puts back the rules that
were in force before the change, and nothing is open at any moment while it does**:
the step saves `user.rules`, `user6.rules`, `ufw.conf` and `/etc/default/ufw`
into `/etc/ufw/maildivvy-saved/` (`0700`) before arming it, and
`/usr/local/sbin/maildivvy-firewall-revert` restores them and loads the rule files with
`iptables-restore --noflush`, as ufw itself loads a changed rule set. A disable on an
installed machine would open 993, 465 and every other port, and ⚠️ so does `ufw reload`,
for the moment between the stop and the start it is made of (measured: 465 answered from
outside during one). So does `ufw default` on an enabled firewall, which is why the step
sets `deny incoming` only when incoming is not denied already. Only a first installation, whose
firewall was off before the change and which has nothing listening yet at step 3, goes
back to off. A copy saved by an earlier run whose timer is still armed is kept, since
that run never proved its rules. A run that loses the machine stops as *unreachable*;
wait for the timer, fix the settings, run again.

A run on the machine itself (`-c local`, as the installer runs) has no session that
crosses the firewall, so its own connection can never cancel a timer. With
`maildivvy_firewall_confirmation: ssh-login` the step waits, under the task line
*Waiting for a new SSH login from <address>*, until sshd accepts a new login from
`maildivvy_admin_ssh_source`, read from the journal records journald itself attributes
to sshd; open a second SSH session from that address then. With none before the timer
fires, the rules in force before the run come back and the step fails. Step 4 waits for
a login of its own the same way after its reload. With `console` neither step waits,
and each says in its output that nothing confirmed it.

Step 4 adds the `DOCKER-USER` block to `/etc/ufw/after.rules` before Docker exists,
keeping the file as it was in `/etc/ufw/after.rules.maildivvy-predocker` and arming a
`maildivvy-docker-block-revert` timer that restores that copy. Every run compares the
kernel's `DOCKER-USER` with the block rule by rule and fails if the chain is missing or
differs, since a lost block fails open. A chain lost while the file keeps the block
comes back with `ufw reload`; a file that lost the block is rewritten by a re-run. The
runtime arriving in step 11 adds its own `FORWARD` jump and changes no rule of the block
(measured 2026-09-20), and the tests then publish a throwaway container port to prove the
block drops it.

## The certificate step (5)

`/usr/local/sbin/maildivvy-cert` does all of it, reading `/etc/maildivvy/certificate.json`
(`0644 root:root`, no secret):

- `store-credentials`: the DNS provider's credentials on stdin as JSON, checked against
  the names `lego dnshelp -c <provider>` lists (a name lego cannot read from a file is
  refused), each written `0600 root:root` to `/etc/lego/credentials/<NAME>` for
  unattended renewal, and listed as `<NAME>_FILE=<path>` with the provider's propagation
  and polling variables in `/etc/maildivvy/certificate.env` (`0600`). lego reads each file
  itself, so no credential is ever in an argv, a unit's environment or a log. It says whether the provider is tested (deSEC) or not. A mode that issues
  nothing has the credentials and the list removed. The step also removes a machine's
  `/etc/lego/desec-token` from before 0.1.0, which the credentials directory replaces.
- `install-provided [--cert --chain --key]`: `provided` mode. Checks the operator's
  certificate (matches its key, covers the name, not expired), publishes the leaf and the
  chain and the key at the same paths and modes as `deploy`, and reloads the consumers.
  The paths default to the settings', so replacing the files there and running it again
  is how the operator renews. Step 1 makes the same checks before anything changes.
- `run`: `lego run` over DNS-01 (issue, or renew when due; lego 5 has no `renew`), store
  `/etc/lego` for production and `/etc/lego/staging` for staging.
- `deploy`: lego's deploy hook. It republishes the certificate to
  `/etc/ssl/certs/<name>.crt` (`0644 root:root`) and the key to
  `/etc/ssl/private/<name>.key` (`0640 root:ssl-cert`), naming a missing source
  file, then reloads every consumer in its one list (`CONSUMERS`: Dovecot,
  Postfix, the proxy) that is enabled, and skips the rest. A step that
  adds a consumer adds it there.
- `self-sign`: `self-signed` mode only.

Before anything changes, ACME modes check that the CA's directory and the DNS API
answer over HTTPS, that the public resolvers answer on 53, and that the
certificate name resolves from the machine. ssl-cert and the hook are in
place before the first issuance. lego is the pinned upstream release,
checked against its checksums file by an anchored match and against the pin.
The `maildivvy-cert-renew.timer` runs daily (4 h jitter, persistent); every install
run starts its service once through systemd and reads that run from the journal.
Not done: preflighting the CA's duplicate-certificate rate limit.

### Self-signed mode

`maildivvy_cert_mode: self-signed` exists for test machines, which have no DNS
credential. It is never reached by default: the default is `acme`,
and preflight accepts `self-signed` only when it is set together with
`maildivvy_insecure_test_certificate: true`, and only without a credential. It
makes an EC P-256 key and a one-year self-signed certificate for the certificate name,
at exactly the paths and modes above, so Dovecot, Postfix and the proxy use it
unchanged. A re-run keeps a published certificate only if it is its own: for the name,
matching its key, and issued by its own subject; an ACME or staging certificate left by a
switch of mode is replaced, since nothing would renew it. The renewal timer is still installed; its run prints
`self-signed mode: no ACME renewal` and touches nothing. The install prints
`WARNING: THIS MACHINE HAS A SELF-SIGNED CERTIFICATE` in the step and again as its
very last task.

**For health (step 17):** the mode is `mode` in `/etc/maildivvy/certificate.json`,
world-readable. In `self-signed` mode no endpoint verifies against the system trust
store, so health must report the certificate as self-signed (not PASS)
rather than as a failing endpoint; in `acme-staging` the chain is the staging CA's,
likewise untrusted. A `provided` certificate is verified against itself too, since its CA
may be a private one; its mode reads PASS, and its expiry WARN 30 days and FAIL 7 days
before the end, since nothing renews it.

## The programs role (step 13, first part brought forward)

`programs` runs right after step 5, because PostgreSQL's passfiles (step 6) and
ClamAV's group (step 10) need its users. It makes, as `docs/architecture.md` § Users,
groups and files lays out:

- the users `maildivvy-milter` (in `clamav`), `maildivvy-admin` (in no other group:
  TLS is the proxy's) and `maildivvy-health` (in `clamav`, `maildivvy-rspamd`,
  `systemd-journal`), allocated system users with no home and no shell; `vmail` (step 2)
  joins `clamav` and `maildivvy-rspamd`. Each user is in exactly those groups, read back.
  `maildivvy-rspamd` has gid 11333, the pinned rspamd image's;
- `/etc/maildivvy/<consumer>/` for `pipeline`, `senthook`, `milter`, `admin`, `health`,
  `owner`, each `0750 root:<the group of the user that reads it>` (`vmail` for both of
  the first two, `maildivvy-milter`, `maildivvy-admin`, `maildivvy-health`, `root`), so no
  program reads another's
  `db.conf`. The consumer names are `src/maildivvy/lib/config.py`'s;
- `/etc/maildivvy/admin/secret`, 32 random bytes in hex made on the machine, once,
  `0600 maildivvy-admin`; a re-run keeps it;
- `/var/lib/maildivvy/fetch`, `0700 vmail`;
- `python3-flask`, the interface's library, from the distribution, proved to import as
  `maildivvy-admin` itself: an import that fails at request time is a 500 on every
  screen. It is installed here rather than with the proxy (step 15) because the code in
  `/opt/maildivvy` is what imports it, and the application's own tests run before the
  proxy exists;
- the code: `src/maildivvy` as `/opt/maildivvy/lib/maildivvy`, every file of `bin/`
  as `/opt/maildivvy/bin/`, and `schema/` as `/opt/maildivvy/schema/`. The controller packs the tree;
  `maildivvy_tree` compares every path, owner, mode and digest with the deployed one
  and, when anything differs, removes `/opt/maildivvy` first and writes it whole.
  Everything is `root:root`, directories and programs `0755`, other files
  `0644`; caches are never deployed, and one the interpreter writes at
  run time is not a difference.

**The hook for the programs' units** (`tasks/units.yml`, at step 13's place in
`site.yml`): a program adds its configuration to `maildivvy_program_files`
(`{src, dest, owner, group, mode}`, templated) and its units to
`maildivvy_program_units` (`{src, enabled}`, templated to
`/etc/systemd/system/<src's name without .j2>`; `enabled: true` enables and starts
it and reads it back), both in `ansible/roles/programs/vars/main.yml`.

**The fetch runner's unit and timer** are the first to use it:
`maildivvy-fetch.service` is a `oneshot` run as `vmail` of
`/opt/maildivvy/bin/maildivvy-fetch`, and `maildivvy-fetch.timer` starts it on
`*:0/<maildivvy_fetch_minutes>` (`*:0/3`, every three minutes), with
`Persistent=true`, `RandomizedDelaySec=maildivvy_fetch_jitter` (20 s) and
`AccuracySec=10s`. Only the timer is enabled; the
service is `static`. The runner bounds each mpop at 900 s of its own,
so the unit's `TimeoutStartSec` (`maildivvy_fetch_run_timeout`,
3600 s) only has to be wider than a run of every mailbox: a run that overruns the
period is not killed, because the next run takes the per-mailbox try-lock, finds it
held and skips that mailbox.

The runner writes one `mpoprc` per external mailbox under `/var/lib/maildivvy/fetch/<id>/`,
beside mpop's own `uidls` state file. ⛔ **The credential is never in that file**: it
names `maildivvy-credential <id>` as mpop's `passwordeval`, and the secret reaches
mpop on a pipe. ⛔ **The rendered file names no trust anchor and no
transport switch** — `tls on` and `tls_starttls off` are literal — so
mpop verifies the provider against the machine's own trust store. A `--trace` run
writes `/var/lib/maildivvy/fetch/<id>/trace` `0600`: it holds the credential in clear,
because `mpop --debug` prints every command verbatim.

**The pass's unit and timer** use the same hook: `maildivvy-pass.service` is a
`oneshot` run as `vmail` of `/opt/maildivvy/bin/maildivvy-pass`, and
`maildivvy-pass.timer` starts it on `maildivvy_pass_calendar` (`*:0/1`, every minute), for every domain, including one with no external mailbox in front of it.
It carries `Persistent=false` and no jitter: a tick that fails leaves its cursor where
it was, so a missed run costs a minute and never a message. Only the timer
is enabled. A run that overruns the period is not killed
(`maildivvy_pass_run_timeout`, 3600 s): the pass takes each `pass_cursor` row with
`FOR UPDATE`, so a second run queues per (domain, mailbox) instead of reading one range
twice. The pass reads the archive through `doveadm` and makes the hardlinks itself, so
it runs as the mail owner, like the fetch runner and the delivery filter.

**The same run drains the administration interface's request queue**, at the end and
never before the fan-out: every act that touches a disk - making a domain's
archive or a person's maildir, connecting, a top-up, a release, a transfer, a deletion,
a password check, a refetch - is a `request` row the interface writes and
`fanout/requests.py` performs, one transaction each, as `maildivvy_pipeline`. A request
that fails ends `failed` with its reason on its own row and does not fail the run; a
queue that cannot be drained at all does. Two of the handlers run another program of
ours as the same user: the credential check and the refetch both run
`/opt/maildivvy/bin/maildivvy-fetch`, so a run of the pass may take as long as the
mailbox it is asked to collect.

**The hardening is one set, and the list of writable paths is per program**.
Every unit of ours carries `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
`RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`,
`SystemCallArchitectures=native`, an empty `CapabilityBoundingSet` and an empty
`AmbientCapabilities` — nothing of ours binds a privileged port, since the interface's TLS
moved to the proxy — and `UMask=0077`, except the milter, whose
socket needs its group. What differs is `ReadWritePaths=`:

| unit | may write | because |
|---|---|---|
| `maildivvy-fetch.service` | `/var/lib/maildivvy/fetch`, `/srv/maildivvy/store`, `/srv/maildivvy/index` | ⛔ **not the state alone**: mpop's delivery command is our filter and the filter runs `dovecot-lda`, and a child inherits this namespace. With the store left out the LDA fails `Read-only file system` on every message while mpop and the unit both report success — 21 scheduled runs delivered nothing |
| `maildivvy-pass.service` | the same three | names in the store, index trees moved by a transfer, and the fetcher's state, which a refetch's child writes and a deletion removes |
| `maildivvy-milter.service` | `-/var/spool/postfix/maildivvy` | its socket and nothing else; the `-` is for a path its own root `ExecStartPre` makes |

Every path must exist before the unit starts, or the namespace is never built and the
unit dies `226/NAMESPACE` naming no path. The certificate's renewal service
(step 5) has its whole `ExecStart` read back with the others, but no sandbox: that unit
is root's, runs lego and the deploy hook, and its ACME path cannot be driven on a
self-signed test machine.

## The database step (6)

`postgresql` runs right after the programs role, since it needs the applier and the
owner's configuration directory. It installs the distribution's PostgreSQL and checks
there is one cluster, `main`, on 5432, then:

- `conf.d/10-listen.conf` sets `listen_addresses = 'localhost'`; the stock file is not
  edited. Read back from `SHOW listen_addresses` and `ss`;
- four lines go at the top of `pg_hba.conf`, before the stock `local all all peer`:
  `postgres` by peer and every other role by password (scram-sha-256) on database
  `maildivvy`, and the owner refused over TCP, so it logs in over the socket only.
  Read back from `pg_hba_file_rules`;
- the role `maildivvy_owner` and the database `maildivvy` it owns;
- `/etc/maildivvy/owner/db.conf` (`0640 root:root`, no password) and `pgpass` (`0600
  root`, five fields). `/usr/local/sbin/maildivvy-pg password` (the role's
  `files/maildivvy_pg.py`) writes a missing passfile with 64 random hex characters,
  keeps an existing one, and sets the role's password, as a SCRAM verifier made on the
  machine and sent on psql's stdin, only when the role cannot log in with its passfile.
  The password never leaves the machine;
- `/opt/maildivvy/bin/maildivvy-schema` applies `schema/` as the owner through the
  product's one connection helper; it takes no password or connection argument, and
  `schema_version` must then hold every migration shipped. Unlike
  the temporary passfile, the applier uses the owner's own passfile, which the
  backup shares (`docs/architecture.md` § Filesystems and paths);
- `maildivvy-pg breakglass` hashes the break-glass password on the machine with
  `openssl passwd -6` (password on stdin, bare sha512-crypt), stores only the hash, and
  keeps a stored hash the password still matches, so a re-run changes nothing. The row
  is read back by shape: one row, 106 characters, `$6$`;
- one role per consumer, made before the schema, whose grants name them:
  `maildivvy_pipeline`, `maildivvy_senthook` (the Sent hook's own, narrower than the
  pipeline's: no credential and no DELETE), `maildivvy_milter`,
  `maildivvy_admin` and `maildivvy_health`, each with `/etc/maildivvy/<consumer>/db.conf`
  (`0640 root:<the reader's group>`, no password) and `pgpass` (`0600`, owned by the
  reader: `vmail` for the first two, `maildivvy-milter`, `maildivvy-admin`,
  `maildivvy-health`), written by `maildivvy-pg password` as the owner's is. `maildivvy_dovecot` and `maildivvy_postfix` are made `NOLOGIN`, since their
  daemons' users do not exist yet: **the Dovecot and Postfix steps must give them
  `LOGIN` and a passfile** their daemon reads;
- the grants and views are in `schema/0001_initial.sql`, which ends by reading every
  grant it relies on back from the catalog (`check_grants()`). A migration
  runs it once, when applied, so the step asks it again on every run: a grant changed by
  hand since the install stops a re-run here. Each
  consumer is then queried as itself through its own passfile, a permitted column
  beside a denied one, and each daemon's role likewise through `SET ROLE`.

## The Postfix package and Dovecot (steps 7 and 8)

Step 7 installs the distribution's `postfix`, its question preseeded in step 1 (`Local
only`, loopback only), so the `postfix` account exists; step 9 configures it. Dovecot's SASL
listener is owned by that account, and Dovecot refuses to start without it.

Step 8 installs `dovecot-core dovecot-imapd dovecot-pgsql dovecot-flatcurve
dovecot-sieve` (2.4, checked) and writes `conf.d` from `roles/dovecot/templates/`. The
stock files it replaces by name (`10-auth`, `10-mail`, `10-master`, `10-ssl`,
`15-mailboxes`, `90-fts`, `90-fts-flatcurve`) are kept once in
`/etc/dovecot/conf.d.stock/`, the rollback. What it sets:

- one passdb and one userdb, both SQL on the view `mailbox_opens` with the whole
  `<account>@<domain>` login; the index and control paths come from the view;
- the role `maildivvy_dovecot`, `NOLOGIN` since step 6, gets `LOGIN` and its password in
  `/etc/dovecot/maildivvy.pgpass`, `0600 dovecot` (the SQL lookups run in the `auth`
  process, as `dovecot`), written by `maildivvy-pg password` before the configuration
  that names it, read back and logged in with;
- maildir, Maildir++ with `/` in IMAP, `mailbox_list_storage_escape_char = ^` from the
  first install (never change it on a machine holding mail), `mail_uid`/`gid`
  the store owner's fixed ids, `maildir_broken_filename_sizes = yes`, no compression;
- IMAP only, 993 alone with TLS 1.2 at least and the product certificate, 143 closed by
  `port = 0`; the firewall keeps 993 closed until step 19;
- one `\Sent` folder, `auto = subscribe`; FTS in `20-fts.conf` with
  `fts_search_read_fallback = no` and the stock `90-` files emptied; `acl_driver = vfile` with `acl_defaults_from_inbox = yes`, nothing shared;
  the Sieve plugins, `vnd.dovecot.pipe` global only and
  `sieve_pipe_bin_dir = /opt/maildivvy/bin`;
- **the Sent hook**: `roles/dovecot/files/sent.sieve` into `/etc/dovecot/sieve/`,
  compiled there with plain `sievec` (a warning fails the step), and the
  binding `namespace inbox { mailbox Sent { sieve_script maildivvy_sent } }`,
  `type = before`, `cause = append`, written in this same step - a binding installed
  without its script leaves a window in which every APPEND to Sent names a missing file.
  The script `require`s `imapsieve`, pipes to `maildivvy-sent-hook` and
  ends in `keep;`, since `pipe` cancels the implicit keep and would expunge the
  sender's own copy. The program itself comes from the programs role,
  which runs before this step; the step refuses to bind a script whose program is not
  an executable file. Compiling here is what keeps the imap process from compiling it
  per message into a directory it cannot write.

The step reads back the effective values with `doveconf -h`, exactly one passdb and
userdb, Dovecot listening on 993 alone, a lookup of nobody answered "no such user"
(exit 67) rather than a temporary failure, `vmail` opening `auth-userdb` and `anvil`,
the Sent hook's binding as the daemon holds it, and the compiled script not older than
the script.

**The archive's door** (for the domain request handler and the Sent hook): the archive
login is read-only by `owner lookup read write-seen` ACLs. With
`acl_defaults_from_inbox`, a folder without its own ACL takes INBOX's, so the archive
cannot create one; but a folder made while it had no ACL of its own keeps the rights it
was given, so **every folder the product makes in an archive gets its own `doveadm acl
set ... owner lookup read write-seen`**. The ACL binds `doveadm` too (`save` exits 77
`Permission denied`); the product's own writes into an archive run `doveadm -o
mail_plugins/acl=no ...`, measured on 2.4.2 to create a folder and save into it.
⚠️ A PARENT DOVECOT MAKES ON ITS WAY PAST GETS NO ACL FILE, so the Sent hook creates
`Sent` in the archive by name before `Sent/<login>`, and both are given the ACL; a
`Sent` left as a parent alone is the archive login, which every administrator shares,
free to append into it.

⚠️ **The delivery agent does not refuse - it falls back, and says nothing** (measured
2026-09-20). `dovecot-lda -d archive@<domain> -m <folder>` with the ACL
plugin on **exits 0 and files the message in INBOX** instead of the folder, where
`doveadm save` exits 77. The same happens for a folder that does not exist. A withheld
message in the archive's INBOX is one the fan-out hands to every reader, so the delivery
filter runs the agent with `-o mail_plugins/acl=no` as well, and makes the quarantine
folder through Dovecot (with its own ACL) before handing the message over.

## Postfix's configuration (step 9)

⛔ **Postfix has no include mechanism, and `main.cf.d` is not a directory it reads.** The
step writes nothing by appending: `ansible/library/maildivvy_postconf.py` states the
parameters and the `master.cf` services the product owns and lets `postconf` edit
exactly those, so the distribution's files are otherwise as they were and no
`overriding earlier entry` warning is ever printed. ⚠️ `postconf -M
'<service>=…'` DROPS that service's `-o` lines (measured on 3.10.6), so a definition
that has to be rewritten is written first and every override of it again after.

What the step leaves:

- **465 alone, in wrapper mode** (`submissions inet … y … smtpd`), SASL through
  Dovecot's socket at `private/auth` — a path a chrooted `smtpd` resolves inside the
  queue directory, never an absolute one. Client and recipient
  restrictions are `permit_sasl_authenticated,reject`, and the sender restriction is
  `reject_sender_login_mismatch,permit_sasl_authenticated,reject`: ⛔ the mismatch check
  answers DUNNO on a match, so a bare `reject` after it refuses the messages it just
  approved. 587 is never a service. 465 stays closed to the network by
  the firewall until publication (step 19).
- ⛔ **nothing on 25, and `sendmail` for root alone** (reversing).
  The distribution's bare `smtp inet` is taken away by name, or it binds every address
  of `inet_interfaces`, and so is the predecessor's loopback listener: it and
  the pickup path let any local process name any active external mailbox as the sender,
  and the per-sender maps relayed it with that mailbox's password, with no From check
  and no scan. `authorized_submit_users = root` closes the pickup path to
  every other account. Mail that system services address to local users is therefore
  not delivered. `inet_protocols = ipv4`, so the read-back is one line, `0.0.0.0:465`,
  and `smtputf8_enable = no`.
- ⛔ **the provider's certificate verified before its password is sent**:
  `smtp_tls_security_level = secure`, matched against the host name the mailbox is
  configured with (`smtp_tls_secure_cert_match = nexthop`) and trusting the
  distribution's bundle (`smtp_tls_CAfile`, a file, read before the client enters its
  chroot). `encrypt` took any certificate, so anyone on the path could collect every
  mailbox's password from AUTH PLAIN. A provider whose certificate does not
  name its configured SMTP host is deferred and never sent AUTH; ⚠️ measured on 3.10.6,
  a host configured as an IP address never matches, even a certificate naming that
  address, so a provider is always configured by name: the interface's host fields and
  the `external_mailbox` columns both refuse an IP address.
- **a client transport for a provider on 465**, `smtps unix … smtp` with
  `smtp_tls_wrappermode = yes`, which `postfix_transport` names for a mailbox whose SMTP
  port is 465: that port speaks TLS from the first byte, and the plain client there logs
  `SMTPS wrappermode (TCP port 465) requires setting "smtp_tls_wrappermode = yes"` and
  sends nothing.
- ⛔ **both transports `error:no per-sender transport for this sender`**. Nothing sends
  unless `sender_dependent_default_transport_maps` names a transport for that sender,
  which is what stops a misconfiguration turning the machine into an open relay for its
  own users. A deliverable default transport opens every sender at once, and a relay
  host does not override the guard: the transport is chosen before the next hop. The
  text after `error:` is part of the value and comes back in the refusal.
- **the five lookup maps**, `/etc/postfix/maildivvy-*.cf`, `0640 root:postfix`, one view
  each, ⛔ keyed BY SENDER and never by host: the lookup falls back to the relay host on
  a miss, so with several mailboxes at one provider a missing per-sender key
  authenticates as some other mailbox. Each names the
  database with a libpq URI carrying `passfile=`, so the password is in no file
  `postconf -n` prints back, and ⚠️ every `%s` is quoted — Postfix escapes the value but
  does not quote it, and the error that follows names a missing table.
- **the rewrite is the SMTP client's** (`smtp_generic_maps`), never cleanup's: a
  canonical rewrite runs before the per-sender maps are read and collapses the key they
  are looked up by. No canonical map is set at all.
- **the role `maildivvy_postfix`**, `NOLOGIN` since step 6, gets `LOGIN` and its password
  in a passfile, written by `maildivvy-pg password … --host 127.0.0.1` and logged in with
  as `postfix` before the step ends. ⚠️ **The passfile is inside the chroot**
  (`/var/spool/postfix/etc/postfix/maildivvy.pgpass`, `0600 postfix`), with
  `/etc/postfix/maildivvy.pgpass` a symlink to it: `submissions` is chrooted, so `smtpd`
  resolves the map's `passfile=` against the queue directory while `postmap` and the SMTP
  client resolve it for real. One file at both paths, never two copies that drift; without
  it every lookup fails `fe_sendauth: no password supplied`. The
  connection is TCP to `127.0.0.1`, because the chroot has no PostgreSQL socket and an
  empty `/etc/hosts`, and libpq matches the passfile's first field against the host it is
  given — so that field is `127.0.0.1` and not `localhost`.
- **the certificate**: `postfix` joins `ssl-cert` now that the package has made the
  account, and the deploy hook is run again (it is lego's, so there is nothing to re-run
  in `self-signed` mode); `smtpd_tls_cert_file` and `_key_file` are set explicitly, or
  465 serves the distribution's snakeoil pair and every client refuses it by name.
  Both ends are TLS 1.2 at least.

⛔ **The step runs `postfix check` before every restart**: it reports a
syntax error while the running service is still the old one, and a restart on a broken
`master.cf` leaves nothing listening. ⚠️ **That check prints two warnings about the
passfile on every run, and both are the price of rules that stand**: libpq *ignores* a
passfile with any group or other access, so it cannot be root-owned and
group-readable, and it is reached through a symlink, which is always `lrwxrwxrwx`. The
set is pinned by a test, so a new warning fails rather than joining two nobody reads.

⛔ **Each map is asked for a name that cannot exist, and STDERR is what is read**:
`postmap -q` exits 1 both for "no such key" and for "the database refused us", so a
correct miss is rc 1 with no output, and a `fatal: query error` with rc 1 is the whole of
Postfix unable to look anything up.

⚠️ **Postfix folds a lookup key to lower case before asking a map** (measured
2026-09-20). The four sending views therefore key on `lower(address)` and publish the
address as it was entered: with the entered spelling as the key, an external mailbox with
one capital in it could not send at all, and the refusal named the login. Only the case
is folded; `address_canonical`, which also folds dots, is never a key.

This step binds no Milter: the binding, and `milter_default_action`, are install step
14's, after the daemon is proved running — a socket nothing listens on, named here,
would tempfail every submission for five steps.

## The antivirus step (10)

ClamAV is the distribution's `clamav-daemon` with `clamav-freshclam` and `fangfrisch`,
so the security pocket patches it unattended; there is no image and no
pin. The account it all runs as is `clamav`, made by `clamav-base` in step 1, and `vmail`
and `maildivvy-milter` are in its group from the programs role, so the delivery filter
and the milter open its socket.

- **`/etc/clamav/clamd.conf` is the product's file, not the package's.** The package
  regenerates it from debconf answers at every upgrade, which would undo these settings
  on a machine that is patched unattended, so the step sets `clamav-daemon/debconf` to
  `false` and writes the whole file from `roles/clamav/templates/clamd.conf.j2` before
  the package is installed. `dpkg-reconfigure clamav-daemon` then leaves it alone.
- `ConcurrentDatabaseReload no`, `StreamMaxLength` and `MaxFileSize` both
  `50M` (`maildivvy_clamav_stream_max`, `maildivvy_clamav_file_max`). The clients gate on
  the lower of the two, read from this file by `maildivvy.lib.scan`; over the daemon's own stream limit there is no verdict at all, only an
  error, which is why the gate is ours. ⛔ That error, `INSTREAM size limit exceeded.
  ERROR`, is the only one the client reads as *unscanned*; any other ERROR is the daemon
  failing (measured: `Error writing to temporary file ERROR` with its temporary directory
  full) and reads as *unavailable*, a 451 at submission and the hold for incoming
  mail.
- `AlertExceedsMax yes`: without it a scan the daemon cuts short at
  `MaxFileSize`, `MaxScanSize`, `MaxRecursion` or `MaxScanTime` is answered `OK`
  (measured: an archive nested 25 deep read clean). With it the answer names
  `Heuristics.Limits.Exceeded.<limit>`, which the client reads as *unscanned*.
- The socket is `/run/clamav/clamd.ctl`, `0660 clamav:clamav`, in a directory
  `0750 clamav:clamav` that `/etc/tmpfiles.d/maildivvy-clamav.conf` recreates at every
  boot: `/run` is tmpfs, and a daemon that cannot bind its socket reads as an
  intermittent scanner rather than a missing directory.
  The mode and group of the socket come from the package's generator reading `clamd.conf`,
  so a changed configuration means the socket unit is made again.
- No `Move`, `Remove` or `Copy` directive: the daemon is handed bytes over the socket and
  has no reason to write anywhere.
- The daemon runs in the foreground under systemd with no `LogFile` and no `LogSyslog`,
  so its log is the unit's journal, once.
- `EnableReloadCommand yes`, so the updater's notification after a signature download is
  accepted (without it freshclam logs `Clamd was NOT notified`), and
  `EnableVersionCommand yes`, so health reads the running daemon's version and signature
  set. Shutdown and stats stay off.
- **The community feed** is `fangfrisch` on the host, configured at exactly
  `/etc/fangfrisch.conf`, which its shipped timer's condition names, and
  writing into `/var/lib/clamav` as `clamav`, so there is one writer and one set of
  databases. Sanesecurity alone, over `https://`
  (`maildivvy_clamav_sanesecurity_prefix`), since the others' memory cost is unmeasured;
  the checksum it verifies is served by the payload's own host, so
  `https` carries the only transport trust there is. `maildivvy_clamav_community_feed:
  false` turns the feed off. After a refresh the step reloads the daemon, so the step's
  own probe reads a daemon that has loaded what it just wrote.
- **The step's proof**: EICAR, a clean message, one over our gate and one over the
  daemon's, all through `maildivvy.lib.scan` as `vmail` — the product's own client, never
  a host ClamAV tool; `clamdscan`, `clamscan` and `clamconf` are not on
  the machine, which is what is left of the distribution's scanning tools.
- **Memory**: measured 2026-09-20 on the 4 GiB test VM with the
  official databases and Sanesecurity loaded (3,747,666 signatures): the daemon's peak over a whole test run
  is **1.38 GB** (`systemctl show clamav-daemon -p MemoryPeak`; 1.06 GB right after its
  first start), and a reload does not double it, since concurrent reload is off.
  Sanesecurity costs about 120 MB of that. The machine keeps about 1.8 GB available.

## The spam scanner step (11)

rspamd has no distribution route, so it stays a container image pinned by digest;
the container runtime is the distribution's `docker.io` with
`docker-compose-v2`, installed after the container firewall block of step 4, so the
bypass never exists. The whole scanner is `/etc/maildivvy/rspamd/`
(`0750 root:root`): the compose project, `.env` with the pin, the `local.d` override tree
and the sender-pinning rule.

- **The pin** is `maildivvy_rspamd_repository`, `maildivvy_rspamd_tag` and
  `maildivvy_rspamd_digest`. Compose is given the digest through `.env` as
  `${RSPAMD_IMAGE:?…}`, so an unset variable is a refusal and never a silent `latest`.
  The image is pulled only when it is missing, so the registry is asked
  once per pin and never on a schedule.
- **Repinning is this step.** Change the digest and the tag together and run the install:
  it records the new pin, recreates the container, reads the configuration back out of
  the running daemon and scores a probe message as `vmail` before reporting success.
  Nothing repins on a timer. The pin is recorded, without a secret, in
  `/etc/maildivvy/scanner.json` (`0644`, beside `certificate.json`), which is where health
  reads whether a newer release is due. A newer release does not stop an install that
  still runs the old pin: step 17 prints health's FAIL for it and goes on.
- **Nothing is published and there is no host networking**: the keys are
  absent from the project and the step reads the container back for them. The normal
  worker binds one unix socket, `/run/maildivvy/rspamd/rspamd.sock`, `0660` owned by the
  image's own id, in a directory `/etc/tmpfiles.d/maildivvy-rspamd.conf` recreates at
  every boot. ⛔ Its parent `/run/maildivvy` is `0755 root:root`, in
  the same file: the interface's own directory is in it too, and an interface that owned
  the parent could rename the scanner's directory away and put its own socket where
  every incoming message is scanned. The container drops every capability
  and runs with `no-new-privileges`: it runs as the image's own id and binds
  a socket it owns, so it needs none. The controller and the milter proxy run no copies, so
  rspamd binds no TCP port at all - measured: with the proxy left at its default it
  listens on `*:11332` and warns that it accepts privileged file inputs there.
- **The image's gid is the host group's.** `maildivvy-rspamd` exists only to name it,
  so the delivery filter, the milter and health open the socket. The step
  reads the gid out of the image and stops the install if a repin moved it.
- ⚠️ **The override tree's own permissions are what the container meets.** It is a bind
  mount source: `0750 root:root` reads as `Permission denied` inside, and rspamd then
  falls back to its built-in defaults - `bind_socket = "*:11333"`, `reject = 15`, every
  module on - and says nothing about it (measured 2026-09-20). The tree is therefore
  `0750 root:maildivvy-rspamd` with `0640` files, and the step reads the running daemon's
  own configuration back.
- **The bands** (`local.d/actions.conf`) are `reject` 150, `add_header` 6, `greylist` 4,
  and nothing in the pipeline files by the action. `reject` is one value
  with the CHECK on `domain.spam_threshold` and `maildivvy.lib.scan.TOP_SCORE`: it is the
  ceiling of every domain's threshold, and moving it moves the schema's bound in a
  migration of its own.
- **The sender pin** is `rspamd.local.lua`, mounted on its own because rspamd loads it
  from outside the override tree and from nowhere else. It reads the
  `Received` headers top down, takes the first one written by a host in
  `maildivvy_rspamd_provider_hosts` that names an address, reads the address out of the
  header's text, and pins the sender there; a provider header with no address is a
  re-injection, so it keeps looking below it. Each host is
  `trust_login` or `judge_provider`, which is what an authenticated submission at that
  provider means. ⛔ The list is **empty by default**: an unlisted
  provider is judged against its POP3 server and the rule logs `sender not pinned`. Add a
  provider only after reading a real chain of its mail, and prove the pin on a message it
  delivered, never on a probe.
- **What is off is off by name**, so an override tree copied over an older one cannot
  leave the old rule running: `external_relay` (the Lua rule replaces it),
  Bayes (no Redis backend, and per-user training is impossible with no recipient at
  ingest) and the DNSBLs. The step reads them back as
  *Modules disabled (explicitly)*, never as an absence, and removes a file under
  `local.d` that it no longer writes.
- **DNSBLs and the resolver are one decision**. `maildivvy_rspamd_rbls` is
  off; turning it on makes the step ask a list about an address that is listed and one
  that is not, and refuse while the machine's resolver answers for both - which is what a
  forwarding resolver does (`127.255.255.254`, "open resolver", inside the range a list
  uses to mean listed; measured on the test machine).
- **The scanner's log leaves the container** through the runtime's journald driver, tagged
  `maildivvy-rspamd`, so recreating the container keeps it. Measured 2026-09-20: three
  container generations' lines stand in one journal, as inferred before.
- **The step's proof**: a message scored through `maildivvy.lib.scan` as `vmail`, over the
  socket the delivery filter will use; the container publishing nothing;
  no TCP API on the runtime; and, in the tests, a throwaway published port that serves on
  loopback and times out from off the machine while the block's counter rises.
- **Memory**: the container holds about 70 MiB resident on the test machine, beside
  ClamAV's 1.38 GB peak, leaving about 1.6 GB available on 4 GiB (measured 2026-09-20).

## The fetcher step (12)

mpop is built on the machine, since Ubuntu 26.04's 1.4.21 refuses `keep <n>d`,
and runs before step 13 renders anything for it:

- the author's `mpop-<version>.tar.xz` is downloaded and checked against the pinned
  sha256 literal (`maildivvy_mpop_version`, `maildivvy_mpop_sha256` in
  `roles/mpop/defaults/main.yml`); a mismatch is removed before anything unpacks it;
- `./configure --with-tls=gnutls --with-libgsasl --with-libidn --without-libsecret
  --without-mpopd`, `make`, installed `0755 root:root` at `/usr/local/bin/mpop`;
- the build's packages (`build-essential`, `pkg-config` and three `-dev` packages)
  come in for the build and go after it: `maildivvy_runtime` marks every package
  holding one of the binary's libraries as manually installed, then purges by name
  what apt would autoremove among the packages the build brought, and nothing that was
  there before. **Never run `apt autoremove` on the mail server**: the
  install does not, and the step's proof is that a simulated autoremove names none of
  the binary's libraries;
- the distribution's `mpop` package, and its `mpopd`, are purged once the built one
  reports the pinned version as `vmail`, and the step fails unless `/usr/local/bin/mpop`
  is the only `mpop` or `mpopd` on the root filesystem.

A re-run finds the pinned version in place and builds nothing. What mpop does with a
failing delivery command, which the inbound hold rests on, is measured in that
record.

## The milter step (14)

The milter binds a submitted message's `From` header to the login that authenticated,
and scans what it accepts, before Postfix queues anything. The
step's whole shape is its order: ⛔ **Postfix's `milter_default_action` is
`tempfail`, so a milter bound before it runs refuses every submission on the machine.**
Step 9 therefore writes no binding and no `milter_*` at all, and this step starts the
daemon, proves it answers, exercises the rollback, and only then binds it.

What the step leaves:

- **pymilter from the distribution** (`python3-milter`), its import proved as an
  unprivileged user *before any socket is bound*: it is a C extension, and its failure
  mode is a service that starts, binds and cannot answer while Postfix is already
  handing it messages. ⛔ Nothing of ours is called `milter.py`:
  pymilter imports a lowercase `milter` extension from inside its own package, and a
  module of that name on the program's path shadows it.
- **the daemon** under `maildivvy-milter`, a no-login system user whose only other group
  is `clamav`, ordered `After=postgresql.service` and `Before=postfix.service` so a
  reboot never lets Postfix accept a submission it would have to defer.
  Its unit names its own database connection file explicitly: without `--db-conf` the
  program would fall back on another consumer's file, which this user cannot read, and
  every submission would be deferred while its own files read exactly as expected.
- ⛔ **the socket inside Postfix's queue**, `/var/spool/postfix/maildivvy/milter.sock`,
  in a directory `2750 maildivvy-milter:postfix`, named relatively as
  `unix:maildivvy/milter.sock`: `submissions` is chrooted, so a socket under `/run` comes
  up correctly and no submission can ever reach it. The directory is made
  in a **root-privileged `ExecStartPre=+`** and listed in `ReadWritePaths=` with the `-`
  prefix — under `ProtectSystem=strict` an unprivileged `ExecStartPre` cannot create it
  and the unit dies `226/NAMESPACE` naming no path, and an unprefixed `ReadWritePaths`
  for a path that does not exist yet refuses to start. `UMask=0007`, or
  the socket is `0700` and every submission is deferred with a permission error naming
  nothing useful.
- ⛔ **the proof that it answers**, in the protocol's own words:
  `maildivvy-milter --probe` negotiates with the socket, because `systemctl is-active`
  reads `active` for a daemon that started and could not open it.
- ⛔ **the rollback, exercised before the real binding**: the step binds
  `unix:maildivvy/does-not-exist.sock`, reads a submission being refused `451`, clears
  the value and reads the control with nothing bound. A rollback first attempted during
  an incident is one nobody has run, so it runs on every application of the role and
  leaves the machine as it found it. ⛔ The real binding is the drill's `always`:
  a drill that fails after the binding was taken away still fails the run,
  and leaves submission bound to the milter rather than open with no From check and no
  scan.
- **`milter_default_action = tempfail`, `milter_protocol = 6`**, the global
  `smtpd_milters` and `non_smtpd_milters` empty, and the binding on `submissions` alone:
  a global binding would also put the milter in front of the pickup
  path, where nothing authenticates and every message would be refused. ⚠️ What the machine
  holds is read from `postconf -M` and `postconf -P` **without arguments**: `-P` naming a
  service that does not exist prints the same `warning: unmatched request` as a correctly
  absent override. Step 9's own module is told to `keep` this one override,
  so a re-run of that step neither writes it nor takes it away.
- **a restart when the code changed**: this is the first long-running program of ours.
  The timers' programs pick up new code at their next run; this one holds what it
  imported at start, so the step restarts it when anything under `/opt/maildivvy` is
  newer than the running daemon.

⚠️ **A refusal's own words are flattened before they are handed to the library**
(measured 2026-09-20): pymilter refuses a reply text with a newline in it, and one with
a bare `%`, and the whole decision is then lost — the client is told
`451 4.3.0 pymilter: untrapped exception`, a temporary failure naming nothing, for a
message that should have been refused for good. A driver's connection error is two
lines and `%` is legal in an address, so both are reachable from ordinary input. Postfix
undoubles the `%` again, and the client sees the address as it typed it.

## The interface step (15)

The administration interface serves plain HTTP on a unix socket, and a reverse proxy in
front of it holds the certificate and the TLS rules. ⛔ **No Python process of ours
handles TLS**: a TLS handshake closed without a request leaves an error on the
OpenSSL queue of the CPython worker that read it, and that worker then drops its next
fresh connections until the process restarts (python/cpython#81891). The proxy is
**nginx**, `nginx-core` from the distribution's main pocket, rather than Apache or
HAProxy.

What the step leaves:

- **the interface's unit**, `maildivvy-admin.service`, `Type=notify` so it reads active
  only after its bind, with step 13's whole hardening set. Its
  `ReadWritePaths=` is `/run/maildivvy/admin` and nothing else: the interface writes
  nothing to disk, and `/run` is read-only under `ProtectSystem=strict`
  like everything else. `/etc/tmpfiles.d/maildivvy-admin.conf` makes that directory, the
  interface's own, at every boot, since `/run` is tmpfs and a unit whose writable path is
  missing dies `226/NAMESPACE` naming nothing. ⛔ Its parent `/run/maildivvy`
  is root's: rspamd's socket directory is in it too;
- **the socket**, `/run/maildivvy/admin/admin.sock`, `0660 maildivvy-admin:www-data`, bound
  under a umask that never widens it even for an instant. ⛔ **The widening goes one
  way**: the unit gives the interface the proxy's group (`SupplementaryGroups=`) so it
  can hand its own socket over at bind, and the proxy is never put in the interface's
  group, which would open `/etc/maildivvy/admin` — the database passfile and the
  session-signing secret — to it (read in the direction of);
- **the client's address**, which the proxy writes as `X-Forwarded-For $remote_addr`.
  ⛔ Never `$proxy_add_x_forwarded_for`, which APPENDS to the header the browser sent:
  anybody could then put an address of their choosing in front of their own. The
  application trusts the header only because it arrives on that socket, and reads an
  address out of it or nothing at all, so the journal, the login throttle and the unit's
  own log can never be handed a name, a second hop or a newline;
- **the proxy's one site**: 443 alone, `ssl_protocols TLSv1.2 TLSv1.3` stated explicitly,
  the published certificate and key named explicitly, and `proxy_pass`
  to the socket. The distribution's default site, which listens on port 80, is removed,
  and nothing answers on 80. The firewall has kept 443 scoped to the administrator
  networks since step 3, and the interface is never published;
- **the certificate**: `www-data` joins `ssl-cert`, the deploy hook is run again (it is
  lego's, so there is nothing to re-run in `self-signed` mode), and the hook's consumer
  list keeps `nginx` with the verb `reload` — nginx re-reads its certificate on a
  reload, and the master process stays where it was. A unit test holds that
  entry to this role's own name for the proxy, so the two cannot drift.

⛔ **The step's proof is a real request**, by name, over TLS, verified against
the certificate and never with `-k`: a known route answers 200 and a missing
one answers 404 as the control. Nothing in the install, and nothing in the tests, opens
a connection and closes it without a request. The step also reads back that no process of
ours holds a TCP socket at all — TLS moved out of the application, and with it every
port it had.

## The backup step (16)

The product backs up what only it can make consistent: **the database and the fetcher's
state, in one run, restored together**. The state is what stops a restored
machine fetching a whole provider window again. **The message store is not copied by the
product**: its copy is the operator's, must keep hardlinks or a
restore multiplies every message by its holders, and must be no older than the dump it
is restored with.

What the step leaves:

- `/opt/maildivvy/bin/maildivvy-backup` (`src/maildivvy/backup/`), run daily by
  `maildivvy-backup.timer` (`OnCalendar=daily`, up to an hour of jitter, `Persistent=true`)
  and by hand the same way. A run:
  1. **pauses collection and fan-out**: the fetch and pass timers are stopped, then it
     **waits** until neither service is running or has a job queued. It never kills a
     run: a fetch holds its mailbox's lock and may take fifteen minutes, and each unit's
     own timeout bounds it. Only a timer that was active is started again, so collection
     an operator had stopped stays stopped;
  2. dumps the database as `maildivvy_owner`, through the owner's own `db.conf` and
     passfile over the unix socket, which puts the backup's identity on the socket rather
     than on loopback, and archives `/var/lib/maildivvy/fetch`;
  3. **judges both by what they hold, never by size**: the dump is decoded
     to its end and must hold every table with exactly the rows counted in the dump's
     own snapshot; the state archive must list every entry of the state directory with
     its owner, mode and bytes. Only then is `.<stamp>.partial` renamed to `<stamp>`, the
     two together. A missing state directory fails the run;
  4. removes the runs beyond `maildivvy_backup_keep`, counted;
  5. runs the operator's store copy, if `maildivvy_backup_store_copy` is set — after the
     dump is in place, so the copy is never older than it, and still inside the pause.
     ⛔ **It runs outside the backup's sandbox**, as root, in a transient unit of its own
     (`maildivvy-store-copy.service`), since it may need to write anywhere, keep owners
     or reach another host; `MAILDIVVY_BACKUP_STAMP` names the run it pairs with. A copy
     that fails fails the run and keeps the dump;
  6. **resumes, whatever happened**: the timers are started again in a `finally`, after
     a failed dump, a failed copy, or a run systemd stopped at its timeout (6 h). A run
     killed outright never reaches it, so the pause first records which timers it stops
     (`/var/lib/maildivvy/backup/paused.json`); the unit's `ExecStopPost`,
     `maildivvy-backup --resume`, starts them from that record, and so does the next run.
- `/var/backups/maildivvy`, `0700 root`: one directory per run named by its UTC moment,
  `20260923T003005Z`, `0700`, holding `database.dump` (pg_dump's custom format),
  `fetch.tar` and `manifest.json`, each `0600`.
- `/var/lib/maildivvy/backup/status.json`, `0644 root`: the newest run's name, moment,
  what it held and what the store copy did. No secret is in it. ⛔ **The pipeline refuses
  to enable an external mailbox until it names a run**: the deletion window
  starts deleting at the provider from the first fetch, and from then on this machine is
  the only holder of the address's mail.
- The unit, `maildivvy-backup.service`, runs as root with step 13's hardening set but for
  one capability: ⛔ **`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`**, because root with
  an empty set cannot read the mail owner's `0700` fetch state, and the predecessor's archive
  came out 45 bytes of nothing after its dump was already written. It
  writes `/var/backups/maildivvy` and `/var/lib/maildivvy/backup` and nothing else.

**Restore** (as root, by hand): `maildivvy-backup --restore <stamp>` pauses the same way,
unpacks the state beside the live one and checks it, restores the dump in one transaction
(`pg_restore --clean --single-transaction`), and only then swaps the state in; a database
that will not restore leaves the state as it was. Put the store back first from the copy
that same run made inside its pause, and no other (amended 2026-09-24), and keep
its hardlinks.

The step's proof is a first run taken through the unit itself, so its sandbox, its
capability and its pause are what is exercised, then read back from the disk. A re-run
over a machine that has one takes no second run.

## The health step (17)

`/opt/maildivvy/bin/maildivvy-health` (`src/maildivvy/health/`) checks the fifteen
subsystems and reports each check as PASS, WARN, FAIL or UNKNOWN:
text on stdout, the JSON report `/var/lib/maildivvy/health/health.json` (`0644
maildivvy-health`, written whole), and the exit code of the worst state (0 PASS, 1 WARN,
2 FAIL, 3 UNKNOWN), so any monitoring system reads it without an adapter. The product
pushes nothing: the operator's monitoring needs a rule for FAIL, for UNKNOWN and
for a stale report.

```
maildivvy-health                          every subsystem; writes the report
maildivvy-health --subsystem <name>       one subsystem, for one monitoring item each
maildivvy-health --cached [--subsystem <name>]
                                          no check run: the report as a collector reads it;
                                          older than 15 min it reads UNKNOWN, a FAIL in it stays FAIL
maildivvy-health --format prometheus      any of these in Prometheus's text format
maildivvy-health --textfile-dir <dir>     a run of every subsystem also writes <dir>/maildivvy.prom
```

What the step leaves:

- `maildivvy-health.timer`, every five minutes, runs `maildivvy-health.service` as
  `maildivvy-health` (a read-only database role; groups `clamav`, `maildivvy-rspamd`,
  `systemd-journal`) with the hardening set, writing only the report's directory. The unit
  succeeds for every report state (`SuccessExitStatus=1 2 3`); it fails only when the
  program cannot run, and then no report is written and it goes stale.
- with `maildivvy_health_textfile_dir` set, the unit runs with `--textfile-dir` and may
  write that directory too; the step makes it `0755 maildivvy-health`, and each run
  replaces `maildivvy.prom` whole (`0644`, through `.maildivvy.prom.partial`, which
  node_exporter skips). The states are the exit codes, so FAIL is 2 and UNKNOWN 3.
  Removing the setting leaves the last file behind: its
  `maildivvy_health_last_run_timestamp_seconds` then ages, which is what an alert reads.
- **two helpers**, because some readings need more than that user has. Each
  is socket-activated, one instance per connection, on a socket `0660
  root:maildivvy-health` under `/run/maildivvy/`; each takes nothing but the names of the
  readings asked for, from a closed list, and answers one JSON document ending
  `"complete": true`, so a helper cut short reads UNKNOWN:
  - `maildivvy-health-store@` runs **as `vmail`**: the ledger's consistency check
    (`fanout/ledger.py`) and the link counts, through the pipeline's role in a read-only
    session; the `keep` line of each rendered mpop configuration; a body search against
    an archive's index. It may write the store and the index trees, because `doveadm`
    keeps Dovecot's index and control files as any reader does;
  - `maildivvy-health-system@` runs **as root** with two capabilities that read -
    `CAP_NET_ADMIN` lists the kernel's ruleset, `CAP_DAC_READ_SEARCH` crosses Postfix's
    `public/` (postdrop's) to ask showq for the queue - and `postfix` as a supplementary
    group, which crosses to the milter's socket and may connect to it. It reads ufw's
    rules (`0640 root`), the ruleset, the container runtime, fail2ban, the queue and the
    milter's socket, and writes nothing. ⚠️ `postqueue` is set-group-id `postdrop`, which
    `NoNewPrivileges` takes away, so no unit of ours could list the queue as a user
    (measured).
- **upstream releases asked at most every six hours**, the answers kept in
  `/var/lib/maildivvy/health/upstream.json`: ClamAV's TXT record `current.cvd.clamav.net`
  (a newer release WARNs, and FAILs once it has been newer for more than 7 days),
  and the registry's tags for the pinned rspamd repository (a newer patch on the pinned
  line FAILs: repin through step 11; the install's step 17 prints that FAIL and goes on).
  An answer that cannot be read is UNKNOWN.
- the bounds (report staleness, free space, memory, certificate days, signature age,
  queue age, the journal and request windows, the fan-out's age, how long collection may
  go without a finished fetch run or a fetched row, the backup's 48 h, the outside
  probe's age) are defaults in `src/maildivvy/health/settings.py`; an operator
  moves one in `/etc/maildivvy/health.conf` (`key=value`). The install writes no such
  file, and a key the program does not know is refused rather than ignored.

The login `dovecot` checks with is one that cannot exist (`maildivvy-health@health.invalid`):
the answer `[AUTHENTICATIONFAILED]` proves the passdb was asked and answered without health
holding a password, and Dovecot logs it as a failed login from `127.0.0.1` every five
minutes. ⚠️ Step 18's `ignoreip` must keep loopback, or the ban counts health.

A timer's last run is read through systemd, which forgets a oneshot's run at every boot.
The daily renewal is then read from the journal, where the end of each start job is kept
across boots; without that it read "never run", UNKNOWN, for up to a day after every
reboot. The fan-out, every minute, reads "not run yet" until its first run after
the boot, which is true, and so does the fetch (`collection/fetch runs`, every few
minutes), whose last run is read as the fan-out's is: a run that fails as a whole touches
no row, so the rows alone would keep their last `ok`. A backup
is a oneshot, `activating` for the whole of its run: that, not `active`, is what health
reads as the pause.

**The step's proof** is a full run taken through the unit, and its report read back: every
subsystem PASS or WARN, or UNKNOWN only where the machine holds no mail yet (no external
mailbox, no delivery row, no message to search for, no fetch run yet). A WARN is printed and accepted: it is
a signal the install cannot act on (a test machine's `self-signed` certificate is one), not
a step that did not work. So is `spam/repin`'s FAIL, a newer rspamd release on the
pinned line: it is printed and does not stop the install, since what it asks for is a
repin (step 11), not a repair; health on the running machine still reads it FAIL.
Every other FAIL and every other UNKNOWN stops the install. `ban` and
`network` are read by steps 18 and 19, which make what they check. With a textfile
directory set, the run must also have written `maildivvy.prom` there, `0644
maildivvy-health`.

## The ban and publication steps (18 and 19)

The mail ports are published last, and only behind a ban proved on the running machine.
Until step 19, 993 and 465 have listeners and the firewall drops them.

**Step 18, the ban** (`roles/ban`): fail2ban from the distribution, with
- `/etc/fail2ban/filter.d/dovecot.local`, which **extends** the stock Dovecot filter with
  2.4.2's `Login aborted: … (auth failed, …)` in both of its endings (`Logged out`, and
  `Connection closed` from a client that just leaves), the address taken from `rip=`;
- `/etc/fail2ban/jail.d/maildivvy.local`: `ignoreip` under `[DEFAULT]` alone - loopback,
  which health fails a login from every five minutes, and every administrator network
  - `maxretry` 5 in `findtime` 10 min for a `bantime` of 1 h (role
  defaults), and two jails: `dovecot` on `imaps`, and `postfix` on `submissions` in
  `mode = auth`, which counts SASL failures and not refused recipients, so the outside
  probe's own refusal is never counted;
- ⚠️ the ban action is **`nftables[type=allports]`**, not the `ufw` action the predecessor used:
  a ban covers every TCP port of the source from fail2ban's own table,
  `inet f2b-table`, which it makes and removes itself. The `ufw` action writes each ban
  into `user.rules`, the file step 3 owns: a re-run would refuse the rule as one it does
  not write, and the self-reverting timer, which puts the saved file back whole, would
  drop live bans or bring back lifted ones;
- the daemon **restarted** when a file changed, never `enable --now`: the package starts
  it at install, and the new jails would never appear.

The proof is `maildivvy-ban prove` (`files/maildivvy_ban.py`, installed in
`/usr/local/sbin`), which proves each jail in four halves, since `attempt` bypasses the
filter and the log:
- **daemon**: the jail is loaded; its backend is read back from the daemon
  (`fail2ban-client -d`: `systemd`, the journal, from the distribution's
  `paths-debian.conf`; nothing in our file sets it); `ignoreip` covers loopback and every
  administrator network, and nothing wider (an extra exemption, or an administrator network
  too wide to exempt, is a failure); `maxretry` is the one written;
- **filter**: a real failed login is made on the machine, the server's line read out of
  its journal, and `fail2ban-regex` must match it once and match nothing in a real line of
  the same server that is not a failure - a session that logged out without a login for
  Dovecot, the refusal at `RCPT TO` (the outside probe's) for Postfix;
- **source**: the running jail read that failure, which it says by logging that it
  ignored the address (its own, `ignoreself`);
- **guesser** (the `postfix` jail): the same source, now under Dovecot's delay, keeps
  failing as a password guesser does until the live jail has read `maxretry` of its
  failures; some are lost to the delay as `Connection lost to authentication server`,
  and if `4 * maxretry` attempts cannot reach `maxretry`, a guesser would never be
  banned;
- **counter and action**: `maxretry - 1` failures sent with `fail2ban-client set <jail>
  attempt` for a TEST-NET-1 address do not ban it; one more does, and the address is then
  counted in the jail's nftables set with a reject rule on it; the unban removes it. The
  address is drawn anew per jail and per run: failures for an address stay counted for
  `findtime` across a ban and an unban.
Then health reads `ban` PASS. ⚠️ Postfix's jail is proved first and from the machine's own
address: Dovecot slows its answer to an address that just failed, and Postfix gives up
after about ten seconds and logs a line the filter rightly ignores.

**Step 19, publication** (`roles/publish`), only once the ban is proved: when step 18 did
not pass its proof in the same run (`--tags publish`, or any run that skipped step 18), step
19 runs `maildivvy-ban prove` itself first, since health's `ban` reads neither `maxretry`
nor the live counter; then health must read `ban` PASS again:
- per-source rate limits: a chain `maildivvy-mail-limit`, reached from
  ufw's input chain for new connections to 993 and 465, drops a source above 30 a minute
  with a burst of 60 on 993 (IMAP clients reconnect whenever IDLE drops), and above 10 a
  minute with a burst of 20 on 465. Loopback and the administrator networks are not
  limited. It is written into `/etc/ufw/before.rules` and `before6.rules` (a marked block
  after `# End required lines`, which ufw loads at boot) and loaded into the running
  firewall with `iptables-restore --noflush` and one inserted jump, never `ufw reload`;
  the kernel chain is then compared with the file rule by rule;
- `ufw allow proto tcp from any to any port 993` and `465`, which never stops the firewall
  and writes each rule for IPv4 and IPv6. ⛔ Step 3 keeps exactly these rules on a re-run
  (`maildivvy_ufw.py`'s `published`), neither deleting them nor ever adding them itself;
- `/var/lib/maildivvy/publication.json` = `{"published_at": …}`, `0644 root`, written once:
  health counts 993 and 465 open without it as a FAIL.

Its proof: the kernel accepts both ports from anywhere in both families; both answer here
(an IMAP greeting and an SMTP banner over TLS); health reads `ban` PASS with the rate limits
now judged, and `network` PASS in every check but `publication`, which only an outside
result can make PASS. The step then prints the probe's command.

⛔ **If any proof of step 18 or 19 fails, 993 and 465 are closed** (`tasks/close.yml`: the
two rules deleted by specification, the record removed, the kernel read back) and the
install stops, saying which proof failed.

**The outside probe** (`tools/outside-probe/maildivvy_outside_probe.py`, standard
library only) is run by the operator from a machine outside the installation's network:
```
python3 maildivvy_outside_probe.py <cert name> [--address <public address>] [--cafile <cert>] > probe-result.json
sudo maildivvy-publication record < probe-result.json      # on the machine
```
It asserts a TLS handshake with our certificate on 993 and 465, `554 5.7.1` at `RCPT TO`
on 465 (a refusal earlier is a FAIL), and nothing answering on 443 or the other ports not
meant to be published. A port that accepts and answers no TLS or no banner, or presents a
certificate that is not ours, makes the result INVALID: the vantage point answers the
ports itself. A vantage point on the machine's own network is invalid too, and the probe
cannot see it. The result names the SHA-256 of the leaf each mail port served
(`leaf_sha256`). `maildivvy-publication record` refuses an INVALID result, one for another
name, one whose ports served another leaf than the published certificate's (another
machine for the same name), one older than the publication, older than the result already
recorded or dated in the future, and any while the ports are not published; health reads
publication PASS only while a recorded PASS is younger than `publication_days` (30) and
names the current certificate's name and leaf, FAIL once it names another (after every
renewal, until the probe is run again). `--cafile` is for a machine whose certificate is `self-signed` or
from staging.

## What the machine needs before the install

- Ubuntu 26.04, freshly installed, reachable by SSH as an account with sudo. Step 1 refuses
  a machine that carries another mail system: a transfer agent or IMAP server this install
  never puts there (Exim, Sendmail, OpenSMTPD, Courier, Cyrus and the like, or rspamd
  outside its container), or Postfix or Dovecot on a machine it has not installed.
- In separate mode, a disk for the store and one for the index beside the system disk,
  of any sizes, and optionally a swap disk. The data disks must be empty whole disks: a
  disk with partitions, a mount or a filesystem the install did not make is refused,
  never formatted. Put the index on low-latency storage and the store on bulk storage.
  In one-disk mode, the filesystem that holds `/srv/maildivvy` is ext4, or
  xfs with reflink off.
- Memory for ClamAV's running peak, not the installer's, and the same at build and at
  run. The source ran at 8 GiB; the packaged daemon with the official databases
  and Sanesecurity peaks at 1.38 GB with concurrent reload off (measured 2026-09-20), so
  4 GiB carries this machine today, with PostgreSQL and Dovecot beside it and about
  1.8 GB still available for rspamd (step 11). Give it more
  if the community feeds are widened.
- Outbound HTTPS to the ACME CA and the DNS provider's API, and outbound DNS (53) to
  the public resolvers lego checks against; a DNS token scoped to the one
  `_acme-challenge.<name>` TXT record.
- Outbound HTTPS to the image registry for the pinned rspamd image, once per pin
  (step 11). A registry that cannot be reached fails the step; nothing is unpinned to get
  around it.
- Outbound HTTPS to `marlam.de` for mpop's tarball, and to the distribution's
  archive for the build's packages (step 12).
- For health's upstream signals (step 17): outbound DNS for the TXT record
  `current.cvd.clamav.net`, and HTTPS to `hub.docker.com`'s tag listing. Without them the
  two signals read UNKNOWN and step 17 stops.
- A resolver that answers the certificate name for the machine and its clients, never
  a router that advertises DNS without serving it.
- For the mail to be reachable from the internet, the router and NAT rules that forward
  993 and 465 to the machine: the product opens them at its own firewall (step 19) and
  never configures the router. Then a machine outside the network to run the outside
  probe from.
- With an LVM root made with `sizing-policy: all`, at least 256 MiB left free in the
  volume group, or `e2scrub_all` checks nothing.
