# Architecture

How Maildivvy is built: the one machine it runs on, the components it is assembled
from, the programs of its own, and how a message passes through them. It is written for
whoever reads the code, the Ansible roles or the tests. How to install and run the
machine is in [the installation guide](installation.md) and
[the administration guide](administration.md).

Maildivvy was rebuilt from an earlier system that ran the same kind of service. Where
the code, the roles or the tests say *the predecessor*, they mean that system: several
rules here exist because of a failure measured there.

## Scale and shape

Maildivvy is sized for a small organisation:

| quantity | up to |
|---|---|
| domains | 30 |
| people | 100 |
| incoming messages per day | 1000 |

- **One machine** runs everything: the mail services, the database, the scanners and
  the administration interface. Nothing is distributed and nothing is replicated.
- At that scale the ledger grows by about 365,000 messages a year and, at five people
  per domain, about 1.8 million delivery rows. The store grows by the size of the mail
  once, whatever the number of people, since fan-out adds hardlinks: at an average of
  100 KiB, about 35 GiB a year. Thirty external mailboxes fetched every three minutes is
  ten sessions a minute.
- None of this needs a queueing system, a second database or a search cluster.

## Components

| layer | component |
|---|---|
| OS and install | Ubuntu 26.04 LTS, Ansible (`ansible-core` from Ubuntu), run by the installer on the machine or from a control machine |
| store | Dovecot 2.4, maildir, one message file hardlinked into every holder's mailbox, dots in folder names escaped as `^2e` |
| ledger and state | PostgreSQL 18 |
| collection | mpop, built from a checksummed release |
| sending | Postfix, authenticated submission on 465 only; a milter that binds From and scans at submission; the provider's certificate verified by name |
| antivirus | ClamAV from the distribution |
| spam | rspamd in a container, its image pinned by digest |
| interface proxy | nginx from the distribution |
| login-failure ban | fail2ban, banning in its own nftables table on every port |
| firewall | ufw |
| certificate | lego, pinned by checksum, through any DNS provider it supports; or the operator's own certificate |

## Programs of our own

Each is a separate process with its own operating-system user and database role:

- **fetch runner**: drives mpop for each external mailbox, with a bounded retry, and
  records each run's outcome. mpop reads the provider password from a credential helper
  on a pipe, never from a file.
- **delivery filter**: scans and marks a message before it is stored, and holds mail at
  the provider while the antivirus is down. It holds no database connection.
- **pass**: fan-out, then the administration interface's request queue.
- **Sent hook**: gives a sent message its name in the domain archive. It runs inside
  every IMAP process, with a database role that can do nothing else.
- **milter**: binds the sender to the login and scans at submission.
- **administration interface**: a Flask application on a unix socket behind nginx.
  Sessions are server-side rows. Every unsafe request must come from the interface's own
  origin, and every signed-in act carries a per-session token.
- **backup**: pauses collection and fan-out, dumps the database and the fetch state
  together, runs the operator's store copy, and resumes.
- **health**: checks fifteen subsystems every five minutes and keeps a JSON report for
  the operator's monitoring, and when asked, a Prometheus textfile for node_exporter.
  Every service is judged by exercising it, never by its unit state.
- **installer**: `maildivvy-install`, run as root from the unpacked release. It checks the
  release against its manifest, reads the installed version, installs, runs the same
  version again or upgrades (a backup, then the new migrations), and runs the
  installation steps on the machine itself.

The language is Python. Password hashes are made and checked with `openssl passwd -6`
on the machine.

## The path of a message

Two paths meet in each domain's archive: mail collected from the external mailbox, and
mail a person sends.

### Incoming

1. **Collect.** A timer starts the fetch runner every three minutes. For each enabled
   external mailbox it takes a try-lock, renders mpop's configuration (TLS on, the
   credential read from a pipe) and bounds the run with its own timeout. mpop retrieves
   one message at a time and pipes it into the delivery filter, and records it as
   retrieved only when the filter succeeded, so a failure leaves that message and every
   later one at the provider for the next run.
2. **Scan and mark.** The delivery filter applies its own size gate, asks ClamAV and
   then rspamd, and decides spam once, against the domain's threshold. It never rejects:
   it files. An infected or unscanned message is withheld. If the antivirus is down the
   filter exits with a temporary failure, so the message waits at the provider; past a
   one-hour bound it is delivered marked *unavailable*.
3. **Store.** The filter hands the message to Dovecot's delivery agent. A clean message
   goes into the domain archive's INBOX; a withheld one into the archive's quarantine,
   with a report in INBOX in its place. Nothing is delivered anywhere but the archive, and
   a stored file is never rewritten.
4. **Record and fan out.** Every minute the pass reads each archive above its cursor, in
   one transaction per domain. For each message it writes the ledger row, then adds a
   hardlink in the mailbox of every person who receives in that domain, with a delivery
   row each - none for a withheld message, or for spam where the domain keeps spam back.
   It fsyncs the directories it linked into, commits, and moves the cursor last. A failed
   domain rolls back and repeats next minute. Then it drains the interface's request
   queue, one request per transaction.
5. **Read.** The person's client sees the new name through IMAP. Reading, flagging,
   moving or deleting changes only that person's own name for the message.

### Outgoing

1. **Submit.** The client authenticates on port 465, implicit TLS, as
   `<login>@<domain>`. Nothing listens on port 25, and only root may use `sendmail`.
2. **Bind the sender.** Postfix refuses an envelope sender the login does not own. The
   milter refuses a From address that is not the external mailbox's own, then scans the
   message with ClamAV before Postfix queues it. It never rewrites.
3. **Relay.** Postfix picks the relay host and credential by sender, verifies the
   provider's certificate against the configured host name before it sends the password,
   and hands the message to the provider's SMTP server.
4. **Sent.** The client's append to its Sent folder is the confirmation. The Sent hook
   finds the file through Dovecot, adds its name under `Sent/<account>` in the archive
   and writes the ledger rows. It never moves the file and never fails the append.

### What this path decides

- **Only the archive receives from outside**, and only the pass makes names in people's
  mailboxes. That keeps one file per message.
- **The archive is read-only to its own login.** Only the product's own writes pass.
- **The provider mailbox is the only queue** for incoming mail.
- **A verdict is taken once and travels in the message.** No later stage recomputes it.
- **Sending leaves no copy of ours before the provider accepts it.**

## Users, groups and files

Privilege is separated by operating-system users. Each process runs as its own user,
reads only what its groups give it, and is hardened by its unit to write only its own
paths. The product fixes its own layout: paths are not settings.

### Users

| user | runs |
|---|---|
| `vmail` | the fetch runner and mpop, the delivery filter, the pass, the Sent hook; owns the store, the indexes and the fetch state. Its uid and gid are fixed install settings, the same on every rebuild |
| `maildivvy-milter` | the sender milter |
| `maildivvy-admin` | the administration application; database rows only, nothing on the mail disks |
| `maildivvy-health` | health, with a read-only database role; two socket-activated helpers read for it what it cannot, one as `vmail` and one as root |
| root | the backup, health's system helper, the installer |

### Database roles

One role per consumer, each with its own password in its own passfile:
`maildivvy_owner` (the schema, the backup), `maildivvy_pipeline` (fetch runner, pass),
`maildivvy_senthook`, `maildivvy_admin` (no DELETE anywhere; the provider credential
write-only), `maildivvy_milter`, `maildivvy_dovecot`, `maildivvy_postfix` (views only) and
`maildivvy_health` (read only). The initial schema ends by reading every grant it relies
on back from the catalog.

### Filesystems and paths

| path | holds |
|---|---|
| `/srv/maildivvy/store` | the message store: `<domain>/<account>` maildirs, one file per message hardlinked into every holder |
| `/srv/maildivvy/index` | Dovecot's indexes, on low-latency storage |
| `/var/lib/maildivvy/fetch` | mpop's configuration and state, per external mailbox |
| `/var/lib/maildivvy/health` | the health report, `health.json` |
| `/var/backups/maildivvy` | database dumps with the fetch state beside them, UTC-stamped |
| `/var/lib/maildivvy/backup/status.json` | the newest backup run and what its store copy did |
| `/var/lib/maildivvy/publication.json` | when the mail ports were opened, and the outside probe's recorded result |
| `/opt/maildivvy` | the code: `bin/`, `lib/`, `schema/` |
| `/etc/maildivvy/<consumer>/` | each consumer's `db.conf` and `pgpass` |
| `/etc/maildivvy/backup.conf` | the backup's settings |
| `/etc/maildivvy/health.conf` | optional: a health bound moved from its default |
| `/etc/maildivvy/install.yml` | the installer's settings, no secret; `0600` root |
| `/etc/maildivvy/version` | the installed release's version, written once every step passed |
| `/etc/maildivvy/installing` | the release a first installation is installing, until its steps passed |
| `/etc/maildivvy/upgrade-paused.json` | the collection and fan-out timers an upgrade paused, until a run starts them again |
| `/etc/maildivvy/upgrade-held` | the stamp of the backup taken before an upgrade's migrations, while that upgrade has not finished |
| `/etc/maildivvy/disks.json` | the disk mode and, in separate mode, the store and index filesystems' UUIDs |
| `/etc/maildivvy/certificate.json` | the certificate mode, name and paths; no secret |
| `/etc/maildivvy/certificate.env` | the variables lego is given: each credential's file path, never a value; `0600` root |
| `/etc/lego/credentials/<NAME>` | one DNS credential each, `0600` root, in a `0700` directory |
| `/var/log/maildivvy/install-<UTC time>.log` | each installer run's whole output; the directory `0700`, each file `0600` |
| `<textfile directory>/maildivvy.prom` | optional: health's report for node_exporter, the health user's |
| `/run/maildivvy/admin/admin.sock` | the interface's socket, opened only by nginx |
| `/usr/local/sbin/maildivvy-*` | the install's own root tools |

Logs go to the journal.

## Database schema

One initial schema, `schema/0001_initial.sql`, and migrations after it. The main tables:

- **`external_mailbox`**: the provider mailbox in front of a domain: address, POP3 login,
  hosts and ports, the deletion window, the stored credential (cleared whenever a host
  changes), and the fetch's state.
- **`domain`**: one DNS label, the external mailbox in front of it, the archive's password
  hash, the spam threshold and whether spam reaches people.
- **`account`**: a person: login, password hash, administrator flag, state.
- **`mailbox`**: a person's mailbox in a domain.
- **`message`** and **`delivery`**: the ledger - each message in a domain, and each name
  of it in a person's mailbox.
- **`request`**: the interface's queue to the pipeline, a closed list of kinds.
- **`audit`**: the journal, append-only for every role.
- **`session`**, **`break_glass`**, **`pass_cursor`**, **`schema_version`**.

### Views

Dovecot, Postfix and the milter read views, never tables. Every sending view reads only
active external mailboxes, and Postfix's lookups key on the address in lower case.

## Installation

Installation is a sequence of Ansible roles, one per step, run against one freshly
installed Ubuntu 26.04 machine. Every step reads its own result back before the next
starts, and a step whose proof fails stops the run and says why. A step that finds its
result already in place proves it and changes nothing, so a re-run is safe.

| # | step | proof read back |
|---|---|---|
| 1 | Preflight: every setting present and well formed, the disks identified, packages installable | a refusal lists every problem at once |
| 2 | Data disks and the `vmail` user | separate disks: each filesystem xfs with reflink off, mounted by UUID from the fstab; one disk: the directories on the filesystem step 1 checked, not mounts of their own; in both, `vmail`'s ids and the disk record |
| 3 | Firewall, with a self-reverting timer armed first; mail ports closed | a new SSH session through the new rules, or the operator's new SSH login, or an explicit console-only choice; then the timer cancelled |
| 4 | The container firewall block, before Docker exists | the chain matches the file rule by rule |
| 5 | Certificate: lego verified by checksum, DNS-01 issuance and daily renewal, or the operator's own certificate published | the certificate names the client-facing name and matches its key |
| 6 | PostgreSQL: loopback only, one role per consumer, the initial schema | each role queried as itself, a denied column beside a permitted one |
| 7 | The Postfix package | the account exists |
| 8 | Dovecot: configuration, the archive's ACLs, the SQL lookups, the Sent hook | the effective configuration read back; a lookup of nobody answers "no such user" |
| 9 | Postfix's configuration: submission on 465 only, per-sender relay maps | `postfix check`; each map answered |
| 10 | ClamAV from the distribution | a test virus reads *infected* through the product's own client |
| 11 | Docker, then rspamd pinned by digest, no published port | a sample message scored |
| 12 | mpop built from a checksummed tarball | the binary the unit will run reports its version |
| 13 | The programs and their units | each unit's whole command line |
| 14 | The milter, then bound to submission | the milter answers; an unauthenticated transaction is refused as it should be |
| 15 | The administration interface behind nginx, on 443 alone | a request through the proxy answers |
| 16 | Backup and its daily timer | a first dump, judged by its content |
| 17 | Health and its timer | every subsystem PASS or WARN, or UNKNOWN where a fresh machine has no data yet |
| 18 | The ban: fail2ban jails for Dovecot and Postfix | each jail proved on the running machine: a real failure line matched, a documentation address banned, one fewer failure not |
| 19 | Publication: rate limits, then 993 and 465 opened | health reads the ban PASS before anything opens; the ports answer; a failure closes them again |

The installation ends empty: no domain, person or external mailbox. The first
administrator signs in with the break-glass password and creates the rest.

## Tests

- **Unit tests** run locally in seconds and need no mail machine: `make test-unit`.
- **Machine tests** install the product on a disposable virtual machine with the real
  Dovecot, Postfix, PostgreSQL, ClamAV, rspamd and mpop, and a stub provider standing in
  for the outside. They drive the path of a message end to end, every failure path, the
  privileges, every screen of the interface in a browser, a full install, a reboot and a
  second run that changes nothing. They run before every release; they are not part of
  this repository.

Rules the tests keep: a positive control beside every "nothing happened"; the whole
chain driven from one input; real binaries against a stub provider, never stubs of our
own programs; what a unit actually runs is asserted, not what it was meant to run; no
intermittent failure is retried away.
