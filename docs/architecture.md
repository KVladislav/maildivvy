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
- An import of years of old mail brings far more at once. Measured with half a million
  imported messages in one archive on a small test machine: Dovecot's index takes about
  400 bytes a message, and its full-text index about 3.3 KB a message once searched, in
  the archive and in every mailbox given the history; a top-up links about 900 messages
  a second.
- None of this needs a queueing system, a second database or a search cluster.

## Components

| layer | component |
|---|---|
| OS and install | Ubuntu 26.04 LTS, Ansible (`ansible-core` from Ubuntu), run by the installer on the machine or from a control machine |
| store | Dovecot 2.4, maildir, one message file hardlinked into every holder's mailbox, dots in folder names escaped as `^2e` |
| ledger and state | PostgreSQL 18 |
| collection | mpop, built from a checksummed release, for POP3; for IMAP, a read-only client of Maildivvy's own on Python's `imaplib` |
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
  on a pipe, never from a file. A mailbox collected over IMAP is read by the runner's own
  client instead, which changes nothing at the provider, and the same program takes the
  slices of an IMAP mailbox's snapshot, from a timer of their own.
- **delivery filter**: scans and marks a message before it is stored, and holds mail at
  the provider while the antivirus is down. It holds no database connection.
- **notice program**: files a notice Postfix wrote to a sender, such as a provider's
  refusal, in the archive of the sender's domain. Postfix runs it as the mail owner.
- **pass**: fan-out, then the administration interface's request queue; the requests
  that wait on a provider run beside it, in a unit of their own.
- **Sent hook**: gives a sent message its name in the domain archive. It runs inside
  every IMAP process, with a database role that can do nothing else.
- **milter**: binds the sender to the login and scans at submission.
- **administration interface**: a Flask application on a unix socket behind nginx.
  Sessions are server-side rows. Every unsafe request must come from the interface's own
  origin, and every signed-in act carries a per-session token.
- **import**: `maildivvy-import`, run by the operator as the mail owner: files a directory
  of message files into a domain archive's INBOX for the pass to record, or into a
  person's Sent with the archive's name for it.
- **backup**: pauses collection, fan-out and the snapshots' slices, dumps the database
  and the fetch state together, runs the operator's store copy, and resumes.
- **health**: checks fifteen subsystems every five minutes and keeps a JSON report for
  the operator's monitoring, and when asked, a Prometheus textfile for node_exporter.
  The administration interface reads the same report, with its age, and runs nothing.
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
   credential read from a pipe, the deletion window or "keep everything", and a pinned
   certificate's fingerprint where the mailbox gives one) and bounds the run with its own
   timeout. mpop retrieves
   one message at a time and pipes it into the delivery filter, and records it as
   retrieved only when the filter succeeded, so a failure leaves that message and every
   later one at the provider for the next run.

   A mailbox collected over IMAP is read by the runner's own client, under the same
   lock, timeout and outcomes. It speaks implicit TLS alone, verified as mpop's is, and
   logs in with `AUTHENTICATE PLAIN` when the server offers it, else `LOGIN`. It sends
   only a read-only set of commands and refuses any other before it leaves the process:
   every folder is opened with `EXAMINE`, never `SELECT`, every body read with
   `BODY.PEEK[]`, which leaves it unread, and nothing is ever deleted, moved or flagged,
   so such a mailbox always keeps its mail at the provider. It reads the INBOX alone:
   every message above a mark kept on the mailbox's row, the INBOX's `UIDVALIDITY` and
   the last UID collected, in order, each held whole before the delivery filter starts,
   and the mark moves past each message filed. Only enabling the mailbox sets the mark,
   where the INBOX stands then. A run that finds no mark, or one from another
   `UIDVALIDITY`, collects nothing and says so with a cause of its own, `mark`, until the
   mailbox is disabled and enabled again; a change of protocol, host or login clears the
   mark, and the protocol changes only while the mailbox is disabled. A message refused
   for an hour is skipped by moving the mark past it, and stays at the provider. That
   hour is one of runs that stopped on the message, at least ten of them: a run that
   never reached it, and the time in which nothing ran, count nothing.
2. **Scan and mark.** The delivery filter applies its own size gate, asks ClamAV and
   then rspamd, and decides spam once, against the domain's threshold. It never rejects:
   it files. An infected or unscanned message is withheld. If the antivirus is down the
   filter exits with a temporary failure, so the message waits at the provider; past a
   one-hour bound it is delivered marked *unavailable*. A scan that fails while ClamAV
   still answers a `PING` on a new connection is about that message, not an outage: the
   message is withheld as unscanned, with a report saying the scanner failed on it, and
   nothing waits.
3. **Store.** The filter hands the message to Dovecot's delivery agent. A clean message
   goes into the domain archive's INBOX; a withheld one into the archive's quarantine,
   with a report in INBOX in its place. Nothing is delivered anywhere but the archive, and
   a stored file is never rewritten.
4. **Record and fan out.** Every minute the pass reads each archive above its cursor, in
   one transaction per domain. For each message it writes the ledger row, then adds a
   hardlink in the mailbox of every person who receives in that domain, with a delivery
   row each - none for a withheld message, or for spam where the domain keeps spam back.
   It fsyncs the directories it linked into, commits, and moves the cursor last. A failed
   domain rolls back and repeats next minute. No one message can hold a domain's cursor:
   a header that will not parse is stored as nothing, a Message-ID too long for the
   ledger's index is stored as its SHA-256 digest, and a message the database still
   refuses is rolled back alone and passed, with one log line that names the command
   recording it by hand. Then it drains the interface's request queue, one request per
   transaction. A connect and a top-up link in batches of 10,000 messages, a transaction
   each, and go back in the queue, in their place, once the run has drained for two
   minutes: the next run fans out before it goes on with them, so a top-up of any size
   holds new mail back by those two minutes and one batch. A request that fails takes
   back the names it made that no commit accounts for, also when the database went away
   under it, and a top-up asked again goes on from what is linked. A refetch, a password check, an enable, the deletion of an external
   mailbox and the discard of a snapshot wait on a provider or a snapshot's slice for up
   to half an hour, so they are drained beside the
   pass, by `maildivvy-requests.service`, which every pass starts; a slow provider never
   delays the fan-out. Deleting a mailbox, a person or a domain deletes the rows and
   commits first, which stops anybody logging in to them; then it ends their sessions
   and removes the directories, since a client still logged in would make them again.
   A removal that fails is tried again by every later pass.
5. **Read.** The person's client sees the new name through IMAP. Reading, flagging,
   moving or deleting changes only that person's own name for the message.

### A snapshot of an IMAP mailbox

A snapshot is a read-only copy of every folder of an IMAP mailbox into the store, for an
import of existing mail to read later. Nothing in it passes the delivery filter or the
pass, and nothing in it reaches anyone.

- It is asked for on the mailbox's page, and taken in slices of up to ten minutes by
  `maildivvy-snapshot.timer`, every ten minutes, as `vmail`, under a lock of its own, so a
  large mailbox never holds up the fetch of the others. Its unit may write the snapshots'
  directory alone.
- Every folder that can be opened is taken, the provider's All Mail, Junk and Trash
  included: the INBOX up to the mark, every other folder up to its last message when the
  snapshot starts. The boundary with collection is not exact; the import is to
  deduplicate by Message-ID.
- The tree is `/srv/maildivvy/store/_snapshots/<id>/`: `Maildir/`, in which each folder is
  the directory Dovecot makes for the provider's name of it, so Dovecot can read it as a
  mail location, and `manifest.json`, which records the folders, their attributes and
  progress, and what was left out. A message's file is named from its folder's
  `UIDVALIDITY` and its UID, so a slice stopped anywhere repeats nothing.
- A slice pauses before the store's filesystem would fall under health's warn level, in
  space or in inodes, and when the provider or the store fails it; every slice tries
  again. A renumbered INBOX, or a server or login changed since the start, fails the
  snapshot. A snapshot of a mailbox switched to POP3 is taken no further: it stays as it
  was, shown on the mailbox's page, until it is discarded. Health warns for a snapshot
  failed, paused for longer than a day, done without messages the provider refused to
  send or folders it left out, or asked for or under way for longer than 7 days, which
  no slice is taking.
- A snapshot is in no dump; the operator's store copy carries it. The backup and the
  upgrade pause its slices. Deleting the mailbox removes it, and a discard, which waits
  for a slice that is running, removes it alone.

### An import of message files

`maildivvy-import` files a directory of whole message files, one message each, into a
domain; it creates no domain, person or mailbox.

- `incoming` writes each file into the domain archive's INBOX under a name of its own,
  `<received moment>.<sha256>.import,S=<size>,W=<size over IMAP>`, read or unread; the
  pass records it, with that moment as its arrival, and gives it to nobody. The second
  size is the one Dovecot gives a client, every line end counted as CR LF, so that it
  never reads a file to learn it. `sent` writes each into a person's
  `Sent/<YYYY>` with its flags, names it in the archive's `Sent/<login>`, and records it as the
  Sent hook does.
- A message is deduplicated by its Message-ID against the archive's ledger and the run's
  own files, else by its bytes; a file already in the store from an earlier run is never
  written twice.
- On the store's filesystem a file is renamed, never linked; from elsewhere it is copied
  under the snapshots' free-space reserve. The staging directory is
  `/srv/maildivvy/store/_imports`.
- After 2,000 files the run waits for the pass to record them, so one minute's fan-out
  holds no more than that; it stops, to be run again, for another import of the domain,
  a backup's or an upgrade's pause, the reserve, the pass not recording in 30 minutes, a
  store refusing a write, the database going away under it, or a deletion in the domain
  waiting for it.
- Each file gets a result line, `imported`, `duplicate` or `refused` and why.
- People get the history by a top-up, which names an imported message as read mail in a
  subscribed folder of its year, `Archives/<YYYY>` (the UTC year of its received moment),
  never in the INBOX; a person's imported sent mail goes into `Sent/<YYYY>` the same way.

### Outgoing

1. **Submit.** The client authenticates on port 465, implicit TLS, as
   `<login>@<domain>`, and may send a message of up to 50 MiB, as much as the antivirus
   scans. Nothing listens on port 25, and only root may use `sendmail`.
2. **Bind the sender.** Postfix refuses an envelope sender the login does not own. The
   milter refuses a From address that is not the external mailbox's own, then scans the
   message with ClamAV before Postfix queues it. A message ClamAV fails on while it still
   answers a `PING` is refused for good, whatever the domain's too-large-to-scan setting
   says; while ClamAV does not answer, the refusal is temporary. It never rewrites.
3. **Relay.** Postfix picks the relay host and credential by sender, and logs in with the
   mailbox's SMTP login, else its POP3 login, else the address. It verifies the
   provider's certificate against the configured host name before it sends the password,
   or against the fingerprint pinned for that server and port, and hands the message to
   the provider's SMTP server. When the provider refuses it, or Postfix gives up after
   its queue lifetime, Postfix's notice to the sender goes into the INBOX of the
   sender's domain archive, unscanned, and the pass brings it to the domain's people.
   Submission refuses the empty sender such a notice has.
4. **Sent.** The client's append to its Sent folder is the confirmation. The Sent hook
   finds the file through Dovecot, adds its name under `Sent/<account>` in the archive
   and writes the ledger rows. It never moves the file and never fails the append.

### What this path decides

- **Only the archive receives from outside**, and only the pass makes names in people's
  INBOX and `Archives/<year>`. A person's Sent has names from their own client and from
  an import of their sent mail, which adds the archive's name with it. Each is a hardlink
  to the archive's one file, which keeps one file per message.
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
| `vmail` | the fetch runner and mpop, the snapshots' slices, the delivery filter, the pass, the import, the Sent hook; owns the store, the snapshots in it, the indexes and the fetch state. Its uid and gid are fixed install settings, the same on every rebuild |
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
| `/srv/maildivvy/store/_snapshots` | the snapshots of IMAP mailboxes, one directory each, beside the domains' directories; `vmail`, `0700` |
| `/srv/maildivvy/store/_imports` | where the operator stages files for `maildivvy-import`, on the store's filesystem, so they are renamed into the store; `vmail`, `0700` |
| `/srv/maildivvy/index` | Dovecot's indexes, on low-latency storage |
| `/var/lib/maildivvy/fetch` | mpop's configuration and state, per POP3 external mailbox; an IMAP mailbox keeps its mark on its row |
| `/var/lib/maildivvy/health` | the health report, `health.json` |
| `/var/backups/maildivvy` | database dumps with the fetch state beside them, UTC-stamped |
| `/var/lib/maildivvy/backup/status.json` | the newest backup run, what its store copy did, and the newest run whose store copy succeeded |
| `/var/lib/maildivvy/publication.json` | when the mail ports were opened, and the outside probe's recorded result |
| `/opt/maildivvy` | the code: `bin/`, `lib/`, `schema/` |
| `/etc/maildivvy/<consumer>/` | each consumer's `db.conf` and `pgpass` |
| `/etc/maildivvy/backup.conf` | the backup's settings |
| `/etc/maildivvy/health.conf` | optional: a health bound moved from its default |
| `/etc/maildivvy/install.yml` | the installer's settings, no secret; `0600` root |
| `/etc/maildivvy/version` | the installed release's version, written once every step passed |
| `/etc/maildivvy/installing` | the release a first installation is installing, until its steps passed |
| `/etc/maildivvy/upgrade-paused.json` | the collection, fan-out and snapshot timers an upgrade paused, until a run starts them again |
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

One initial schema, `schema/0001_initial.sql`, and migrations after it. An upgrade applies
the migrations before its steps replace the programs, so a migration only adds: what the
previous release still reads or writes is removed or narrowed a release later, and the
applier refuses a migration that narrows without saying why the previous release is not
affected. The main tables:

- **`external_mailbox`**: the provider mailbox in front of a domain: address, the
  protocol it is collected over (POP3 or IMAP), the collection and SMTP logins, hosts and
  ports (the `pop3_` columns hold the IMAP server's too), pinned certificate fingerprints,
  the deletion window or whether mail is kept at the provider (always, for IMAP), the
  stored credential (cleared whenever a host changes), the fetch's state, an IMAP
  mailbox's mark (cleared whenever its protocol, host or login changes), and its
  snapshot's state.
- **`domain`**: one DNS label, the external mailbox in front of it, the archive's password
  hash, the spam threshold and whether spam reaches people.
- **`account`**: a person: login, password hash, administrator flag, state.
- **`mailbox`**: a person's mailbox in a domain.
- **`message`** and **`delivery`**: the ledger - each message in a domain, and each name
  of it in a person's mailbox; an imported message keeps the moment it arrived where it
  was kept before and, beside it, the moment it was imported.
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
