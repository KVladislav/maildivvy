# Changelog

Every release of Maildivvy, newest first. Versions follow [Semantic Versioning](https://semver.org/);
in 0.x, a minor version may change settings or behaviour, and says how here.

## Unreleased

## 0.3.0 - 2026-11-21

### Added

- An external mailbox can be collected over IMAP as well as POP3: the add form's
  **Protocol** chooses, and the server's fields are named by it. Over IMAP, Maildivvy
  only reads: it changes nothing at the provider. Every folder is opened read-only, every
  message read without marking it as read, nothing deleted, moved or flagged, so an IMAP
  mailbox always keeps its mail there. Its INBOX is collected from where it stood when the
  mailbox was enabled; disabling it keeps that starting point, so enabling it again
  collects what arrived meanwhile. A new host, login or protocol, or a provider that
  numbers its INBOX afresh, makes the next enabling start from where the INBOX then
  stands. A new IMAP host or login on an enabled mailbox, or a renumbered INBOX, stops its
  collection with the cause `mark` until the mailbox is disabled and enabled again. The
  protocol changes only while the mailbox is disabled.
- A snapshot of every folder of an IMAP mailbox, asked for on its page: a read-only copy
  into the store, under `/srv/maildivvy/store/_snapshots`, for an import of existing mail
  to read later. A new timer, `maildivvy-snapshot.timer`, takes it in slices every ten
  minutes; it pauses before the store reaches health's warn level, which its slices read
  as `vmail` from `/etc/maildivvy/health.conf` when you have one: that file must be
  readable by `vmail` too (`0644` does), or every slice pauses. A message the provider
  refuses to send is asked for again for about an hour once every folder is taken; a
  snapshot that ends without some reads *done, N not copied*, and one that left folders
  out *done, N folders left out*. Health warns for a snapshot failed, paused for longer
  than a day, done without messages the provider refused or folders it left out, or not
  advancing. A backup and an upgrade pause it with collection, waiting up to about an
  hour for a run of slices to end, and the store copy carries it; no dump does. The
  administration guide's new § 6 says how it runs and how to discard one.
- The upgrade applies a new migration, for the protocol, the IMAP mailbox's starting
  point and the snapshot, and starts the new timer at its end.
- `maildivvy-import` files mail kept elsewhere into the machine from a directory of whole
  message files: `incoming` into a domain archive, `sent` into a person's Sent and the
  archive's. Each message is deduplicated by its Message-ID, renamed from
  `/srv/maildivvy/store/_imports` (a new directory the upgrade makes) or copied from
  elsewhere, and given a line in a result file; `--dry-run` writes nothing, `--scan` asks
  ClamAV. People get the history with a top-up, as read mail. A run stops and is run
  again for a backup or an upgrade, the free-space reserve, a deletion or PostgreSQL
  restarting under it, and repeats nothing. The administration guide's new § 7 says how to stage, run and follow it.
- A migration adds the moment a message was imported beside the moment it arrived.

### Changed

- An IMAP mailbox's messages over 50 MiB are no longer downloaded: Maildivvy asks each
  message's size first, skips one over 50 MiB (the antivirus's scan limit and the largest
  message the machine sends), and goes on with the rest. The message stays at the
  provider, where you can read it; the journal names it with its size, and health warns
  and the mailbox's page says so for a week (migration 0011). Before, such a
  message was downloaded whole, and one that could not be filed was downloaded again on
  every run, which could pass a provider's daily download limit.
- A person's login may be typed in capitals: **Add person**, the sign-in page and
  `maildivvy-import sent --login` take `Ivan` as `ivan`, as mail clients already did.
  Before, the form refused a capital and the sign-in page did not find the person.
- Dovecot's indexer may take 1 GB of memory instead of 256 MB: under the old bound it could
  not index an archive of half a million messages, and every search of it failed.
- Dovecot's IMAP process may take 1 GB of memory instead of 256 MB: under the old bound,
  opening a domain archive's INBOX of about 360,000 imported messages ran out of memory
  once new mail had reached it, and every later opening failed the same way.
- The fan-out's run takes no new request from the administration interface's queue after
  two minutes; what is left waits for the next run, a minute later, so a queue of large
  top-ups no longer holds everyone's new mail back for hours.
- A top-up and the connect of a new mailbox link in batches of 10,000 messages, each kept
  as soon as it is done. After two minutes of them the request goes back in the queue, in
  its place, and the next run delivers new mail before it goes on, so one large top-up
  no longer holds everyone's new mail back for its whole length, and its size is no
  longer bounded by the hour a run may take. The journal shows how many messages it has
  linked so far. A top-up that fails says how many were linked before it; asked again, it
  goes on from there.
- The add form's provider port box starts empty, for a POP3 mailbox too: left empty, the
  port is the protocol's own, 995 for POP3 and 993 for IMAP. Changing a saved mailbox's
  protocol does not change its port: set it under **Provider servers**.
- The installation setting `maildivvy_postfix_inet_protocols` is withdrawn: the machine serves
  IPv4 alone, as every other listener already did, and `all` stopped the install at Postfix's
  step. An `install.yml` that still carries the line is refused at the first step, naming it;
  remove the line and run the installer again.
- rspamd no longer sends fuzzy hashes of every message it scores to rspamd.com: the
  image's `rspamd.com` fuzzy rule is off, with the modules that would follow a message's
  links (`url_redirector`), probe its sender's mail server (`mx_check`) or fetch rules
  while running (`rspamd_update`). Each is off by name, and the install reads every one
  back from the running scanner. The public feed added little since its full lists became
  paid; no `FUZZY_*` symbol is scored any more. The installation guide's outbound access
  now names what rspamd still reaches: its lists at `maps.rspamd.com` and the ASN lookup
  at `asn.rspamd.com`.

### Security

- The `postfix` and `www-data` accounts are no longer members of `ssl-cert`, the group that
  can read the certificate's private key. Postfix and nginx read the key as root before
  they drop privileges, so the membership gave every mail and web worker process read
  access to the key for nothing. The upgrade takes both accounts out of the group and
  restarts the two daemons; the key keeps its mode, `0640 root:ssl-cert`.
- The certificate is served from `/etc/maildivvy/tls/<name>.crt`, no longer from
  `/etc/ssl/certs/`, where every `update-ca-certificates` run (any `ca-certificates`
  upgrade) gave a self-signed certificate a hash link and so made it a trusted root of the
  machine's default trust store. The upgrade moves the certificate unchanged and removes
  the old file and its link; the key stays in `/etc/ssl/private/`. Copy the certificate
  for the outside probe's `--cafile` from the new path.
- The backup's unit and health's store reader may open unix sockets only: neither opens
  a network socket of its own.
- An authenticated login can no longer deliver into a mailbox on the machine itself: a
  message to `root@[127.0.0.1]`, or to any user at one of the machine's own addresses,
  was delivered by Postfix's local transport to `/var/mail` on the system disk, past the
  per-sender check that refuses everything else. Postfix's local and virtual transports
  are now refused like its default one, so such a recipient is refused at RCPT. The two
  mailbox limits that only let those transports start are removed on upgrade. Root's own
  mail, cron's output included, was already refused and still is.
- A provider password could be written to the system journal. Adding an external mailbox
  whose address or POP3 login held a C1 control character (U+0080 to U+009F) passed the
  form, failed the database's check, and the interface logged PostgreSQL's error, whose
  detail quoted the whole row, password included; the page was an error page. The form
  now refuses those characters beside the field, the password is written by a statement
  of its own once the row is saved, and the interface logs a database error by its code
  and constraint alone, never its text. A form a database check still refuses says
  "Not saved" with a sentence instead of an error page. If such an address was ever
  typed, the password may be in the `maildivvy-admin` unit's journal: change it at the
  provider.

### Fixed

- lego is repinned to 5.6.0 from 5.4.1, by version and sha256 for each architecture,
  checked against the release's checksums file. Upstream's 5.5.0 and 5.6.0 add DNS
  providers and fix several (among them punycode domains on renewal, and a log flag
  that a configuration file overrode); the commands Maildivvy runs are unchanged.
- rspamd is repinned to 4.3.0 from 4.2.3, by digest, with its tag. Upstream's release
  changes scoring: SPF is evaluated in the order of its terms, DKIM refuses signatures
  with duplicated tags, `l=0` or keys under 1024 bits, URL mismatches score apart from
  phishing, mail without a Date header no longer matches the past-date rules, and new
  symbols report truncated or unreadable archives and documents. It also fixes a
  header without a colon or an empty Deliver-To aborting a worker, and an empty MIME
  part stopping the scan of the parts after it. Its notes rename none of the settings
  Maildivvy writes; a message's score may differ slightly from 4.2.3's.
- A fault of the delivery filter itself, such as a size in `clamd.conf` it cannot read or
  a delivery agent that is not installed, no longer counts against the message in hand,
  which after an hour was skipped in every mailbox. The filter now tries a message of its
  own: when that fails too, collection holds as for a store that cannot take mail, the
  mail waits at the provider, and health's `store hold` is FAIL with the fault in its line.
- IMAP collection: a login refused with `BAD`, `[ALERT]` or any code other than
  `[AUTHENTICATIONFAILED]` or `[EXPIRED]` is recorded as the provider's error, not as a
  refused password, and a `BAD`'s words, which may repeat the password, are not kept. A
  NUL in a provider's answer no longer stops collection of every mailbox after it. A date
  or a folder delimiter Maildivvy cannot read no longer stops a mailbox on every run. A
  provider that numbers its INBOX lower without a new UIDVALIDITY stops collection with
  the cause `mark` instead of collecting nothing, silently.
- An IMAP mailbox held because the store cannot take mail no longer downloads its next
  message on every run: the provider is asked again once the store could take it. A
  frozen IMAP mailbox is tried once an hour instead of every run.
- A pause of collection, fan-out and the snapshots holds whoever starts their timers. A
  reboot inside a backup's, a restore's or a failed upgrade's pause, a re-run of the
  installer during the nightly store copy, or a start by hand no longer runs a fetch, a
  pass or a slice: the units refuse to start while the pause is recorded, and the
  installer's re-run leaves the timers to the backup or restore that holds them. Health
  reads a timer running under a recorded pause as WARN, and a backup's pause left with no
  backup running names itself. An installer whose SSH session drops outside `tmux` no
  longer leaves collection paused for good when it had applied no migration.
- A backup run now records the release and the schema that took it, and a restore
  refuses a run whose schema is not the installed programs' unless the same release took
  it, saying which release to install first. Runs from before this release record
  neither and are restored with a warning. The printed way back from a failed upgrade
  now also stops a timer the older release does not have.
- A request under which PostgreSQL restarted, or its connection was ended, no longer
  leaves the names it had made in people's mailboxes with no delivery row, nor stays
  `running` until the next run: the names are taken back and the reason is written on a
  second connection. When the connection is lost inside a commit, no name is taken back
  until the request's row has been read for whether that commit is there.
- Deleting a mailbox, a person or a domain while somebody is logged in no longer leaves
  directories behind. A mail client logged in without a folder open carried on after the
  deletion, and its next command made the mailbox's maildir and both its index
  directories again, owned by no row; the next mailbox made for that person in that
  domain would have inherited them. A deletion now deletes its rows and commits, which
  stops anybody logging in again; then it ends every session of those logins, waits for
  them to go, and only then removes the directories. If that last step fails, the request
  fails saying the rows are deleted and what is left, and every later run of the pass
  removes what is left and ends the request done. Deleting a domain no longer removes any
  file before all its rows are deleted. Health's `store` subsystem has a new check,
  `directories`, that warns of every mailbox or domain directory no row holds.
- An archive folder whose index was lost no longer has its messages read by their old
  numbers. Dovecot numbers such a folder's messages again: with both index directories
  gone, from 1 and closing any gap left by a message removed by hand, so a number could
  name another message's file and a release, a deliver-one or a top-up linked the wrong
  message; with only the uidlist directory (`ctl/`) gone, above the old numbers, and the
  pass then read the whole folder as new mail and gave everybody every message again. The
  pass now keeps each folder's UIDVALIDITY and checks it, and that the last number it
  read is still there, before it reads the folder; a folder that fails either links
  nothing, its domain's pass fails naming it, and health's `store/fan-out` names it.
  `maildivvy-pass --only <domain> --folder <folder> --renumber`, run as the mail owner,
  gives the folder's ledger rows their new numbers and lets the pass carry on. The
  administration guide's store copy now says to leave the index out whole or copy it whole,
  and what to run after a restore onto a machine rebuilt from nothing. The upgrade applies
  one database migration, `schema/0007_the_archives_uidvalidity_beside_the_cursor.sql`.
- A store that cannot take mail no longer costs each external mailbox a message. A full
  or read-only store, a folder the mail owner may not write, or Dovecot not answering
  made the delivery fail, and the fetch counted that against the message in hand: after
  an hour it skipped it, recorded as collected but never stored, and the provider deleted
  it after the deletion window. When a delivery fails, the delivery filter now asks
  whether the store could take any message at all; if not, it exits 73, the message
  stays at the provider, and collection holds with the cause `store` until a delivery
  succeeds. The fetch screen says so, and health's `store` subsystem reads FAIL (its new
  check `store hold`) while any mailbox is held. A delivery agent that does not answer
  within its bound no longer stops the filter with a traceback. The upgrade applies one
  database migration, `schema/0006_a_store_that_cannot_take_mail_is_a_fetch_cause.sql`.
- An installation or upgrade stopped between writing Dovecot's, Postfix's, rspamd's or
  nginx's configuration and restarting the daemon left it on its old configuration, and
  every later run proved the files and restarted nothing. Each of the four is now
  restarted whenever its configuration is newer than its last start (for Postfix, its last
  reload), so the next run finishes what the stopped one left. nginx is restarted rather
  than reloaded when its site changes. Dovecot's configuration is checked in a copy before
  it replaces the live files, and the interface's check that nothing listens on port 80 now
  reads every address, IPv6 included.
- The sidebar's count of withheld messages no longer reads the whole message ledger on
  every page of the administration interface, which grew slower with every message kept:
  an index answers it. A password change is now stamped at the moment
  it is written, not when its transaction began. The upgrade applies one database
  migration, `schema/0004_withheld_count_and_password_stamp.sql`.
- Every administration interface session is signed out once by this upgrade: the session
  cookie and the forms' token are now signed under keys of their own, so a token a page
  carries is never a valid cookie. Sign in again after upgrading.
- Opening a link to the interface from another site no longer signs the browser out.
  The browser withholds the session cookie on such a link and the sign-in page answers,
  as before, but it no longer deletes a cookie the request did not carry.
- Stopping the interface lets the requests it is answering finish, then removes its
  socket. It used to cut them off: systemd stops a service with SIGTERM, and only an
  interrupt from the keyboard ended the server cleanly.
- A sign-in made while a password change was being saved could open a session with the
  old password that the change did not end. The sign-in now waits for the change and
  reads the new password.
- Every time the interface prints is in UTC, with the date and the zone said, such as
  `2026-09-30 14:58 UTC`. Some places printed the database's own spelling, with seconds
  and an offset, and some only an hour of an unsaid day.
- The interface's content security policy now forbids every script, frame and loaded
  resource besides its own inlined stylesheet, where it used to forbid framing alone.
- The interface no longer waits without end on `openssl` while checking or making a
  password: after five seconds the sign-in is refused or the save fails.
- Setting or changing a provider certificate pin now clears the stored provider password,
  as changing a host always has, so the password is never presented to a certificate
  someone else pinned. Type the password again after saving a new pin; removing a pin
  keeps it. A provider that replaces a pinned certificate now costs the password as well
  as the new pin. The database clears it, as it does on a host change, so it holds for
  every writer and for two saves at once; the upgrade applies one database migration,
  `schema/0005_a_new_pin_clears_the_password_for_every_writer.sql`.
- A provider certificate pin no longer lets one external mailbox's password go to a
  certificate another mailbox pinned. Postfix applies a pin to the SMTP server, not the
  mailbox, so a pin set on one mailbox used to be accepted for every mailbox sending
  through the same host and port. A pin now holds there only while every one of those
  mailboxes names the same fingerprint; while they differ, or some name none, mail to that
  server waits in the queue and no password is sent. If several of your mailboxes share a
  pinned SMTP server, give each of them the same pin. The upgrade applies one database
  migration, `schema/0003_a_shared_smtp_pin_needs_every_sender.sql`.
- An external mailbox whose SMTP pin differs from another sending mailbox's at the same
  host and port, or that has none where the other has one, now says so beside its SMTP
  pin field and on the list, naming the other mailboxes. Before, nothing on screen said
  that mail to that server had stopped, until health reported the queue's age.
- A password is at most 256 bytes: 256 plain letters and digits, 128 Cyrillic letters.
  A longer one used to be accepted and hashed from its first 256 bytes only, so the
  interface signed in with it while every mail client was refused. The interface, the
  sign-in and the installer's `breakglass_password` now refuse it. An account whose
  password was set longer than that before this release no longer signs in anywhere:
  set its password again. A longer `breakglass_password` stops the installer until it
  is shortened.
- The journal writes a login as itself where the row carries one: a transfer's recipient,
  a new mailbox's login, and a POP3 or SMTP login before and after. A login such as
  `ivan_petrov_01`, which mixes lower case, digits and an underscore, used to be written
  as `<withheld>` like a password. Rows written before this release keep `<withheld>`.
- An upgrade started while the daily backup ran joined that backup, whose end started
  collection and fan-out again: the migrations and the installation steps then ran with
  fetches and passes going. The installer now waits for a running backup to finish,
  pauses collection itself and takes a backup of its own, and stops before any change
  if collection is running again after it. A backup run while an upgrade's pause is
  recorded starts nothing.
- After a restore that may have committed and left collection stopped, the next daily
  backup dumped the database the restore may not have reached as the newest run and
  started collection again. It now refuses, as does its unit's resume, and names the
  restore to run again; the restore, completed, lets it run.
- A fetch is read from mpop's own lines only. A traced fetch's message text, or the delivery
  filter's complaint about a message, that contained mpop's words "no messages" or "returned exit
  status" could make a fetch that retrieved mail read as having found none, or a
  refused message read as the antivirus hold.
- A transfer makes its renamed directories durable before it records the new holder, so
  a power loss right after it cannot leave the mailbox's files with the old holder while
  the database names the new one.

## 0.2.1 - 2026-10-22

Checked in full after its release, on 2026-11-14: the installation on both disk layouts,
a stranger's installation by the guide and the upgrade from the first version, which its
release had not run, all passed.

### Fixed

- rspamd is repinned to 4.2.3, by digest, with its tag. Upstream's release fixes crashes
  and leaks and changes how HTML, URLs and ARC seals are read, so a message can score
  differently than under 4.2.2. With the DNS blocklists turned on, a blocklist rule now
  scores once per matched value.

## 0.2.0 - 2026-10-20

### Added

- An external mailbox may have an SMTP login of its own. Left empty, the relay logs in
  with the POP3 login, or with the address when the POP3 login is empty or holds a colon
  (a `recent:` login).
- An external mailbox may keep its mail at the provider: nothing is deleted there,
  whatever the deletion window.
- A provider certificate that cannot be verified can be pinned by its SHA-256
  fingerprint, for the POP3 server and the SMTP server each on its own. A pinned server
  is trusted by that certificate alone. An SMTP pin holds for every external mailbox
  sending through the same host and port.
- `maildivvy_postfix_message_size_limit`, a Postfix role default that
  `/etc/maildivvy/install.yml` may set: the largest message submission accepts.

### Changed

- ⚠️ The relay logs in with an external mailbox's POP3 login where one is set, no longer
  always with the address. A provider that accepts only the address for SMTP stops
  relaying such a mailbox's mail until its SMTP login is set to the address.
- Submission accepts a message up to 50 MiB (52428800 bytes), as much as the antivirus
  scans. It was Postfix's default of 10240000 bytes.
- The upgrade applies one database migration, `schema/0002_provider_login_keep_and_pins.sql`.
  It upgrades a 0.1 release; a machine from before 0.1.0 is upgraded with a 0.1 release
  first, and the installer refuses this one there until it is.

## 0.1.3 - 2026-10-11

### Fixed

- rspamd is repinned to 4.2.2, by digest, with its tag. Upstream's release fixes
  memory-safety bugs and changes some rules (cryptocurrency addresses, hidden text in
  HTML tables, obfuscated links), so a message can score differently than under 4.2.1.

## 0.1.2 - 2026-10-02

### Changed

- The administration interface takes its designed look: every screen, the sign-in page
  and not-found now use one design system, with one blue, a word beside every colour and
  red only for a worded state, a danger zone or a refusal. No route, form field, status
  or act changes. What reads differently: an external mailbox's Enable and Disable
  buttons are a state switch whose word is the state (*enabled*, *disabled*), still
  named Enable or Disable for a screen reader; the Health screen is one box per
  subsystem, without the table's column words; a deletion page states "Messages removed:
  0" as a sentence; the delete and remove pages carry the way back as crumbs; the
  administrator mark is a lock icon beside its word; a deletion page's Cancel link
  carries a back arrow; and what the sign-in page says is a coloured notice.
- Health's colours follow the design: PASS is green, WARN amber, FAIL red and UNKNOWN
  grey, each always with its word. The top bar's health badge stays solid red whenever
  the report fails or is missing; everywhere else a FAIL, and the Health screen's
  no-report notice, is a soft red with its word rather than a solid one.
- The administration guide's upgrade section now says the whole of an upgrade in order:
  read the release's notes, get and verify the release, run its installer, and check the
  machine afterwards.

### Fixed

- The installation no longer stops when a newer rspamd is released than the one the
  version pins. Health's `spam/repin` FAIL is printed with the warnings at the health
  step and the run goes on; every other FAIL still stops it. Health on the installed
  machine still reads FAIL for it, which says to repin. Before, every installation
  failed at the health step from the hour upstream released a newer patch.
- rspamd is repinned to 4.2.1, by digest, with its tag.
- The ClamAV step's read of the community signatures accepts a database freshclam has
  updated incrementally (`main.cld` in place of `main.cvd`), and no longer counts
  freshclam's own `.sign` files as community signatures. Before, a re-run could stop
  there once the main database had been updated that way.

## 0.1.1 - 2026-09-30

### Added

- The administration interface shows health's report: a Health screen lists every
  subsystem and check with the report's time and age, and the overview lists every FAIL
  subsystem and a report that is stale or cannot be read. The screen only reads the
  report file; a stale or missing report is shown as such, never as fine. Every
  signed-in page's top bar shows health's whole state and the report's age, and each
  state has a colour of its own beside its word.

### Changed

- `/etc/maildivvy/health.conf`, when you have one, must now also be readable by
  `maildivvy-admin` (it holds no secret; `0644` does), or the interface shows the report
  as unjudged. If you made one, run `sudo chmod 0644 /etc/maildivvy/health.conf`.

### Fixed

- The installer's screen now ends step 19 with `PUBLISHED: NOW PROVE IT FROM OUTSIDE.`,
  as the installation guide says. Before, that text was only in the log.
- The outside probe no longer reports INVALID when your public address's 443 belongs
  to another service, such as a router forwarding it to another machine. Publication
  then stayed UNKNOWN for good. Now the probe fails 443 only when it answers as this
  machine: with its certificate, or with Maildivvy's sign-in page behind another
  certificate or none. Any other answer passes as another service, as long as 993 and
  465 proved the machine in the same run. Run the new probe from `tools/outside-probe/`
  and record its result (administration guide, the outside probe).
- The first certificate issuance no longer waits up to an hour, or fails, because a
  public resolver was asked before the DNS provider had published the challenge record.
  lego now waits for the record at the zone's own nameservers only (lego's
  `--dns.propagation.disable-rns`). The installation guide says what to do if an
  issuance still fails: wait up to an hour, then run the installer again.
- The installation guide runs `sudo apt-get update` before `sudo apt install minisign`.
  On a fresh machine the package was not found without it.

## 0.1.0 - 2026-09-28

### Added

- The first public release: collection from provider mailboxes, scanning, fan-out to the
  people of each domain, sending through the provider, the administration interface,
  health and backup, installed by nineteen proved steps on one Ubuntu 26.04 machine.
- Public documentation: installation and administration guides, and the architecture.
