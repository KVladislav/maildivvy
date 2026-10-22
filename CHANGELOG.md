# Changelog

Every release of Maildivvy, newest first. Versions follow [Semantic Versioning](https://semver.org/);
in 0.x, a minor version may change settings or behaviour, and says how here.

## Unreleased

## 0.2.1 - 2026-10-22

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
