# Changelog

Every release of Maildivvy, newest first. Versions follow [Semantic Versioning](https://semver.org/);
in 0.x, a minor version may change settings or behaviour, and says how here.

## Unreleased

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
