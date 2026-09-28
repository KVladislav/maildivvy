# Maildivvy

Maildivvy is a self-hosted mail server for a small organisation whose addresses live at
external mail providers. It collects mail from those provider mailboxes, scans it,
shares each message among the people entitled to it, and sends on their behalf through
the provider of the real address, with a small web interface to administer it.

It owns no mail domain and receives no SMTP from the internet. Your provider keeps
receiving your mail, handling MX records, SPF, DKIM and reputation; Maildivvy is what
your people connect their mail clients to.

## Who it is for

An organisation of up to about a hundred people across up to thirty domains, where
several people must read and answer the same addresses - `office@`, `orders@`,
`support@` - and each needs their own login, their own read and unread state, and their
own Sent folder, without sharing one password to the provider mailbox.

## How it differs

- **Shared mail without shared passwords.** Every message is stored once and appears in
  the mailbox of each person entitled to it. What one person reads, flags, moves or
  deletes changes only their own view.
- **One archive per domain.** Everything received and sent in a domain is kept in a
  read-only archive, with a ledger of who received what.
- **Sending through the real address.** Mail a person sends leaves through the
  provider's own SMTP server, as the provider address, so it is signed and delivered as
  mail from that provider always was. The sender is bound to the login: nobody can send
  as another address.
- **Scanned both ways.** Incoming mail is scanned by ClamAV and rspamd before it is
  stored; outgoing mail is scanned before it is queued. While the antivirus is down,
  incoming mail waits at the provider instead of arriving unscanned.
- **Proved, not just configured.** The installer is nineteen Ansible steps, and each one
  reads its own result back before the next starts. The mail ports open last, only after
  the login-failure ban has been proved on the running machine.
- **Built from standard parts.** Dovecot, Postfix, PostgreSQL, ClamAV, rspamd, nginx,
  fail2ban and mpop, with programs of its own in Python for collection, scanning,
  fan-out, the Sent hook, the submission milter, the interface, health and backup.

## Requirements

- One machine running Ubuntu 26.04 LTS, freshly installed, with at least 4 GiB of
  memory.
- Disks for the mail store and its index: see
  [the installation guide](docs/installation.md#the-machine-and-its-disks).
- A name for the machine that mail clients connect to, and a certificate for it: see
  [the installation guide](docs/installation.md#the-certificate).
- Mailboxes at a provider that offers POP3 and authenticated SMTP over TLS.
- If people read mail from outside your network: your router forwarding ports 993 and
  465 to the machine.

## Documents

- [Installation guide](docs/installation.md): what the machine needs, the settings, the
  install, the first sign-in and the first mail.
- [Administration guide](docs/administration.md): backup and restore, health and
  monitoring, the ban, upgrades, and what never to do.
- [Architecture](docs/architecture.md): how it is built.
- [The installation's roles](ansible/README.md): each step in detail.
- [Changelog](CHANGELOG.md), [security policy](SECURITY.md),
  [contributing](CONTRIBUTING.md).

## Status and support

Maildivvy is released as 0.x versions: settings and behaviour may still change between
minor versions, and the changelog says how. It is provided as-is, under the
[Apache License 2.0](LICENSE): there is no promised response time and no backport of
fixes to older releases.

## Release signing key

Each release tarball is signed with [minisign](https://jedisct1.github.io/minisign/) by
the maintainer; [the installation guide](docs/installation.md#getting-and-verifying-the-release)
says how to check it. The public key, key ID `005378842F03A0D3`, is:

```
RWTToAMvhHhTABvnWx4ZlZerhfVa0zF3W7kSMA605iJEGU7XvgGIJPpq
```

A new key would be announced here, with the reason; the key is never changed silently.

## Tests

The unit tests, and the lint of the installation roles (`ansible-lint` and Ansible's
syntax check), run locally in seconds and need no mail machine. They need Python 3.14 and
the packages `.github/workflows/ci.yml` installs, at its versions; a `.venv` at the
repository's root is used when it is there:

```
python3.14 -m venv .venv
.venv/bin/pip install pytest==9.0.2 pyyaml==6.0.3 flask==3.1.3 jinja2==3.1.6 \
    ansible-core==2.20.1 ansible-lint==26.9.0
make test-unit
make lint
```

CI runs both on every push and pull request.
