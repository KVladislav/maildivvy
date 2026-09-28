# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's private vulnerability
reporting: on this repository's **Security** tab, choose **Report a vulnerability**
(<https://github.com/KVladislav/maildivvy/security/advisories/new>). Do not open a public
issue for a vulnerability.

Include what you found, the version (`/etc/maildivvy/version` on an installed machine,
or the release tarball's name), and the steps that show it. A report is acknowledged
through the advisory itself; there is no promised response time.

## Supported versions

Fixes go into the latest release only. Older releases get no backports: upgrade to the
latest release to receive a fix. Maildivvy is provided as-is, under the
[Apache License 2.0](LICENSE).

## Scope

In scope: the programs, the installation roles, the schema and the installer in this
repository, and the configuration they write on the machine.

Out of scope: vulnerabilities in the components Maildivvy installs (Ubuntu, Dovecot,
Postfix, PostgreSQL, ClamAV, rspamd, nginx, fail2ban, mpop, lego), which belong to their
own projects - unless Maildivvy configures them insecurely.
