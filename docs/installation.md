# Installation guide

This guide is for the person who installs Maildivvy. It says what the machine needs,
which settings to decide, how to run the installation, and how to start using the
machine. Running it afterwards is in [the administration guide](administration.md); how
it is built is in [the architecture](architecture.md); each installation step in detail
is in [the roles' README](../ansible/README.md).

Placeholders are written `<like this>`. No value in this guide belongs to a real site.

## 1. Before installation

### The machine and its disks

- Ubuntu 26.04, freshly installed, reachable by SSH as an account with sudo. Maildivvy
  must be the only mail system on it: step 1 refuses a machine with another mail server
  installed (Exim, Sendmail, OpenSMTPD, Courier, Cyrus and the like), or with Postfix or
  Dovecot that this installation did not put there.
- Memory: 4 GiB carries the product. ClamAV with its signature databases peaks at about
  1.4 GB, and rspamd holds about 70 MiB.
- If the root filesystem is LVM made with `sizing-policy: all`, leave at least 256 MiB
  free in the volume group.

#### Disks

Maildivvy keeps two things apart from the system: the mail store
(`/srv/maildivvy/store`) and Dovecot's indexes (`/srv/maildivvy/index`). Choose one of
two modes with `maildivvy_disk_mode`.

**Separate disks** (`separate`, the default). The store and the index each get a disk
of their own, and a dedicated swap disk is optional. Put the index on low-latency
storage and the store on bulk storage. The disks may be of any size, the same size
included. Each must be an **empty whole disk**: no partitions, no filesystem, not
mounted. The installation formats the store and index as xfs with reflink off, mounts
them by filesystem UUID, and makes the swap disk a swap area in place of the system's
swap file.

You name each disk by its current device path. Find them with:

<!-- runnable: shell -->
```
lsblk -d -o PATH,SIZE,MODEL,TYPE
```

Step 1 refuses a device that is not a whole disk, a disk that is not empty, the disk
that holds `/`, and one disk named for two roles. Nothing is formatted until every
disk passes.

The device path is read once, at the first installation. After formatting, the
installation records each filesystem's UUID in `/etc/maildivvy/disks.json`, and every
later run finds the disks by that UUID alone. Device names that change after a reboot
change nothing, and a run with other device paths in its settings changes nothing
either.

**One disk** (`single`). The store and the index are directories on the filesystem
that holds `/srv/maildivvy`, normally the root filesystem. Nothing is formatted or
mounted. That filesystem must be ext4, or xfs with reflink off. On xfs with reflink on,
Dovecot's index rewrites make the store grow, so step 1 refuses it unless you set
`maildivvy_single_disk_allow_reflink: true`. Mail and the system then share one
filesystem, so health warns and fails at more free space than with separate disks
(30% and 15% instead of 20% and 10%).

The mode is fixed at the first installation. A later run with the other mode is
refused.

| setting | required | what it is | shape |
|---|---|---|---|
| `maildivvy_disk_mode` | no, default `separate` | separate disks for the store and index, or one disk | `separate` or `single` |
| `maildivvy_store_disk`, `maildivvy_index_disk` | in separate mode, at the first installation | the store and index disks, as they are named now | a device path, such as `/dev/sdb` |
| `maildivvy_swap_disk` | no | a dedicated swap disk. With it, the system's `/swap.img` is removed | a device path |
| `maildivvy_single_disk_allow_reflink` | no, default `false` | in one-disk mode, accept an xfs filesystem with reflink on | `true` or `false` |

In one-disk mode, leave the three disk settings out: step 1 refuses them.

A machine installed before these settings existed named its disks by size. It is
recognised by the filesystems mounted at `/srv/maildivvy/store` and
`/srv/maildivvy/index`: the next run records their UUIDs. The size settings are no longer
settings: leave them out, since `/etc/maildivvy/install.yml` refuses them.

### The network

- **Administrator networks.** Decide which networks may reach SSH (22) and the
  administration interface (443). Nothing else can. The connection that runs the install
  must come from one of them: step 3 applies the firewall and then proves that a new SSH
  session still gets through. If it does not, a timer puts the old rules back after
  300 s and the run stops as *unreachable*. Fix the setting and run again. An install run
  on the machine itself proves it by your own new SSH login instead (§ 3).
- **Outbound access**, during the install and afterwards: the Ubuntu archive; the ACME
  CA and your DNS provider's API over HTTPS; public resolvers on port 53; the lego and
  mpop release downloads (`github.com`, `marlam.de`); the container registry for the
  rspamd image and `hub.docker.com`'s tag listing; ClamAV's and Sanesecurity's signature
  mirrors, and the DNS record `current.cvd.clamav.net`; and each mail provider's POP3 and
  SMTP servers.
- **Inbound from the internet**, if people read mail from outside: forward 993 (IMAP)
  and 465 (submission) from your router to the machine. The product opens them at its
  own firewall in the last step. It never configures the router. Never forward 443 or 22.
- **A resolver** that answers the machine's mail name for the machine itself and for the
  mail clients. Do not point the machine at a router that advertises DNS but does not
  serve it.

### The mail name

The mail name, `<mail hostname>`, is the fully qualified name mail clients connect to,
and the name the certificate carries. It is not the machine's short hostname.

- Clients must resolve `<mail hostname>` to the machine: inside your network to its
  internal address, and from the internet to the address your router forwards.
- The name need not resolve publicly for an ACME certificate: it is issued by DNS-01,
  which only writes a TXT record at `_acme-challenge.<mail hostname>`.

### The certificate

Mail clients, Postfix and the administration interface all use one certificate for
`<mail hostname>`. Choose where it comes from with `maildivvy_cert_mode`.

**ACME** (`acme`, the default). The certificate is issued by Let's Encrypt over DNS-01
through [lego](https://go-acme.github.io/lego/), and renewed by a daily timer 30 days
before it expires. lego writes the challenge record through your DNS provider's API, at
the first issuance and at every renewal, so the machine keeps the provider's credentials.

- Set `maildivvy_acme_dns_provider` to lego's code for your provider, such as `desec`,
  `cloudflare` or `ovh` ([the list](https://go-acme.github.io/lego/dns/)).
- Give its credentials in `maildivvy_acme_dns_credentials`, by the names lego uses. The
  installed lego lists them for your provider with `lego dnshelp -c <provider>`, under
  "Credentials". Give only the ones your way of signing in needs: for Cloudflare, an API
  token as `CF_DNS_API_TOKEN` alone, or `CF_API_EMAIL` with `CF_API_KEY`.
- Scope the credentials as narrowly as your provider allows. Best is a token that may
  write only the TXT record `_acme-challenge.<mail hostname>`: a token that can write
  anything else can take over the zone.
- Step 5 checks every name against the installed lego's own list, under "Credentials",
  and refuses one that is not there. A name lego lists under "Additional Configuration"
  cannot be given: Maildivvy sets the propagation timeout and polling interval itself.
  Step 5 also refuses a credential that lego cannot read from a file, such as Route 53's
  access keys, because a credential never reaches lego any other way. It does not check
  that you gave every credential your provider needs, since some providers list
  alternatives (a token, or a key with an address): a missing one fails step 5 inside
  lego, with lego's own message.
- **deSEC is the provider Maildivvy is tested with.** Any other provider is reported as
  untested in step 5's output. It works the same way, but read the first issuance, and
  the first renewal a couple of months later (health's `tls` subsystem), yourself.
- The credentials reach the machine on the installation's standard input, and each is
  stored in its own root-only file under `/etc/lego/credentials/`. lego is given each
  file's path, as `<NAME>_FILE` in `/etc/maildivvy/certificate.env`, and reads the file
  itself. No credential is ever in a command line, a service's environment or a log.
- The wait for the record to propagate is at most 3900 seconds, polled every 30
  seconds against public resolvers. That suits deSEC, whose zones cache a missing record
  for up to an hour. Another provider's zone may need another value:
  `maildivvy_acme_dns_propagation_timeout` and `maildivvy_acme_dns_polling_interval`,
  role defaults you may override in the settings file (§ 2).
- An issuance takes several minutes, most of it waiting for propagation. Step 5 sitting
  on "Issue the certificate" is normal.

**Your own certificate** (`provided`). You give the certificate, its chain (the issuing
CA's certificates) and its private key, as files on the machine. Copy them there first,
readable by root alone. Step 1 refuses, before anything changes, a certificate that does
not match its key, that does not cover `<mail hostname>` or that has expired, and a key
that is encrypted. Step 5 publishes the certificate followed by the chain.

Nothing renews a provided certificate. Health warns 30 days before it expires and fails 7
days before. To replace it, put the new files at the same paths and run:

```
sudo maildivvy-cert install-provided
```

It makes the same checks, publishes the new certificate and reloads Dovecot, Postfix and
the interface. `--cert`, `--chain` and `--key` read other paths once; the next
installation run reads the settings' paths again, so keep the settings current.

**Self-signed** (`self-signed`) is for a test machine only: no mail client trusts it and
nothing renews it. Step 1 refuses it unless `maildivvy_insecure_test_certificate` is
`true`, and the installation ends with a warning saying the certificate is self-signed.

| setting | required | what it is | shape |
|---|---|---|---|
| `maildivvy_cert_mode` | no, default `acme` | where the certificate comes from. `acme-staging` issues from Let's Encrypt's staging CA, which no mail client trusts: for tests only | `acme`, `provided` or `self-signed`; `acme-staging` for tests |
| `maildivvy_acme_dns_provider` | no, default `desec` | your DNS provider, as lego names it | lego's code, such as `cloudflare` |
| `maildivvy_acme_dns_credentials` | in `acme` mode | the provider's credentials; for deSEC, `{DESEC_TOKEN: <token>}` | a mapping of lego's names to one-line values |
| `maildivvy_acme_email` | no, default none | the ACME account's contact address, which gets the CA's expiry mail | an address, or `-` |
| `maildivvy_provided_cert`, `maildivvy_provided_chain`, `maildivvy_provided_key` | in `provided` mode | the certificate, chain and unencrypted key | absolute paths on the machine |
| `maildivvy_insecure_test_certificate` | no, default `false` | allows `self-signed`, for a test machine. On the machine, the installer's `--insecure-test-certificate` sets it, and the settings file may not | `true` or `false` |

In `provided` and `self-signed` mode, leave the DNS credentials out: step 1 refuses them,
and a machine switched to either mode has its stored credentials removed.

## 2. Install-time settings

The settings are Ansible variables in one YAML file.

- **On the machine** (§ 3), the file is `/etc/maildivvy/install.yml`. The installer writes
  it from your answers, or reads the one you wrote. It may hold only the settings in this
  guide's tables and the role defaults the roles' README lists as an operator's to
  override (below): any other name, a misspelled one included, is refused by name, and so
  is `maildivvy_insecure_test_certificate`. It holds no secret: the installer asks for the
  break-glass password and the DNS credentials on each run, and refuses a settings file
  that carries one. It must be `0600` and root's, since it names a command the backup
  runs as root. Its values and the secrets are taken literally, never as templates, so a
  password or a store-copy command may contain `{{`, `{%` or `{#`.
- **From a control machine**, the file also holds the break-glass password and the DNS
  credentials: keep it out of any repository and readable by you alone.

Step 1 checks every setting before anything changes, and a refusal lists every missing,
malformed or ambiguous setting at once. The disks' and the certificate's settings are in
their sections above.

| setting | required | what it is | shape |
|---|---|---|---|
| `maildivvy_hostname` | yes | the short hostname of the machine these settings are for. Step 1 compares it with the machine's own hostname and refuses a mismatch, so settings aimed at the wrong machine change nothing. The install never sets the hostname | `[a-z0-9-]`, one label |
| `maildivvy_cert_name` | yes | the mail name: the name clients connect to, which the certificate carries. Postfix also uses it as its own name | `<mail hostname>`, lower case, two labels or more |
| `maildivvy_vmail_uid`, `maildivvy_vmail_gid` | yes | the fixed ids of `vmail`, the store's owner. Keep them the same on every rebuild of one deployment, or a restored store belongs to nobody. A re-run with other ids is refused | a number from 100 to 999 |
| `maildivvy_admin_networks` | yes | the only sources SSH and the interface accept, and the networks the ban and the rate limits never touch | a list of CIDR networks with no host bits set, such as `["<network>/<prefix>"]`; one wider than /16 (IPv4) or /48 (IPv6) must be a private range, and none wider than /8 (IPv4) or /7 (IPv6), the widest private ranges |
| `maildivvy_firewall_confirmation` | no, default `new-session` | how the firewall steps learn you can still log in before they cancel the timer that would put the old rules back: `new-session` opens a new SSH session through the new rules (an install from another machine); `ssh-login` waits for your new SSH login from `maildivvy_admin_ssh_source`; `console` confirms nothing and says so, if you work from the console only. An install run on the machine itself cannot use `new-session` | `new-session`, `ssh-login` or `console` |
| `maildivvy_admin_ssh_source` | with `ssh-login` | the address you log in from over SSH. It must be inside an administrator network | one IP address |
| `maildivvy_container_pool` | no, default `172.16.0.0/12` | the range the container firewall block treats as containers. It must not overlap an administrator network | one CIDR network |
| `maildivvy_breakglass_password` | yes | the break-glass password (§ 4). Stored only as a hash | 15 characters or more |
| `maildivvy_backup_keep` | no, default 8 | how many backup runs are kept, counted and never aged | 1 to 1000 |
| `maildivvy_backup_store_copy` | no, default none | your command that copies the mail store, run as root inside each backup ([administration guide § 1](administration.md#1-backup-and-restore)) | one line of shell |
| `maildivvy_health_textfile_dir` | no, default none | a directory for node_exporter's textfile collector, where health writes `maildivvy.prom` ([administration guide § 3](administration.md#3-health)). Step 17 creates it, owned by the health user, when it does not exist. An existing directory must already be the health user's, `maildivvy-health`: step 1 refuses one that is not, and nothing re-owns it | an absolute path without spaces |

A settings file for an install on the machine itself, written as `<settings file>` on
the machine (§ 3 puts it in its place):

<!-- runnable: file <settings file> -->
```yaml
maildivvy_hostname: <short hostname>
maildivvy_cert_name: <mail hostname>
maildivvy_vmail_uid: <100-999>
maildivvy_vmail_gid: <100-999>
maildivvy_disk_mode: separate
maildivvy_store_disk: <store disk device>
maildivvy_index_disk: <index disk device>
maildivvy_admin_networks: ["<network>/<prefix>"]
maildivvy_firewall_confirmation: ssh-login
maildivvy_admin_ssh_source: <address you log in from>
maildivvy_cert_mode: acme
maildivvy_acme_dns_provider: desec
maildivvy_backup_store_copy: "<one-line store copy command>"
```

It holds no secret: the installer asks for the break-glass password and the DNS
credentials, or reads them on its standard input (§ 3). From a control machine, add
both to the file instead, as `maildivvy_breakglass_password` and
`maildivvy_acme_dns_credentials` (the secrets file of § 3 shows them), and leave out the
two firewall confirmation lines: a control machine confirms by a new session of its own.

Each role also has defaults, such as the antivirus's limits, the rspamd pin and the fetch
period. [The roles' README](../ansible/README.md) lists them. A role default is not an
install setting and step 1 does not ask for it, but the settings file may override the
ones the roles' README lists as an operator's to override; `/etc/maildivvy/install.yml`
refuses every other name, a role's own paths and programs included.

## 3. Running the installation

### Getting and verifying the release

Each release is published on the repository's GitHub Releases page as three files:
`maildivvy-<version>.tar.gz`, its signature `maildivvy-<version>.tar.gz.minisig`, and
`SHA256SUMS`. Download all three, then check the signature before you unpack anything,
with [minisign](https://jedisct1.github.io/minisign/) (in Ubuntu's archive):

<!-- runnable: shell -->
```
sudo apt install minisign
minisign -V -m maildivvy-<version>.tar.gz -P <release signing key>
```

The release signing key is in [the README](../README.md#release-signing-key). Take it
from the repository's page on GitHub, not from a tarball: a key that comes with the
file it checks proves nothing. A good release prints `Signature and comment signature
verified` and a trusted comment naming the tarball and its version; check that it is
the version you meant to download. Anything else - a failed check, another version -
means the file is not the release: do not install it.

`SHA256SUMS` tells you the download is whole:

<!-- runnable: shell -->
```
sha256sum --check SHA256SUMS
```

It is not signed; the signature is what tells you the release is ours. Once unpacked,
the installer checks every file of the release against the release's own `MANIFEST`
before it changes anything.

### On the machine

Copy the release to the machine, and as the account with sudo, unpack it:

<!-- runnable: shell -->
```
tar -xzf maildivvy-<version>.tar.gz
cd maildivvy-<version>
```

and run the installer from the release directory:

```
sudo ./maildivvy-install
```

Run it inside `tmux` (Ubuntu server has it) or `screen`, so that the run goes on if your
SSH session drops: steps 3 and 4 change the firewall while it runs. After a drop, log in
again and reattach with `tmux attach`.

It works in this order, and stops at the first thing that is wrong:

1. **Checks.** The machine runs Ubuntu 26.04, the installer runs as root, and every file
   of the release is as the release's `MANIFEST` lists it: none changed, missing or
   added. It reads which version is installed and says whether it installs, runs the
   same version again or upgrades ([upgrades](administration.md#upgrades)). A refusal
   here changes nothing.
2. **Ansible.** It installs `ansible-core` from the Ubuntu archive, the version the
   installation is tested with.
3. **Settings.** It reads `/etc/maildivvy/install.yml` (§ 2). When there is none, it asks
   for the settings in turn: the mail name, one number for both `vmail` ids, the disks
   (with each disk's size and model shown), the administrator networks, how the firewall
   steps are confirmed, the certificate, the store copy and the textfile directory. It
   takes `maildivvy_hostname` from the machine's own hostname, and does not ask for
   `maildivvy_single_disk_allow_reflink`, `maildivvy_container_pool` or
   `maildivvy_backup_keep`, which keep their defaults unless you add them to the file. It
   then shows them all and, on your `yes`, writes the file. To change a setting later,
   edit the file and run the installer again.
4. **Secrets.** It asks for the break-glass password, twice, and in `acme` mode for your
   DNS provider's credential names and each value. Nothing you type is shown. The secrets
   are handed to the run in a root-only file in memory, under `/run`, which is removed as
   soon as the run has read it. The break-glass password is stored only as its hash, and
   the DNS credentials only as [the certificate section](#the-certificate) says.
5. **The steps.** It runs the nineteen steps on the machine and prints a line per step,
   what a step says to you, and a failure's message. The whole output is kept in
   `/var/log/maildivvy/install-<time>.log`, readable by root alone.
6. **The version.** Once every step passed, it records the release in
   `/etc/maildivvy/version`.
7. **What is left.** It ends with the list of what you still have to do: the outside
   probe, the router, the first sign-in, and the store copy before the first external
   mailbox is enabled.

Run it again at any time: a step that finds its work done proves it and changes nothing.

**The firewall steps wait for you.** A run on the machine has no session of its own that
crosses the firewall, so `maildivvy_firewall_confirmation` cannot be `new-session` there.
Choose one of:

- `ssh-login`, with `maildivvy_admin_ssh_source` set to the address you log in from. When
  step 3 or step 4 changes the firewall, the installer prints `Waiting for a new SSH login
  from <address>` and asks you to open a new SSH session to the machine from that address.
  Keep the session the installer runs in open. If no login arrives before the timer runs
  out (300 s), the old rules come back and the run stops. Have a second terminal ready
  before you start.
- `console`, if you work at the machine's console only. The steps then keep the new rules
  without waiting, and say that no SSH login confirmed them.

**Without questions.** With the settings file in place, `--secrets-on-stdin` asks nothing
and reads the secrets as a YAML mapping on standard input. Write them as
`<secrets file>`, readable by you alone:

<!-- runnable: file <secrets file> -->
```yaml
maildivvy_breakglass_password: "<15 characters or more>"
maildivvy_acme_dns_credentials:
  DESEC_TOKEN: "<token scoped to the challenge record>"
```

It may hold only these two settings; anything else belongs in the settings file. Then, from the release directory, put the settings file of § 2 in
its place, run the installer, and remove the secrets file:

<!-- runnable: shell -->
```
sudo install -D -m 0600 -o root -g root <settings file> /etc/maildivvy/install.yml
sudo ./maildivvy-install --secrets-on-stdin < <secrets file>
rm <secrets file>
```

**Its exit code** says how the run ended, for a script that runs it:

| exit | what happened |
|---|---|
| 0 | installed, the same version run again and proved, or upgraded |
| 1 | installing `ansible-core`, a step or the upgrade failed. The screen says what; the log has everything |
| 2 | refused. A refusal by the checks before the log is started changes nothing; a refusal of the settings or the secrets, after `ansible-core` was installed, changes nothing else |

**A test machine.** `--insecure-test-certificate` allows `maildivvy_cert_mode:
self-signed` ([the certificate](#the-certificate)). It is an option of the command alone:
a settings file with `maildivvy_insecure_test_certificate` is refused, so a self-signed
certificate is chosen again on every run.

### From a control machine

On the machine you install from, with Ansible (`ansible-core`) and a copy of this
repository. Write an inventory with one host in group `maildivvy`:

```yaml
maildivvy:
  hosts:
    <mail machine>:
      ansible_host: <address>
      ansible_user: <account with sudo>
```

Then, from the repository's root:

```
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook -i <inventory> -e @<settings file> ansible/site.yml
```

Add `-K` if sudo on the machine asks for a password. Keep the output:
`| tee <install log>`.

A control-machine run takes no backup and applies no version rule, so it is for a fresh
installation, or for running the same version again. Step 1 refuses it on a machine whose
`/etc/maildivvy/version` names another version than the release's `VERSION`: upgrade a
machine that `maildivvy-install` manages with `maildivvy-install` ([upgrades](administration.md#upgrades)).
It refuses too a machine installed before 0.1.0 (our database, no version file and no
unfinished installation): `maildivvy-install` of a 0.1 release upgrades it. With no version
file and no unfinished installation, a database that does not answer is refused as well,
since the run cannot tell such a machine from a clean one: start PostgreSQL and run again.
At its end the run records the release's version in `/etc/maildivvy/version`, so a later
`maildivvy-install` finds the machine at that version. Until then a first installation is
recorded in `/etc/maildivvy/installing`, as `maildivvy-install` records its own, so one
that stopped part way is installed again, never taken for an installed machine. A run with `--tags <role>[,<role>]`,
which re-runs those steps alone ([the roles' README](../ansible/README.md)), records
nothing. `--tags` exists only for a control-machine run; `maildivvy-install` always runs
every step.

### Reading the step proofs

The run is the nineteen steps of [the architecture § Installation](architecture.md#installation),
in order. Every step reads its own result back before the next starts.

- **A failed proof stops the run** and says what failed. Nothing after it runs. Fix the
  cause and run again: a step that finds its work done proves it and changes nothing.
- **Step 1** fails once with every problem in the settings and the disks listed.
- **Step 3** can stop the run as *unreachable* (§ 1, administrator networks).
- **Step 5** issues the certificate, which can take several minutes.
- **Step 17** runs health through its unit. It accepts every subsystem PASS or WARN, and
  UNKNOWN only where a fresh machine has no data yet (no external mailbox, no delivery,
  no mail to search). It prints each WARN it accepted.
- **Steps 18 and 19** prove the ban and then open 993 and 465. If any of their proofs
  fails, both ports are closed again and the run stops naming the proof. Step 19 ends
  with `PUBLISHED: NOW PROVE IT FROM OUTSIDE` and the command that runs the outside probe
  ([administration guide § 2](administration.md#2-the-outside-probe)).
- The recap must read `failed=0`.

The installation ends empty: no domain, person or external mailbox.

## 4. First sign-in and first mail

### Break-glass

Open `https://<mail hostname>/` from an administrator network. Sign in as `break-glass`
with `maildivvy_breakglass_password`. Every act of a break-glass session is journaled as
break-glass. Break-glass is for the day the accounts table cannot be used; use it now to
create the first administrator, then sign out.

To change the break-glass password, run the installation again with a new value. That
ends every open break-glass session.

### The first administrator

**People → Add person**, with **Administrator** ticked. Leave both password fields
empty and a password is generated and shown once, on the next page, with the mail client
settings. It is not shown again, not logged and not journaled. A password you type
yourself must be 15 characters or more. Sign out, and sign in as that person.

The last active administrator cannot be revoked, blocked or deleted, and nobody deletes
their own account.

### A domain

**Domains → Add domain.** The label is one DNS label, lower case, such as `<label>`:
logins in this domain are `<login>@<label>`. It is a name inside Maildivvy, not the
provider's domain. The domain's archive is made in the same act, with a read-only IMAP
login `archive@<label>` and the password you type twice.

### A person and their mailbox

**People → Add person** as above, without **Administrator**. Then **Mailboxes → Give
someone a mailbox**: the domain and the person. A mailbox receives mail that arrives from
then on; earlier mail is a top-up afterwards. The pipeline makes the mailbox on disk
within about a minute.

The person's mail client uses `<mail hostname>` for both IMAP (993) and submission
(465), implicit TLS on both, with the login `<login>@<label>` and the one password.

### An external mailbox

**External mailboxes → Add external mailbox.** This is the provider mailbox the domain's
mail is collected from, and sent through. You give the address, the POP3 login if it is
not the address, the provider password, the POP3 and SMTP hosts and ports, the deletion
window in days, and the domain in front of it. It is saved **disabled**.

⛔ **Give both hosts by name, never by IP address.** The relay verifies the provider's
certificate against the host name the mailbox is configured with before it sends the
password, and a host given as an IP address never matches. The forms and the database
refuse an IP address for either host.

- The POP3 port is implicit TLS. An SMTP port of 465 is sent with implicit TLS; any other
  SMTP port, such as 587, uses STARTTLS.
- Changing either host clears the stored password: type it again.
- Changing the POP3 login makes the fetcher treat the mailbox as new and collect its
  whole window again.
- The deletion window counts from when the fetcher first saw a message. After it, the
  message is deleted at the provider, and this machine holds the only copy.

Then **Check password** asks the pipeline to log in at the provider, and **Enable**
checks the password again and starts collection. Both are requests the pipeline performs
within about a minute; the page says when to look again, and a refusal shows its reason
on the mailbox's page.

### Copy the store before you enable the first external mailbox

The pipeline refuses to enable an external mailbox until a backup has been taken. That
gate checks only the product's half: the database and the fetch state. **The store's
copy is yours, and nothing checks it.** Once an external mailbox is enabled its deletion
window starts running, and after it the provider no longer holds the mail. So before the
first enable:

1. Set `maildivvy_backup_store_copy` in the settings file and run the installation
   again, unless it was set from the start.
2. Take a backup by hand, and read its result:

   <!-- runnable: shell -->
   ```
   sudo systemctl start maildivvy-backup.service
   cat /var/lib/maildivvy/backup/status.json
   ```
3. In what it prints, `store_copy` must be `ok`, not `none configured` and not
   `failed, exit <n>`.
4. Check the copy itself where your command wrote it: every file there, owners kept, and
   hardlinks kept ([administration guide § 1](administration.md#what-the-store-copy-must-do)).

Only then enable the external mailbox.
