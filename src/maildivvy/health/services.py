"""The services a client or the machine talks to: `tls`, `dovecot`, `postfix`, `milter`,
`search` and `interface`.

⛔ EVERY SERVICE IS JUDGED BY EXERCISING ITS FUNCTION, NEVER BY ITS UNIT STATE.
Dovecot read `active` with its auth worker dead, the milter with its socket outside the
chroot, the interface with every screen answering 500. So Dovecot is asked for a login,
submissions for its greeting and its AUTH, the milter for a negotiation in its own
protocol, and the interface for a page through the proxy - each over TLS, verified by the
certificate's name, never with verification turned off.

The login Dovecot is asked for cannot exist (`.invalid` is no domain label), so the
answer proves the passdb was asked and answered, without health holding any password:
`[AUTHENTICATIONFAILED]` is the database saying "no such user"; `[UNAVAILABLE]` is the
lookup failing, which is what a dead auth worker or an unreachable database reads as.
"""

import datetime
import hashlib
import imaplib
import json
import re
import socket
import ssl
import time

from maildivvy.health import probe
from maildivvy.health.context import check, passed
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, UNKNOWN, WARN, Check

IMAPS, SUBMISSIONS, HTTPS = 993, 465, 443
ENDPOINTS = {IMAPS: "imaps", SUBMISSIONS: "submissions", HTTPS: "the interface"}
PROBE_LOGIN = "maildivvy-health@health.invalid"   # no domain label ends in `.invalid`
PROBE_PASSWORD = "not-a-password"
RENEW_UNIT, RENEW_TIMER = "maildivvy-cert-renew.service", "maildivvy-cert-renew.timer"
SENT_FAILURE = "maildivvy-sent-hook: failed:"   # senthook/hook.py FAILURE: one line per failure
MILTER_UNIT = "maildivvy-milter.service"
MILTER_GROUP = "postfix"
EX_TEMPFAIL_RETRY = 3  # seconds, the auth side's pool reconnects on the next lookup


# --- tls --------------------------------------------------------------------


def not_after(der):
    """The certificate's expiry, read by openssl from its DER."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    out = probe.command(["openssl", "x509", "-noout", "-enddate"], input=pem, check=True).stdout
    match = re.match(r"^notAfter=(.+)$", out.strip())
    if not match:
        raise Unreadable("openssl printed no expiry")
    return datetime.datetime.strptime(match.group(1), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc)


def fingerprint(der):
    return hashlib.sha256(der).hexdigest()[:16]


FIRST_PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def published_der(path):
    """The published certificate's leaf. An ACME certificate is published as lego wrote it,
    the leaf and then the CA's certificate; read whole, the chain is no certificate at all."""
    try:
        with open(path) as handle:
            first = FIRST_PEM.search(handle.read())
        if first is None:
            raise ValueError("no PEM certificate in it")
        return ssl.PEM_cert_to_DER_cert(first.group(0))
    except (OSError, ValueError) as err:
        raise Unreadable(f"{path}: {err}") from None


@check("mode")
def certificate_mode(ctx):
    """In `self-signed` and `acme-staging` mode no client trusts the chain: the
    certificate is reported as what it is, never as a pass."""
    mode = ctx.certificate()["mode"]
    if mode == "acme":
        return passed("mode", "acme: the production CA")
    if mode == "provided":
        # the expiry is read against the provided bounds instead
        return passed("mode", "provided: the operator's own certificate, renewed by the operator")
    if mode == "acme-staging":
        return Check("mode", WARN, "acme-staging", "the staging CA's certificate: every client "
                                                   "refuses it; for a test machine only")
    if mode == "self-signed":
        return Check("mode", WARN, "self-signed", "a self-signed certificate: every client "
                                                  "refuses it; for a test machine only")
    return Check("mode", FAIL, mode, f"{mode!r} is not a certificate mode the install knows")


def judge_expiry(endpoints, published, now, conf, mode="acme"):
    """the expiry is UNKNOWN, not FAIL, until every endpoint it covers serves.

    `endpoints` is {port: DER or Unreadable}; every endpoint must serve the published
    certificate, or a consumer was not reloaded after a renewal. A provided
    certificate is renewed by nothing, so it is judged against its own, earlier bounds.
    """
    if mode == "provided":
        warn, fail = conf.provided_certificate_warn_days, conf.provided_certificate_fail_days
        late = "nothing renews a provided certificate: replace it with `maildivvy-cert install-provided`"
    else:
        warn, fail = conf.certificate_warn_days, conf.certificate_fail_days
        late = "the renewal due 30 days before has not happened"
    silent = {port: err for port, err in endpoints.items() if isinstance(err, Exception)}
    if silent:
        return Check("expiry", UNKNOWN, "not every endpoint serves",
                     "; ".join(f"{port} ({ENDPOINTS[port]}): {err}" for port, err in sorted(silent.items())))
    stale = [port for port, der in sorted(endpoints.items()) if fingerprint(der) != fingerprint(published)]
    ends = not_after(published)
    days = (ends - now).total_seconds() / 86400
    reading = (f"{', '.join(str(p) for p in sorted(endpoints))} serve {fingerprint(published)}, "
               f"valid until {ends.date().isoformat()} ({days:.0f} days)")
    if stale:
        return Check("expiry", FAIL, reading,
                     f"{', '.join(map(str, stale))} serve another certificate than the published "
                     "one: a consumer was not reloaded after the renewal")
    if days < fail:
        return Check("expiry", FAIL, reading, f"less than {fail} days left")
    if days < warn:
        return Check("expiry", WARN, reading, f"less than {warn} days left: {late}")
    return passed("expiry", reading)


@check("expiry")
def certificate_expiry(ctx):
    cert = ctx.certificate()
    endpoints = {}
    for port in ENDPOINTS:
        try:
            endpoints[port] = probe.served_certificate(port, cert["cert_name"], ctx.anchor())
        except Unreadable as err:
            endpoints[port] = err
    return judge_expiry(endpoints, published_der(cert["published_cert"]), ctx.now, ctx.settings, cert["mode"])


def judge_renewal(timer_active, shown, journaled=None):
    """The daily renewal's last run, read through systemd.

    ⚠️ systemd forgets a oneshot's last run at every boot, so with no run since the boot
    the last one is `journaled`, the (moment, job result) the journal kept across boots
    (probe.last_start_job). Without it a daily renewal read "never run" for up to a day
    after every reboot (found by a reboot test)."""
    ended = probe.timestamp(shown["ExecMainExitTimestamp"])
    timer = f"timer {'active' if timer_active else 'inactive'}"
    if ended is not None:
        reading = (f"{timer}, last run {ended.isoformat(timespec='seconds')}: {shown['Result']}, "
                   f"status {shown['ExecMainStatus']}")
        failed = shown["Result"] != "success" or shown["ExecMainStatus"] != "0"
    elif journaled is not None:
        moment, result = journaled
        reading = (f"{timer}, last run {moment.isoformat(timespec='seconds')} (read from the "
                   f"journal: none since the boot): {result}")
        failed = result != "done"
    else:
        reading = f"{timer}, last run never: {shown['Result']}, status {shown['ExecMainStatus']}"
        failed = None
    if not timer_active:
        return Check("renewal", FAIL, reading, "the renewal timer is not active: the certificate "
                                               "will expire")
    if failed is None:
        return Check("renewal", UNKNOWN, reading, "the renewal has never run")
    if failed:
        return Check("renewal", FAIL, reading, "the renewal's last run failed: read "
                                               f"`journalctl -u {RENEW_UNIT}`")
    return passed("renewal", reading)


@check("renewal")
def renewal(ctx):
    shown = probe.show(RENEW_UNIT, "Result", "ExecMainStatus", "ExecMainExitTimestamp")
    journaled = None
    if probe.timestamp(shown["ExecMainExitTimestamp"]) is None:
        journaled = probe.last_start_job(RENEW_UNIT)
    return judge_renewal(probe.is_active(RENEW_TIMER), shown, journaled)


TLS = [certificate_mode, certificate_expiry, renewal]


# --- dovecot -------------------------------------------------


class Client(imaplib.IMAP4_SSL):
    """IMAP to the loopback address, verified for the certificate's name."""

    def __init__(self, name, context):
        super().__init__(name, IMAPS, ssl_context=context, timeout=30)

    def _create_socket(self, timeout):
        raw = socket.create_connection((probe.LOCAL, self.port), timeout)
        return self.ssl_context.wrap_socket(raw, server_hostname=self.host)


class NoAnswer(Exception):
    """The service was asked and did not answer: a reading taken, and a FAIL."""


def imap_attempt(name, anchor):
    """(capabilities, the server's answer to a login that cannot exist)."""
    try:
        conn = Client(name, probe.tls_context(anchor))
    except (OSError, ssl.SSLError, imaplib.IMAP4.error) as err:
        raise NoAnswer(f"{probe.LOCAL}:{IMAPS} as {name}: {err}") from None
    try:
        capabilities = list(conn.capabilities)
        try:
            conn.login(PROBE_LOGIN, PROBE_PASSWORD)
            answer = "OK"
        except imaplib.IMAP4.error as err:
            answer = str(err)
    finally:
        try:
            conn.shutdown()
        except OSError:
            pass
    return capabilities, answer


def judge_imap(capabilities, answer):
    reading = f"greeted with {len(capabilities)} capabilities; a login that cannot exist: {answer}"
    if "IMAP4REV1" not in capabilities:
        return Check("imap login", FAIL, reading, "the greeting is not an IMAP server's")
    if "AUTHENTICATIONFAILED" in answer:
        return passed("imap login", reading)
    if answer == "OK":
        return Check("imap login", FAIL, reading, f"a login that cannot exist, {PROBE_LOGIN}, was "
                                                  "accepted")
    return Check("imap login", FAIL, reading, "the passdb did not answer: no login can succeed")


@check("imap login")
def imap_login(ctx):
    name = ctx.certificate()["cert_name"]
    try:
        capabilities, answer = imap_attempt(name, ctx.anchor())
        if "UNAVAILABLE" in answer:
            # ⚠️ measured: after the database restarts, the auth side's first lookup
            # can answer a temporary failure while its pool reconnects; the next is exact
            time.sleep(EX_TEMPFAIL_RETRY)
            capabilities, answer = imap_attempt(name, ctx.anchor())
    except NoAnswer as err:
        return Check("imap login", FAIL, str(err), "Dovecot does not answer on its published port")
    return judge_imap(capabilities, answer)


def block(text, opening):
    """The body of the first `<opening> {` block of `doveconf -n`, nested blocks included."""
    lines = text.splitlines()
    for start, line in enumerate(lines):
        if line.strip() == f"{opening} {{":
            depth, body = 1, []
            for inner in lines[start + 1:]:
                depth += inner.count("{") - inner.count("}")
                if depth <= 0:
                    return "\n".join(body)
                body.append(inner)
    return None


def judge_dovecot_config(text):
    """The effective configuration, not the files."""
    if not re.search(r"^mail_path = ", text, re.MULTILINE):
        # the parse control: this line is always printed for this configuration
        raise Unreadable("doveconf -n printed no mail_path: the configuration was not read")
    problems = []
    imap = block(text, "inet_listener imap")
    if imap is None or not re.search(r"^\s*port = 0$", imap, re.MULTILINE):
        problems.append("plaintext IMAP on 143 is not closed by port = 0")
    if "mail_compress" in text:
        problems.append("a compression plugin is on: a compressed message is not the archive's inode")
    sent = len(re.findall(r'special_use = "\\\\Sent"', text))
    if sent != 1:
        problems.append(f"{sent} folders are \\Sent, not one")
    if re.search(r"^\s*fts_autoindex = yes$", text, re.MULTILINE):
        problems.append("fts_autoindex is on")
    if re.search(r"^\s*substring_search = yes$", text, re.MULTILINE):
        problems.append("substring_search is on")
    reading = "143 closed, no compression, one \\Sent, indexing on search only"
    if problems:
        return Check("configuration", FAIL, "doveconf -n read", "; ".join(problems))
    return passed("configuration", reading)


@check("configuration")
def dovecot_config(ctx):
    return judge_dovecot_config(probe.command(["doveconf", "-n"], check=True).stdout)


def judge_sent_failures(lines, hours):
    """Failed Sent links over the window: one line each, counted.

    ⛔ The control: the window holds Dovecot's own lines at all - this run's own login
    attempt wrote one - so an empty count is a quiet hook and never a window read wrong.
    """
    if not lines:
        raise Unreadable(f"the journal holds no Dovecot line in the last {hours} h, not even this "
                         "run's own login attempt: the window was read wrong")
    failures = sum(1 for line in lines if SENT_FAILURE in line)
    reading = f"{failures} failed in the last {hours} h ({len(lines)} Dovecot lines read)"
    if failures:
        return Check("sent hook", WARN, reading, f"{failures} sent message(s) got no archive name: "
                                                 f"read `journalctl -u dovecot -g '{SENT_FAILURE}'`")
    return passed("sent hook", reading)


@check("sent hook")
def sent_failures(ctx):
    hours = ctx.settings.sent_failure_hours
    return judge_sent_failures(probe.journal(ctx.ago(hours=hours), "--unit=dovecot.service"), hours)


DOVECOT = [imap_login, dovecot_config, sent_failures]


# --- postfix ----------------------------------------------------------------------


def smtp_answer(conn, command=None):
    if command:
        conn.sendall(command.encode() + b"\r\n")
    return probe.lines_of(conn, lambda b: re.search(rb"(^|\r\n)\d{3} [^\r\n]*\r\n$", b) is not None)


@check("submission")
def submission(ctx):
    """465 greets over TLS and offers AUTH (the only way in)."""
    name = ctx.certificate()["cert_name"]
    try:
        with probe.tls_session(SUBMISSIONS, name, ctx.anchor()) as conn:
            greeting = smtp_answer(conn)
            ehlo = smtp_answer(conn, "EHLO maildivvy-health")
            smtp_answer(conn, "QUIT")
    except (OSError, ssl.SSLError) as err:
        return Check("submission", FAIL, f"{probe.LOCAL}:{SUBMISSIONS} as {name}",
                     f"submissions does not answer: {err}")
    reading = f"greeting {greeting[:3]}, EHLO {ehlo[:3]}"
    if not greeting.startswith("220") or not re.search(r"^250[ -]AUTH ", ehlo, re.MULTILINE):
        return Check("submission", FAIL, reading, "submissions did not greet and offer AUTH")
    return passed("submission", reading + ", AUTH offered")


def postconf(*argv):
    return probe.command(["postconf", *argv], check=True).stdout


def judge_transports(default, relay):
    reading = f"default {default or '(empty)'}, relay {relay or '(empty)'}"
    if not default.startswith("error:") or not relay.startswith("error:"):
        return Check("transports", FAIL, reading, "a transport that is not error: sends mail no "
                                                  "per-sender map chose")
    return passed("transports", reading)


@check("transports")
def transports(ctx):
    default, relay = postconf("-h", "default_transport", "relay_transport").splitlines()
    return judge_transports(default.strip(), relay.strip())


def judge_milter_binding(per_service, smtpd, non_smtpd):
    """Bound on submissions, and nowhere globally. `postconf -P`
    is read WITHOUT arguments: naming a service that does not exist prints the same as a
    correctly absent override."""
    bound = [line.split("=", 1)[1].strip() for line in per_service.splitlines()
             if line.startswith("submissions/inet/smtpd_milters =")]
    reading = (f"submissions: {bound[0] if bound else '(none)'}; smtpd_milters "
               f"{smtpd or '(empty)'}; non_smtpd_milters {non_smtpd or '(empty)'}")
    problems = []
    if bound != ["unix:maildivvy/milter.sock"]:
        problems.append("the milter is not bound on submissions")
    if smtpd or non_smtpd:
        problems.append("a global milter binding also stands in front of the pickup path")
    if problems:
        return Check("milter binding", FAIL, reading, "; ".join(problems))
    return passed("milter binding", reading)


@check("milter binding")
def milter_binding(ctx):
    smtpd, non_smtpd = postconf("-h", "smtpd_milters", "non_smtpd_milters").splitlines()
    return judge_milter_binding(postconf("-P"), smtpd.strip(), non_smtpd.strip())


def judge_queue(lines, now, conf):
    arrivals = []
    for line in lines:
        if line.strip():
            arrivals.append(datetime.datetime.fromtimestamp(int(json.loads(line)["arrival_time"]),
                                                            datetime.timezone.utc))
    if not arrivals:
        return passed("queue", "empty")
    minutes = (now - min(arrivals)).total_seconds() / 60
    reading = f"{len(arrivals)} message(s), the oldest {minutes:.0f} min"
    if minutes > conf.queue_fail_minutes:
        return Check("queue", FAIL, reading, f"a message has waited over {conf.queue_fail_minutes} "
                                             "min: read `postqueue -p` and the relay's refusal")
    if minutes > conf.queue_warn_minutes:
        return Check("queue", WARN, reading, f"a message has waited over {conf.queue_warn_minutes} min")
    return passed("queue", reading)


@check("queue")
def queue(ctx):
    # the system helper's: `postqueue` reaches showq through Postfix's `public/`, which is
    # `postdrop`'s, through its set-group-id - and no unit of ours gains a privilege
    return judge_queue(ctx.helper("system", "queue")["lines"], ctx.now, ctx.settings)


POSTFIX = [submission, transports, milter_binding, queue]


# --- milter --------------------------------------------------------


def judge_milter_running(active):
    if not active:
        return Check("running", FAIL, MILTER_UNIT + " inactive",
                     "the milter is not running: every submission is deferred")
    return passed("running", MILTER_UNIT + " active")


def judge_milter_socket(reading):
    """Its socket there, with Postfix's group, or Postfix cannot open it."""
    socket_ = reading["socket"]
    if not socket_.get("exists"):
        return Check("socket", FAIL, f"{reading['path']}: absent",
                     "the milter's socket is not there: every submission is deferred")
    text = f"{reading['path']}: {socket_['kind']}, group {socket_['group']}, mode {socket_['mode']}"
    if socket_["kind"] != "socket" or socket_["group"] != MILTER_GROUP:
        return Check("socket", FAIL, text, f"the socket must be a socket of group {MILTER_GROUP}, "
                                           "or Postfix cannot open it")
    return passed("socket", text)


def judge_milter_answers(reading):
    """A negotiation in the milter's own protocol, not the unit's state."""
    if reading["negotiation"].get("version"):
        return passed("answers", f"negotiated protocol version {reading['negotiation']['version']}")
    return Check("answers", FAIL, "no negotiation",
                 f"the milter did not negotiate: {reading['negotiation'].get('error')}")


def judge_milter(active, reading):
    return [judge_milter_running(active), judge_milter_socket(reading), judge_milter_answers(reading)]


@check("running")
def milter_running(ctx):
    return judge_milter_running(probe.is_active(MILTER_UNIT))


@check("socket")
def milter_socket(ctx):
    return judge_milter_socket(ctx.helper("system", "milter"))


@check("answers")
def milter_answers(ctx):
    return judge_milter_answers(ctx.helper("system", "milter"))


MILTER = [milter_running, milter_socket, milter_answers]


# --- search ------------------------------------------------------------------------


def judge_plugins(plugins, fallback):
    reading = f"mail_plugins: {', '.join(plugins)}; fts_search_read_fallback = {fallback}"
    missing = [name for name in ("fts", "fts_flatcurve") if name not in plugins]
    if missing:
        return Check("index plugin", FAIL, reading, f"not loaded: {', '.join(missing)}")
    if fallback != "no":
        return Check("index plugin", FAIL, reading, "a failed index search falls back to reading "
                                                    "every message")
    return passed("index plugin", reading)


@check("index plugin")
def index_plugin(ctx):
    out = probe.command(["doveconf", "-h", "mail_plugins", "fts_search_read_fallback"],
                        check=True).stdout.splitlines()
    plugins = [line.split("=")[0].strip() for line in out[:-1] if line.strip().endswith("= yes")]
    return judge_plugins(plugins, out[-1].strip() if out else "")


def judge_search(reading):
    """A word a message holds is found, and a part of that word is not: IMAP's own SEARCH
    matches substrings, so a search that read the messages would find it; the index keeps
    whole words only. The word itself is never reported."""
    if not reading.get("domain"):
        return Check("search", UNKNOWN, "no archive holds a message with a word to search for",
                     "nothing to search yet: this reads once mail has arrived")
    text = f"archive of {reading['domain']}, message {reading['uid']}"
    if reading.get("error"):
        return Check("search", FAIL, text, f"the search failed: {reading['error']}")
    if not reading["whole"]:
        return Check("search", FAIL, text, "the index did not find a word the message holds")
    if reading["part"]:
        return Check("search", FAIL, text, "a part of a word was found: the search read the "
                                           "messages instead of the index")
    return passed("search", text + ": a whole word found, a part of it not, so the index answered")


@check("search")
def search(ctx):
    return judge_search(ctx.helper("store", "search"))


SEARCH = [index_plugin, search]


# --- interface ------------------------------------------------------------------


def https_status(name, anchor, path):
    try:
        with probe.tls_session(HTTPS, name, anchor) as conn:
            conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n"
                         "User-Agent: maildivvy-health\r\n\r\n".encode())
            head = probe.lines_of(conn, lambda b: b"\r\n" in b)
    except (OSError, ssl.SSLError) as err:
        raise NoAnswer(f"{probe.LOCAL}:{HTTPS} as {name}: {err}") from None
    match = re.match(r"^HTTP/1\.[01] (\d{3})", head)
    if not match:
        raise Unreadable(f"{path} was answered with no HTTP status line")
    return int(match.group(1))


def judge_interface(page, missing):
    reading = f"/ answered {page}, /maildivvy-health-no-such-page answered {missing}"
    if page == 200 and missing == 404:
        return passed("through the proxy", reading)
    return Check("through the proxy", FAIL, reading,
                 "the application did not answer through the proxy (a 502 is the proxy alone)")


@check("through the proxy")
def interface(ctx):
    name = ctx.certificate()["cert_name"]
    anchor = ctx.anchor()
    try:
        return judge_interface(https_status(name, anchor, "/"),
                               https_status(name, anchor, "/maildivvy-health-no-such-page"))
    except NoAnswer as err:
        return Check("through the proxy", FAIL, str(err), "the proxy does not answer on 443")


INTERFACE = [interface]

WANTS = {"postfix": {"system": ["queue"]}, "milter": {"system": ["milter"]},
         "search": {"store": ["search"]}}
