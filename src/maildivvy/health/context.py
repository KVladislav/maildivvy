"""What one run of the checks shares: the time, the bounds, the database, and the helpers'
readings - each taken once, so every check of a run reads the same moment.

A reading that cannot be taken raises `Unreadable` in every check that asks for it, and
each of those checks becomes UNKNOWN; the others go on.
"""

import datetime

from maildivvy.health import helper, probe, settings as settings_module
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import PASS, UNKNOWN, Check


def check(name):
    """Names a check function: the name its UNKNOWN carries when it raises."""
    def mark(function):
        function.check_name = name
        return function
    return mark


class Context:
    def __init__(self, conf=None, now=None, wants=None):
        self.settings = conf or settings_module.Settings()
        self.now = now or datetime.datetime.now(datetime.timezone.utc)
        self.wants = wants or {}   # {helper: [reading, ...]} for the subsystems that run
        self._db = None
        self._helpers = {}

    # --- the database, as maildivvy_health: read, and nothing else ---------------------

    def query(self, sql, params=()):
        if self._db is None:
            try:
                from maildivvy.lib import db
                conn = db.connect("health")
                conn.set_session(readonly=True, autocommit=True)
            except Exception as err:  # the driver's own errors, and ConfigError
                self._db = err
            else:
                self._db = conn
        if isinstance(self._db, Exception):
            raise Unreadable(f"the database as maildivvy_health: {one_line(self._db)}")
        try:
            with self._db.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        except Exception as err:
            raise Unreadable(f"the database as maildivvy_health: {one_line(err)}") from None

    def close(self):
        if self._db is not None and not isinstance(self._db, Exception):
            self._db.close()

    # --- the helpers: one connection each per run --------------------------------------

    def helper(self, name, reading):
        """One reading of a helper (`store` or `system`), all of this run's taken at once."""
        if name not in self._helpers:
            wanted = sorted(set(self.wants.get(name, ())) | {reading})
            try:
                self._helpers[name] = helper.ask(name, wanted)
            except Unreadable as err:
                self._helpers[name] = err
        answer = self._helpers[name]
        if isinstance(answer, Unreadable):
            raise answer
        if reading not in answer:
            # a reading this run did not ask for at first: asked for on its own
            try:
                answer.update(helper.ask(name, [reading]))
            except Unreadable as err:
                raise err from None
        found = answer[reading]
        if isinstance(found, dict) and "error" in found:
            raise Unreadable(f"the {name} helper could not read {reading}: {found['error']}")
        return found

    # --- files other steps write for health to read --------------------------------------

    def certificate(self):
        found = probe.load_json(settings_module.CERTIFICATE)
        if not isinstance(found, dict) or not found.get("cert_name") or not found.get("mode"):
            raise Unreadable(f"{settings_module.CERTIFICATE} names no certificate and mode")
        return found

    def anchor(self):
        """The trust anchor endpoints are verified with: the system store in `acme` mode,
        the published certificate itself otherwise (it is self-signed, the staging CA's, or
        the operator's own, whose CA may be a private one)."""
        cert = self.certificate()
        return None if cert["mode"] == "acme" else cert["published_cert"]

    def ago(self, **delta):
        return self.now - datetime.timedelta(**delta)


def one_line(err):
    return " ".join(str(err).split())[:300] or type(err).__name__


def run_check(function, ctx):
    """A check's own result, or UNKNOWN naming why it could not be read."""
    name = getattr(function, "check_name", function.__name__)
    try:
        found = function(ctx)
    except Unreadable as err:
        return [Check(name, UNKNOWN, "not read", one_line(err))]
    except Exception as err:  # a check that breaks is a reading not taken, never a pass
        return [Check(name, UNKNOWN, "not read",
                      f"the check itself failed: {type(err).__name__}: {one_line(err)}")]
    if isinstance(found, Check):
        return [found]
    return list(found)


def passed(name, reading):
    return Check(name, PASS, reading)
