"""The fifteen subsystems of health, in their order, and running them.

Each subsystem is a list of check functions; each check is run on its own, so one that
cannot read is UNKNOWN beside the others and never stops them, and every
check of a run shares one Context: one database session, one answer from each helper.
"""

from maildivvy.health import data, scanners, services, system
from maildivvy.health.context import Context, run_check
from maildivvy.health.report import Report, Subsystem

SUBSYSTEMS = {
    "host": system.HOST,
    "network": system.NETWORK,
    "ban": system.BAN,
    "tls": services.TLS,
    "dovecot": services.DOVECOT,
    "postfix": services.POSTFIX,
    "milter": services.MILTER,
    "antivirus": scanners.ANTIVIRUS,
    "spam": scanners.SPAM,
    "search": services.SEARCH,
    "collection": data.COLLECTION,
    "store": data.STORE,
    "database": data.DATABASE,
    "interface": services.INTERFACE,
    "backup": data.BACKUP,
}

# {subsystem: {helper: [reading]}}: what each subsystem asks a helper for, so one run asks
# each helper once, for everything the subsystems it runs need.
WANTS = {**system.WANTS, **services.WANTS, **scanners.WANTS, **data.WANTS}


def wants_of(names):
    found = {}
    for name in names:
        for helper, readings in WANTS.get(name, {}).items():
            found.setdefault(helper, set()).update(readings)
    return found


def run(names=None, conf=None, now=None):
    """A report of the subsystems named, or of all fifteen, in their order."""
    names = list(SUBSYSTEMS) if names is None else [n for n in SUBSYSTEMS if n in names]
    ctx = Context(conf=conf, now=now, wants=wants_of(names))
    try:
        subsystems = []
        for name in names:
            checks = []
            for function in SUBSYSTEMS[name]:
                checks.extend(run_check(function, ctx))
            subsystems.append(Subsystem(name, checks))
    finally:
        ctx.close()
    return Report(ctx.now, subsystems)
