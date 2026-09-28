"""The journal: who did what, when, and to whom.

Every row is written by `record`, and by nothing else, so no screen can build its own
INSERT and miss the value filter. The act's name comes from a closed,
declared list. The row is written on the connection the act itself uses
and inside the act's transaction, so the two commit together or not at all;
a write that fails takes the act down with
it rather than leaving a change nobody can account for.

The table is append-only for every role (a trigger) and the interface's
role holds no UPDATE or DELETE on it.

`request_id` names the request an act asked for, so the journal screen can show
whether the pipeline performed it and why not.

**The secret filter judges each value by its shape, never by its key**. Refusing a key because its name contains "credential" is what broke
the first real password change in the predecessor: `{"credential_set": true}` was withheld.
The filter is a second line only - the real guarantee is that the interface's role
cannot read the credential at all.
"""

import json
from datetime import date

from maildivvy.admin import validate

# ⚠️ THE NAMES ARE THIS PRODUCT'S, NOT THE SOURCE'S. Every act that touches the mail
# store is a request the pipeline performs, and the pipeline writes the
# row when it performs it, in the administrator's name and against the request
# (`fanout/requests.py`). So an act's name here is its REQUEST KIND, and the
# source's `release_message`, `run_top_up`, `run_refetch`, `deliver_one_message`,
# `transfer_mailbox` and `delete_real_mailbox` are `release`, `top_up`,
# `refetch`, `deliver_one`, `transfer` and `delete_external_mailbox` here. A unit test
# holds this list to what the three writers actually write.

# Written by the interface itself: the rows it changes with no disk work behind them.
INTERFACE_ACTS = (
    "map_domain", "set_archive_password", "set_spam_policy", "set_outbound_unscanned",
    "create_account", "set_password", "set_account_state", "grant_admin", "revoke_admin",
    "add_external_mailbox", "deactivate_external_mailbox", "set_credential",
    "set_provider_servers", "set_pop3_login", "set_delete_window", "resume_fetch",
    "break_glass_use",
)
# Written by the pipeline, in the name of the administrator who asked for it.
# These are exactly the request kinds of `schema/0001_initial.sql`.
PIPELINE_ACTS = (
    "create_domain", "create_mailbox", "connect", "top_up", "deliver_one", "release",
    "delete_account", "delete_mailbox", "delete_external_mailbox", "delete_domain",
    "transfer", "refetch", "test_credential", "activate_external_mailbox",
)
# Written by the fetch runner, whose actor is the fetcher itself.
FETCHER_ACTS = ("auto_skip_message", "fetch_frozen")
DECLARED = frozenset(INTERFACE_ACTS + PIPELINE_ACTS + FETCHER_ACTS)

WITHHELD = "<withheld>"
LONG = 200            # a string longer than this is withheld whatever its shape
SHAPED = 12           # a string at least this long, with no space and no `@`, may be one
CLASSES = 3           # ... when it mixes at least this many character classes
LIMIT = 500           # at most this many rows are read

INSERT = ("INSERT INTO audit (actor, action, target, detail, break_glass, request_id) "
          "VALUES (%s, %s, %s, %s::jsonb, %s, %s)")

# One row per act, newest first, with the outcome of the request it asked for joined to
# it. Every filter is a bound parameter, and a filter left out is a COALESCE onto the
# column itself rather than SQL built by hand.
SELECT = """
SELECT a.id, a.at, a.actor, a.action, a.target, a.detail, a.break_glass, a.request_id,
       r.state AS request_state, r.result AS request_result
  FROM audit a
  LEFT JOIN request r ON r.id = a.request_id
 WHERE a.actor = COALESCE(%s, a.actor)
   AND a.action = COALESCE(%s, a.action)
   AND a.target IS NOT DISTINCT FROM COALESCE(%s, a.target)
   AND a.at >= COALESCE(%s::date, '-infinity')
   AND a.at < COALESCE(%s::date + interval '1 day', 'infinity')
 ORDER BY a.at DESC, a.id DESC
 LIMIT %s
"""


class UndeclaredAct(Exception):
    """An act name no list declares. It is refused where it is written, never stored."""


def classes_of(text):
    kinds = set()
    for character in text:
        if character.islower():
            kinds.add("lower")
        elif character.isupper():
            kinds.add("upper")
        elif character.isdigit():
            kinds.add("digit")
        else:
            kinds.add("other")
    return kinds


def is_secret_shaped(text):
    if len(text) > LONG:
        return True
    if len(text) < SHAPED or " " in text or "@" in text:
        return False
    if validate.is_host(text):
        return False     # the host field's own rule, so the two cannot drift
    return len(classes_of(text)) >= CLASSES


def filtered(value):
    """`value` with every password-shaped string replaced, reaching into lists and objects."""
    if isinstance(value, str):
        return WITHHELD if is_secret_shaped(value) else value
    if isinstance(value, dict):
        return {key: filtered(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [filtered(item) for item in value]
    return value          # booleans, numbers and null always pass


def detail_text(detail):
    """The detail as the JSON text it is written and shown as."""
    return json.dumps(detail if detail is not None else {}, sort_keys=True, default=str)


def record(conn, actor, action, target=None, detail=None, break_glass=False, request_id=None):
    """Write one journal row on `conn`, inside whatever transaction the act is using."""
    if action not in DECLARED:
        raise UndeclaredAct(
            f"{action!r} is not a declared act; declare it in journal.INTERFACE_ACTS "
            "before any screen writes it")
    with conn.cursor() as cursor:
        cursor.execute(INSERT, (actor, action, target, detail_text(filtered(detail)),
                                break_glass, request_id))


def date_filter(text):
    """A YYYY-MM-DD date, or None for an empty filter; anything else is Refused.

    A date the screen dropped silently would answer with rows outside the range that was
    asked for, which reads as "those events are not in the journal".
    """
    if text is None or not str(text).strip():
        return None
    try:
        return date.fromisoformat(str(text).strip())
    except ValueError:
        raise validate.Refused("A date is written YYYY-MM-DD.") from None


def rows(conn, who=None, action=None, target=None, since=None, until=None, limit=LIMIT):
    """The journal, newest first, filtered by bound parameters alone."""
    with conn.cursor() as cursor:
        cursor.execute(SELECT, (who or None, action or None, target or None,
                                since or None, until or None, limit))
        names = [column[0] for column in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]
