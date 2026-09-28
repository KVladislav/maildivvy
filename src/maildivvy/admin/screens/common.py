"""What every screen shares: the closed list of sentences, refusals, and small readers.

**A successful act redirects and says what it did in one sentence from a closed list**.
The key travels as `?done=<key>` and nowhere else, so the application holds
no state between the act and the page that reports it; an unknown key renders nothing at
all, rather than the key itself.

**A refused form is the same form at 400**, with the typed values back in place, the
refusal above it and the sentence beside the field at fault. A password field
is never filled back in - not a person's, not an archive's, not a provider's.

**A value the database would reject is refused here first**. Two
things are needed for that, and only one of them is the check: the check itself, which a
screen runs before it writes; and `unique_violation`, which catches the constraint a
CONCURRENT submission can still fire between the check and the write, and answers with
the *same sentence the check would have used* rather than an error page.
The statement runs inside a savepoint, so the act's
transaction - which carries its journal row - is still usable afterwards.
"""

import json
from contextlib import contextmanager

from flask import g, redirect, request, url_for

from maildivvy.admin import journal, validate
# how long the pipeline takes, read off the installed timer; the reading
# lives in maildivvy.lib.timer, which health reads too
from maildivvy.lib.timer import EVERY_MINUTES, EVERY_SECONDS, FETCH_TIMER, timer_period  # noqa: F401

ARCHIVE = "archive"          # every domain's own mailbox, never a person

# ⚠️ THE CLOSED LIST. A key that is not here renders nothing, so a screen
# cannot report an act by inventing a sentence, and a sentence cannot be built from
# anything a person typed.
DONE = {
    # domains
    "domain_created": "Domain created.",
    "archive_password_set": "Archive password replaced.",
    "spam_saved": "Spam policy saved.",
    "spam_same": "Nothing changed: the spam policy is as it was.",
    "outbound_saved": "Outgoing mail setting saved.",
    "outbound_same": "Nothing changed: the setting is as it was.",
    "domain_deletion_asked": "Domain deletion asked.",
    # external mailboxes
    "external_saved": "External mailbox saved, disabled.",
    "settings_saved": "Settings saved.",
    "settings_saved_login": ("Settings saved, and a check of the stored password with "
                             "the new POP3 login asked."),
    "settings_saved_password": "Settings saved, and a check of the new password asked.",
    "servers_saved": "Servers saved.",
    "servers_saved_password_cleared": ("Servers saved. Changing the host cleared the stored "
                                       "provider password; enter it again in Settings, below."),
    "servers_same": "Nothing changed: the servers are as they were.",
    "check_asked": "Check asked.",
    "enable_asked": "Enable asked.",
    "disabled": "Disabled.",
    "external_deletion_asked": "External mailbox deletion asked.",
    # fetch
    "fetch_resumed": "Fetch resumed.",
    "refetch_asked": "Refetch asked.",
    # people
    "account_created": "Person created.",
    "password_set": "Password set.",
    "admin_saved": "Administrator flag saved.",
    "admin_same": "Nothing changed: the administrator flag is as it was.",
    "state_set": "State set.",
    "comment_saved": "Comment saved.",
    "account_deletion_asked": "Person deletion asked.",
    # mailboxes
    "mailbox_given": "Mailbox given.",
    "transfer_asked": "Transfer asked.",
    "mailbox_removal_asked": "Removal asked.",
    # moderation and maintenance
    "release_asked": "Release asked.",
    "top_up_asked": "Top-up asked.",
    "one_message_asked": "One message asked.",
}


def done_sentence(key):
    """The sentence for a `?done=` key, or None. An unknown key is not shown at all."""
    return DONE.get(key) if isinstance(key, str) else None


def acted(endpoint, key, **values):
    """303 back to the screen the act came from, with the sentence's key."""
    return redirect(url_for(endpoint, done=key, **values), code=303)


def origin(default_endpoint, **values):
    """Where an act returns to: the screen it was submitted from, else its section's list.

    ⚠️ Only the Referer's PATH is used, never its query, so a `done` key from the
    previous act cannot ride along onto the next screen.
    """
    from maildivvy.admin import app

    referer = request.headers.get("Referer") or ""
    path = referer.split("?", 1)[0].split("#", 1)[0]
    if path.startswith("http://") or path.startswith("https://"):
        rest = path.split("://", 1)[1]
        path = "/" + rest.partition("/")[2]
    return app.safe_path(path) or url_for(default_endpoint, **values)


def acted_at(path, key):
    """303 to a path already decided, carrying the sentence's key."""
    return redirect(f"{path}?done={key}", code=303)


# --- reading -------------------------------------------------------------------------------

def rows(conn, sql, parameters=()):
    """Every row of a query, as dictionaries keyed by column name."""
    with conn.cursor() as cursor:
        cursor.execute(sql, parameters)
        names = [column[0] for column in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]


def one(conn, sql, parameters=()):
    """The first row of a query as a dictionary, or None."""
    found = rows(conn, sql, parameters)
    return found[0] if found else None


BIGINT_MAX = 2 ** 63 - 1        # a row id never exceeds this


def as_int(value):
    """A whole number a form field spells, or None.

    ⛔ `str.isdigit()` is TRUE for `'²'` and other non-ASCII digits, which `int()` then
    refuses - a 500. It is also true for a number far past a bigint, which the database
    then refuses - another 500. So the check is ASCII digits within the bigint range, and
    anything else is no number at all.
    """
    text = str(value or "").strip()
    if not (text.isascii() and text.isdigit()):
        return None
    number = int(text)
    return number if number <= BIGINT_MAX else None


def want_int(value, what):
    """A whole number from a form, or Refused: a non-numeric id is a sentence, not a 500."""
    number = as_int(value)
    if number is None:
        raise validate.Refused(f"The {what} must be a number.")
    return number


def checked(form, name):
    """A checkbox: absent means off, because an unchecked box sends nothing at all."""
    return form.get(name) is not None


# --- the constraint a concurrent submission can still fire ----------------

@contextmanager
def unique_violation(conn, sentence):
    """Run a write; a unique violation from a concurrent submission becomes `sentence`.

    Two identical submissions both pass the handler's own duplicate check, because the
    check and the insert are not one statement. The loser's INSERT then waits on the
    unique index and raises when the winner commits. Without this the loser gets an
    error page for a value the screen has a perfectly good sentence for.
    """
    # ⚠️ imported here, as `lib/db.py` imports it: the driver is the machine's, and the
    # unit suite runs on the controller where it is not installed
    import psycopg2

    with conn.cursor() as cursor:
        cursor.execute("SAVEPOINT before_write")
    try:
        yield
    except psycopg2.IntegrityError as err:
        with conn.cursor() as cursor:
            cursor.execute("ROLLBACK TO SAVEPOINT before_write")
        # ⛔ ONLY a unique violation is the duplicate this sentence describes.
        # A different integrity error (a check, a foreign key) is not a duplicate; giving
        # it the duplicate sentence would mislead, so it is left to surface as itself.
        if getattr(err, "pgcode", None) != "23505":   # 23505 = unique_violation
            raise
        raise validate.Refused(sentence) from None
    with conn.cursor() as cursor:
        cursor.execute("RELEASE SAVEPOINT before_write")



def spell(period):
    """A period as the screen says it: "3 minutes", "1 minute", "45 seconds"."""
    if period is None:
        return None
    seconds = int(period.total_seconds())
    if seconds % 3600 == 0:
        return f"{seconds // 3600} hour" + ("s" if seconds != 3600 else "")
    if seconds % 60 == 0:
        return f"{seconds // 60} minute" + ("s" if seconds != 60 else "")
    return f"{seconds} second" + ("s" if seconds != 1 else "")


# --- what a row reads while the pipeline owes it something ------------------

# The verb a waiting row is named by. A kind nobody spelt here is named as itself rather
# than dropped, because a row saying nothing is how an act nobody performed looks healthy.
VERBS = {
    "create_domain": "create",
    "create_mailbox": "connect",
    "connect": "connect",
    "transfer": "transfer",
    "delete_mailbox": "delete",
    "delete_account": "delete",
    "delete_domain": "delete",
    "delete_external_mailbox": "delete",
    "top_up": "top up",
    "deliver_one": "deliver one message",
    "release": "release",
    "refetch": "refetch",
    "test_credential": "check the password",
    "activate_external_mailbox": "enable",
}

# Enabling says what the pipeline does first, because the provider decides it, not us.
# Everything else says the one conservative thing that is true of every
# kind: the pipeline drains the queue at the end of its run.
LOOK_AGAIN = {
    "activate_external_mailbox": "the pipeline checks the password and enables it by {time}",
}
LOOK_AGAIN_DEFAULT = "the pipeline runs by {time}"
NO_PERIOD = "the pipeline's own period could not be read from the machine"
NO_REASON = "the pipeline gave no reason"
WAITING = "waiting for the pipeline"

# The states a request is in while it still owes the row something.
PENDING = ("queued", "running")


def queue_reading(kind, state, asked_at, result, period=None):
    """The newest request for a row, read as the three things a screen may say.

    `waiting` is "asked to <verb>, HH:MM"; `look_again` is the time by which to look
    again, taken from the real timer period and never from a constant; `failed` is the
    pipeline's own reason, shown for EVERY kind and escaped
    where it is rendered, because it is `str(exc)` and not ours.
    """
    reading = {"waiting": None, "look_again": None, "failed": None}
    if not kind:
        return reading
    if state == "failed":
        return {**reading, "failed": result or NO_REASON}
    if state not in PENDING:
        return reading
    when = f", {asked_at:%H:%M}" if asked_at else ""
    reading["waiting"] = f"asked to {VERBS.get(kind, kind)}{when}"
    if period is not None and asked_at is not None:
        template = LOOK_AGAIN.get(kind, LOOK_AGAIN_DEFAULT)
        reading["look_again"] = template.format(time=f"{asked_at + period:%H:%M}")
    else:
        reading["look_again"] = NO_PERIOD
    return reading


def newest_request(where):
    """The four columns `queue_reading` reads, as scalar sub-selects on a row's query.

    `where` names the request rows that belong to the row being listed, in terms of the
    outer query's own columns and no bound parameter of its own; it is written once per
    screen, so the four sub-selects cannot disagree about which request is the newest.
    """
    columns = []
    for column in ("kind", "state", "created_at", "result"):
        columns.append(f"(SELECT r.{column} FROM request r WHERE {where} "
                       f"ORDER BY r.id DESC LIMIT 1) AS newest_{column}")
    return ",\n       ".join(columns)


def reading_of(row, period=None):
    """`queue_reading` for a row carrying the four `newest_*` columns."""
    return queue_reading(row["newest_kind"], row["newest_state"], row["newest_created_at"],
                         row["newest_result"], period)


# --- the queue the interface writes -----------------------------------------

def ask(conn, kind, target, payload, identity):
    """Queue one request for the pipeline and return its id.

    Who asked and whether the session is the break-glass one are COLUMNS, never payload,
    so the journal row the pipeline writes names the administrator.
    """
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO request (kind, target, payload, asked_by, break_glass) "
            "VALUES (%s, %s, %s::jsonb, %s, %s) RETURNING id",
            (kind, target, json.dumps(payload, default=str), identity.login,
             identity.break_glass))
        return cursor.fetchone()[0]


def record(conn, action, target, detail=None, request_id=None):
    """One journal row in the act's own transaction, in the signed-in person's name.

    Every screen writes through this one function, so no screen can build an INSERT of
    its own and miss the value filter or the closed list of acts.
    """
    journal.record(conn, actor=g.identity.login, action=action, target=target,
                   detail=detail, break_glass=g.identity.break_glass,
                   request_id=request_id)
