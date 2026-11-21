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
CONCURRENT act can still fire between the check and the write - a duplicate, or a row
the write points at removed meanwhile - and answers with the *sentence the check would
have used* rather than an error page. The statement runs
inside a savepoint, so the act's transaction - which carries its journal row - is still
usable afterwards.
"""

import json
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import g, redirect, request, url_for
from markupsafe import Markup, escape

from maildivvy.admin import journal, validate
from maildivvy.fanout import requests as pipeline
# how long the pipeline takes, read off the installed timer; the reading
# lives in maildivvy.lib.timer, which health reads too
from maildivvy.lib.timer import EVERY_MINUTES, EVERY_SECONDS, FETCH_TIMER, timer_period  # noqa: F401

ARCHIVE = "archive"          # every domain's own mailbox, never a person


def moment(value):
    """A moment as every screen prints it: UTC, date and time to the minute, the zone said.

    The one way, as the `moment` filter in a template and called in a sentence built here,
    so no screen prints the database's own spelling or a bare hour of an unsaid day. Every
    column is a `timestamptz`; a moment with no zone is taken as UTC. Anything else is a
    mistake, not a moment, and is refused rather than printed as it is.
    """
    if value is None:
        return ""
    if not isinstance(value, datetime):
        raise TypeError(f"not a moment: {value!r}")
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%d %H:%M UTC")

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
    # collection over IMAP: the protocol, and an IMAP login or host changed, which
    # clears the starting point its collection reads from, whatever the mailbox's state
    "settings_saved_protocol": ("Settings saved, and a check of the stored password over the "
                                "new protocol asked. Its port is under Provider servers: 995 "
                                "for POP3 and 993 for IMAP, unless the provider says "
                                "otherwise."),
    # back from IMAP, which kept every message at the provider, and POP3 has no record of
    # what IMAP collected: its first fetch takes all of it again
    "settings_saved_protocol_pop3": ("Settings saved, and a check of the stored password over "
                                     "POP3 asked. Its port is under Provider servers: 995, "
                                     "unless the provider says otherwise. Once enabled, the "
                                     "first fetch takes every message the provider offers "
                                     "that POP3 has not taken here before, mail already "
                                     "collected over IMAP included, and each reaches every "
                                     "person of the domain a second time."),
    "settings_saved_imap_login": ("Settings saved, and a check of the stored password with "
                                  "the new IMAP login asked."),
    "settings_saved_imap_login_cleared": ("Settings saved, and a check of the stored password "
                                          "with the new IMAP login asked. The new login "
                                          "cleared the starting point in the provider's INBOX: "
                                          "enabling sets a new one where the INBOX then stands, "
                                          "so mail that arrived since the last fetch comes in "
                                          "only through a snapshot."),
    "settings_saved_imap_login_waits": ("Settings saved, and a check of the stored password "
                                        "with the new IMAP login asked. The new login cleared "
                                        "the starting point in the provider's INBOX: nothing "
                                        "is collected until the mailbox is disabled and "
                                        "enabled again."),
    "servers_saved": "Servers saved.",
    "servers_saved_password_cleared": ("Servers saved. The new host or fingerprint cleared the "
                                       "stored provider password; enter it again in Settings, "
                                       "below."),
    "servers_saved_mark_cleared": ("Servers saved. The new host cleared the stored provider "
                                   "password and the starting point in the provider's INBOX: "
                                   "enter the password again in Settings below, then disable "
                                   "and enable the mailbox. Nothing is collected until then."),
    "servers_saved_mark_cleared_disabled": ("Servers saved. The new host cleared the stored "
                                            "provider password and the starting point in the "
                                            "provider's INBOX: enter the password again in "
                                            "Settings below. Enabling sets a new starting "
                                            "point where the INBOX then stands, so mail that "
                                            "arrived since the last fetch comes in only "
                                            "through a snapshot."),
    "servers_same": "Nothing changed: the servers are as they were.",
    "check_asked": "Check asked.",
    "enable_asked": "Enable asked.",
    "disabled": "Disabled.",
    "external_deletion_asked": "External mailbox deletion asked.",
    # the snapshot of an IMAP mailbox's folders
    "snapshot_asked": "Snapshot asked: its own timer takes it in slices.",
    "snapshot_discard_asked": "Discard of the snapshot asked.",
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
    # any act whose request is still waiting
    "already_asked": "Already asked: waiting for the pipeline.",
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
    then refuses - another 500 - and for one past the 4300 digits `int()` reads at all.
    So the check is ASCII digits within the bigint range, read without `int()` past it,
    and anything else is no number at all.
    """
    text = str(value or "").strip()
    if not (text.isascii() and text.isdigit()):
        return None
    number = validate.whole_number(text, BIGINT_MAX)
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
def unique_violation(conn, sentence, gone=None):
    """Run a write; a unique violation from a concurrent submission becomes `sentence`,
    and a foreign-key violation becomes `gone` where the screen gives one.

    Two identical submissions both pass the handler's own duplicate check, because the
    check and the insert are not one statement. The loser's INSERT then waits on the
    unique index and raises when the winner commits. Without this the loser gets an
    error page for a value the screen has a perfectly good sentence for. The same gap
    lets the pipeline delete a row the write names after the screen found it there.
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
        # ⛔ ONLY a unique violation is the duplicate `sentence` describes, and only a
        # foreign key is a row removed meanwhile. Any other integrity error (a check) is
        # neither, and a foreign key the screen gave no sentence for is not known to be
        # a race; each is left to surface as itself.
        pgcode = getattr(err, "pgcode", None)
        if pgcode == "23505":                     # unique_violation
            raise validate.Refused(sentence) from None
        if pgcode == "23503" and gone:            # foreign_key_violation
            raise validate.Refused(gone) from None
        raise
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
    "discard_snapshot": "discard the snapshot",
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

    `waiting` is "asked to <verb>, <moment>"; `look_again` is the time by which to look
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
    when = f", {moment(asked_at)}" if asked_at else ""
    reading["waiting"] = f"asked to {VERBS.get(kind, kind)}{when}"
    if period is not None and asked_at is not None:
        template = LOOK_AGAIN.get(kind, LOOK_AGAIN_DEFAULT)
        reading["look_again"] = template.format(time=moment(asked_at + period))
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


def not_cleared(conn, label, account=None):
    """The refusal of a slot an earlier deletion has not cleared yet, or None.

    `[label, account]` is a mailbox's slot, `[label, None]` a domain's. The deletion's rows
    are gone and its directories are not: a row given that slot now would open
    the deleted mail at the same path. ⛔ The pipeline's own `STILL_LISTED`, never a second
    text, so the screen refuses exactly what the handler would fail.
    """
    found = one(conn, pipeline.STILL_LISTED, {"label": label, "account": account})
    if found is None:
        return None
    what = f"the domain {label}" if account is None else f"{account}@{label}"
    return (f"Request {found['id']}, a deletion, has not finished removing the old directories "
            f"of {what}: given again now, it would hold the deleted mail. The pipeline tries "
            "again on every run and the journal says why it has not; once they are removed, "
            "this can be done.")


# the advisory lock namespace of `ask_once`, beside the last administrator's ('ma') and
# the fetcher's ('mf'); its second key is a hash, so two acts may share one and only wait
ONCE = 0x6D71   # 'mq'


def ask_once(conn, kind, target, payload, identity, same=None):
    """Queue a request unless one of this kind and target is queued or running already;
    return the new id, or None when one was pending.

    `same` names payload keys that must also match for a pending request to count: one
    mailbox may have two messages asked by id at once, but not the same one twice.

    ⛔ THE ROUTE LOOKS, NOT ONLY THE TEMPLATE. A row hides its button
    while its request waits; a double click or a replayed POST still arrives. The lock
    is held until the act commits, so two POSTs at once cannot both find nothing: a
    look-then-insert alone does not hold under read committed, and a unique index would
    make an upgrade fail on a duplicate already queued.
    """
    with conn.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                       (ONCE, f"{kind} {target}"))
        cursor.execute("SELECT id FROM request WHERE kind = %s AND target = %s "
                       "AND state IN ('queued', 'running') AND payload @> %s::jsonb "
                       "LIMIT 1",
                       (kind, target,
                        json.dumps({key: payload[key] for key in same or ()}, default=str)))
        if cursor.fetchone():
            return None
    return ask(conn, kind, target, payload, identity)


def record(conn, action, target, detail=None, request_id=None):
    """One journal row in the act's own transaction, in the signed-in person's name.

    Every screen writes through this one function, so no screen can build an INSERT of
    its own and miss the value filter or the closed list of acts.
    """
    journal.record(conn, actor=g.identity.login, action=action, target=target,
                   detail=detail, break_glass=g.identity.break_glass,
                   request_id=request_id)


# --- the shapes several screens share, in the design's components --------------------
#
# One template of macros, compiled once like every other, which a screen's template imports
# by name: `{%- from "common.SHAPES" import field, refused %}`, then
# `{{ field('Label', 'label', typed.label, warn=refusal if fault == 'label') }}`. Everything
# they are given is escaped unless it is already `Markup` (a `{% set %}` block is), so a
# typed value or a pipeline's reason is text, never markup.
# The refusal, the password never filled back in and the numbers before a
# destructive act's button are described below without their ids: a template's
# own comments are text the program carries.
#
# ⛔ `csrf()` is the session's forgery token (`app.csrf_token`) as a hidden field, and EVERY
# POST form calls it first thing after its opening tag: the setting row below does, and a
# unit test sweeps every template the interface holds for a POST form that does not. With
# no session (the sign-in page) it writes nothing; the sign-in POST is exempt.
SHAPES = """
{%- macro csrf() -%}
{%- set token = csrf_token() -%}
{%- if token %}<input type="hidden" name="_csrf" value="{{ token }}">{% endif -%}
{%- endmacro -%}

{#- the way back, drawn beside "Cancel, nothing changes" and "Back to ..." -#}
{%- macro back() -%}<svg class="icon"><use href="#i-back"/></svg>{%- endmacro -%}

{#- a destructive act's confirmation cancels back to the item it would act on -#}
{%- macro cancel(url) -%}
<p><a href="{{ url }}">{{ back() }} Cancel, nothing changes</a></p>
{%- endmacro -%}

{#- a flash: the `flash` box in its tone (`ok`, `attn`, `bad`, `info`), the named icon of the
    shell's set and the sentence, or nothing at all when there is no sentence -#}
{%- macro flash(tone, icon, sentence) -%}
{%- if sentence %}<div class="flash {{ tone }}"><svg class="icon {{ tone }} ico"><use href="#i-{{ icon }}"/>\
</svg><div>{{ sentence }}</div></div>{% endif -%}
{%- endmacro -%}

{#- a refusal: the red flash with the alert, or nothing when there is none -#}
{%- macro refused(sentence) -%}{{ flash('bad', 'alert', sentence) }}{%- endmacro -%}

{#- the worded red line beneath a row whose newest request failed, or nothing -#}
{%- macro pipeline_failed(reason) -%}
{%- if reason %}<span class="row-sub state-bad"><svg class="icon bad"><use href="#i-x"/>\
</svg> the pipeline could not do it: {{ reason }}</span>{% endif -%}
{%- endmacro -%}

{#- a page's own row as `queue_reading` read it: an amber flash while the pipeline owes it
    something, the refusal when it failed, or nothing -#}
{%- macro pipeline_flash(reading) -%}
{%- if reading.waiting %}{{ flash('attn', 'clock', reading.waiting ~ '. ' ~ reading.look_again ~ '.') }}
{%- elif reading.failed %}{{ refused('the pipeline could not do it: ' ~ reading.failed) }}
{%- endif -%}
{%- endmacro -%}

{#- a labelled input, its help line, and the refusal beside it in `help warn`; any other
    keyword is an attribute of the input (`attributes`). ⛔ A password field is never filled
    back in: its value is dropped here, whatever the screen hands over. -#}
{%- macro field(label, name, value=none, type='text', help=none, warn=none) -%}
<div class="field"><label for="{{ name }}">{{ label }}</label>\
<input id="{{ name }}" name="{{ name }}" type="{{ type }}"
{{- {'value': none if type == 'password' or value == '' else value}|attributes }}
{{- kwargs|attributes }}>
{%- if help %}<p class="help">{{ help }}</p>{% endif %}
{%- if warn %}<p class="help warn">{{ warn }}</p>{% endif -%}
</div>
{%- endmacro -%}

{#- one `zone-row` of a danger zone: the act's sentence, its detail (or none) and its control -#}
{%- macro zone_row(sentence, about, control) -%}
<div class="zone-row"><div><b>{{ sentence }}</b>
{%- if about %}<p class="muted">{{ about }}</p>{% endif -%}
</div>{{ control }}</div>
{%- endmacro -%}

{#- the red frame, its head and the `zone-row` of its act: the sentence, its detail (or none)
    and the control; `before` is the rows of lesser acts drawn above it (`zone_row`'s), or
    none -#}
{%- macro danger_zone(sentence, about, control, before=none) -%}
<section class="danger-zone"><div class="box-head"><h2>Danger zone</h2></div>\
{%- if before %}{{ before }}{% endif -%}
{{ zone_row(sentence, about, control) }}</section>
{%- endmacro -%}

{#- what a destructive act removes, as numbers before its button: `numbers` is
    (count, what) pairs, `before` a sentence above them, the call's own body the sentences
    beneath, and the one solid red button that performs it -#}
{%- macro what_goes(numbers, action, button, before=none) -%}
<section class="danger-zone">
<div class="box-head"><h2>What goes</h2></div>
<div class="box-body">
{% if before %}{{ before }}
{% endif %}<div class="kv">
{%- for count, what in numbers %}<div><b>{{ count }}</b><span>{{ what }}</span></div>{% endfor -%}
</div>
{{ caller() }}
<form class="form-foot" method="post" action="{{ action }}">{{ csrf() }}\
<button class="btn btn-danger-solid" type="submit">{{ button }}</button></form>
</div>
</section>
{%- endmacro -%}

{#- one `form.setting` row: its title and description left, its fields and its own button
    right. The design keeps the primary for the row that sets a password. With no button
    (none) the row is a plain `div.setting`: something to read, nothing to send. -#}
{%- macro setting(action, title, about, fields, button, primary=false) -%}
{%- set about_line %}{% if about %}<p class="about">{{ about }}</p>{% endif %}{% endset -%}
{%- if button is none -%}
<div class="setting"><div><h2 class="st">{{ title }}</h2>{{ about_line }}</div><div>{{ fields }}</div></div>
{%- else -%}
<form class="setting" method="post" action="{{ action }}">{{ csrf() }}\
<div><h2 class="st">{{ title }}</h2>{{ about_line }}</div>\
<div>{{ fields }}<div class="form-foot"><button class="{{ 'btn btn-primary' if primary else 'btn' }}" \
type="submit">{{ button }}</button></div></div></form>
{%- endif -%}
{%- endmacro -%}
"""


def attributes(values):
    """HTML attributes from keywords, the `attributes` filter: `class_` is `class`,
    `aria_label` is `aria-label`; a true value is written bare, a false or missing one not
    at all."""
    written = []
    for name, value in values.items():
        name = name.rstrip("_").replace("_", "-")
        if value is None or value is False:
            continue
        written.append(f" {name}" if value is True else f' {name}="{escape(value)}"')
    return Markup("".join(written))
