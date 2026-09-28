"""Maintenance: the top-up over a range, and one message by id. No screen of its own.

Both acts hang off a mailbox, so neither is reached by typing a path. Refetch
hangs off a fetch-screen row and the archive listing off a domain; those live with their
own screens.

⛔ **THE NUMBER THE SCREEN STATES IS COUNTED BY THE PIPELINE'S OWN SELECTOR**, imported
from `fanout/requests.py` rather than written a second time.
Measured on the predecessor: with the range's end bound left to each caller, the
screen counted to the last second of the day and the request delivered to midnight, so
every single-day range stated a number and delivered nothing. One text, one bound, both
readings.

⛔ **AN EMPTY DATE IS REFUSED, NEVER WIDENED**. In the predecessor an empty From or To silently became the wide end, so a
range with blank fields quietly became most of the archive without the warning that "all
of it" carries. "All of it" is still a wide EXPLICIT pair, so its size is knowable before
it runs.

⛔ **DELIVERING BY ID REFUSES AN ID OUTSIDE THE MAILBOX'S DOMAIN**. The source journaled and queued any number typed, and only the pipeline could fail
it. Here the row is read first, and a message of another domain never becomes a request.
"""

from datetime import date

from flask import g, request

from maildivvy.admin import app, validate
from maildivvy.admin.screens import common, mailboxes
from maildivvy.fanout import requests as pipeline

record = common.record

# "All of it" is a wide pair and never an absent one: both ends are plain
# calendar days, so what it will deliver has a number before it runs.
WIDE_SINCE = "0001-01-01"
WIDE_UNTIL = pipeline.WIDE_UNTIL

NOT_A_NUMBER = "A message id is a number; the archive listing shows them."
WRONG_DOMAIN = ("Message {message_id} is not a message of {label}, which is the domain "
                "this mailbox is in. The archive listing shows the ids of this domain's "
                "messages.")
NO_MESSAGE = ("There is no message {message_id}. The archive listing shows the ids of "
              "this domain's messages.")
# A release is the only way a withheld message reaches anybody
WITHHELD = ("Message {message_id} is withheld. Only a release gives a withheld message to "
            "anybody, and a release gives it to everybody who receives in the domain.")
FOLLOWS = "The count follows a valid range."

PAGE = """
<p class="crumbs"><a href="{{ url_for('mailboxes') }}">Mailboxes</a> /
  <a href="{{ url_for('mailbox', mailbox_id=box.id) }}"><code>{{ box.address }}</code></a>
  / Top up</p>
<h1>Top up <code>{{ box.address }}</code></h1>
<p>A top-up delivers what never arrived in this mailbox. It does not put back what the
person deleted on purpose; <a href="{{ url_for('mailbox', mailbox_id=box.id) }}">deliver
one message by id</a> does that.</p>
{%- if refusal and not field %}<p class="refusal">{{ refusal }}</p>{% endif %}

<h2>Recount a range</h2>
<form method="get" action="{{ url_for('top_up', mailbox_id=box.id) }}">
  <label for="since">From</label>
  <input id="since" name="since" value="{{ typed.since }}">
  {%- if field == 'since' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <label for="until">To</label>
  <input id="until" name="until" value="{{ typed.until }}">
  {%- if field == 'until' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <p><button type="submit">Recount</button>
  {%- if ranged is none %} <span class="field-refusal">{{ follows }}</span>{% endif %}</p>
</form>

<h2>Run it</h2>
<form method="post" action="{{ url_for('top_up', mailbox_id=box.id) }}">
  <label><input type="radio" name="choice" value="range"
    {{ 'checked' if typed.choice != 'all' }}> Between two dates</label>
  <p>{% if ranged is none %}{{ follows }}{% else %}<span class="would-deliver">{{ ranged }} message(s) would be delivered</span>,
  from {{ typed.since }} to {{ typed.until }} inclusive &mdash; both ends are whole
  calendar days, so a range of one day is that day entire.{% endif %}</p>
  <input type="hidden" name="since" value="{{ typed.since }}">
  <input type="hidden" name="until" value="{{ typed.until }}">
  <label><input type="radio" name="choice" value="all"
    {{ 'checked' if typed.choice == 'all' }}> All of it</label>
  <p><span class="would-deliver">{{ everything }} message(s) would be delivered</span> to
  <code>{{ box.address }}</code>. Each one becomes a header entry in this person's mail
  client cache, which has a ceiling of its own.</p>
  <p><button type="submit">Top up</button>
     <a href="{{ url_for('mailbox', mailbox_id=box.id) }}">Cancel, nothing changes</a></p>
</form>
<p>The count is the same selection the pipeline delivers: messages of
<code>{{ box.label }}</code> that are in the archive, that this mailbox has not been
given, and &mdash; unless the domain lets spam reach people &mdash; that are not spam.</p>
"""


# --- the two counts ----------------------------------------------------------

def default_range(today=None):
    """From the first of the previous month, to today: the range the form opens with."""
    today = today or date.today()
    first = today.replace(day=1)
    previous = (first.replace(year=first.year - 1, month=12) if first.month == 1
                else first.replace(month=first.month - 1))
    return previous.isoformat(), today.isoformat()


def count(conn, box, since, until):
    """How many a top-up over this range would deliver, by the pipeline's own count."""
    with conn.cursor() as cursor:
        return pipeline.count_for(cursor, box["id"], box["domain_id"], since, until)


def typed_range(values):
    """The two dates as typed, or (field at fault, sentence). Empty is refused."""
    for name, what in (("since", "From date"), ("until", "To date")):
        try:
            validate.calendar_date(values.get(name), what)
        except validate.Refused as refused:
            return name, str(refused)
    return None, None


# --- the screens -----------------------------------------------------------------------------------

def register(app_):
    @app_.route("/mailboxes/<int:mailbox_id>/top-up", methods=["GET", "POST"])
    def top_up(mailbox_id):
        """both counts before the choice, then the chosen range."""
        conn = app.connection()
        box = mailboxes.needed(conn, mailbox_id, common.timer_period())
        values = request.form if request.method == "POST" else request.args
        since, until = default_range()
        typed = {"since": values.get("since", since) or "",
                 "until": values.get("until", until) or "",
                 "choice": values.get("choice", "range")}
        field, refusal = typed_range(typed)

        if request.method == "GET":
            return page(conn, box, typed, field, refusal)
        if typed["choice"] == "all":
            # ⚠️ a wide EXPLICIT pair: the person was shown its number on this page
            asked_since, asked_until = WIDE_SINCE, WIDE_UNTIL
        elif refusal:
            return page(conn, box, typed, field, refusal)
        else:
            asked_since, asked_until = typed["since"], typed["until"]

        asked = common.ask(conn, "top_up", box["address"],
                           {"mailbox_id": mailbox_id, "since": asked_since,
                            "until": asked_until}, g.identity)
        record(conn, "top_up", box["address"],
               {"since": asked_since, "until": asked_until}, request_id=asked)
        return common.acted("mailbox", "top_up_asked", mailbox_id=mailbox_id)

    @app_.post("/mailboxes/<int:mailbox_id>/deliver-one")
    def deliver_one_message(mailbox_id):
        """one message to one person, the one targeted undelete."""
        conn = app.connection()
        box = mailboxes.needed(conn, mailbox_id, common.timer_period())
        typed = {"message_id": request.form.get("message_id", "")}
        message_id = common.as_int(typed["message_id"])
        if message_id is None:
            return card(conn, box, NOT_A_NUMBER, typed)
        found = common.one(conn, "SELECT id, domain_id, state FROM message WHERE id = %s",
                           (message_id,))
        if found is None:
            return card(conn, box, NO_MESSAGE.format(message_id=message_id), typed)
        if found["domain_id"] != box["domain_id"]:
            # ⛔ the predecessor queued any number typed, so a wrong id became a journal row
            # and a failed request rather than a sentence
            return card(conn, box, WRONG_DOMAIN.format(message_id=message_id,
                                                       label=box["label"]), typed)
        if found["state"] == "withheld":
            return card(conn, box, WITHHELD.format(message_id=message_id), typed)
        asked = common.ask(conn, "deliver_one", box["address"],
                           {"mailbox_id": mailbox_id, "message_id": message_id},
                           g.identity)
        record(conn, "deliver_one", box["address"], {"message": message_id},
               request_id=asked)
        return common.acted("mailbox", "one_message_asked", mailbox_id=mailbox_id)


def card(conn, box, refusal, typed):
    return mailboxes.card(conn, box, 400, "deliver", refusal, typed)


def page(conn, box, typed, field=None, refusal=None):
    ranged = (None if refusal else count(conn, box, typed["since"], typed["until"]))
    return app.render(f"Top up {box['address']}", PAGE, section="mailboxes",
                      status=400 if refusal else 200, box=box, typed=typed,
                      field=field, refusal=refusal, follows=FOLLOWS, ranged=ranged,
                      everything=count(conn, box, WIDE_SINCE, WIDE_UNTIL))
