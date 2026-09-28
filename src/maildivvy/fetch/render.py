"""One mpop configuration per external mailbox, rendered from the row and nothing else.

⛔ THE RENDERED FILE NEVER CARRIES THE PROVIDER'S SECRET. It names a
command - `passwordeval` - which mpop runs and reads on a pipe, so the secret is never
in a file, never in `argv` and never in the process table. No code path here writes one.

⛔ THE TRANSPORT HAS NO SWITCH. The two transport lines of TEMPLATE are
literal constants, and a unit test reads every line of this package to prove no other
one carries the lowercase token. A slot in either of them would be the switch that rule
exists to keep out; a server that speaks plain text is reached by swapping the BINARY
(`--mpop`), which changes what runs and nothing about what the file says.

⛔ THE HOST AND THE LOGIN LINES ARE MPOP'S STATE KEY. mpop files what it
has already retrieved under (host, login), so one character's difference there reads to
it as a mailbox it has never seen and its whole retained window is fetched again - a
window's worth of duplicates in the archive and in the ledger. Whatever a later column
adds to the file is rendered somewhere else; those two lines do not move.

⛔ THE LOGIN AND THE ADDRESS BECOME A DIRECTIVE. Whichever is in force is
written as the `user` line as it stands, so a line break there is a second directive in
a file mpop obeys as the mail owner. One rule - `check_field` - refuses whitespace and
control characters in both, and in the host beside them, so the three cannot drift
apart. The store holds the same rule (`schema/0001_initial.sql`), and this is the half
that holds for a row written any other way.

The row arrives as `Mailbox`, unpacked by name: a query that lost a column raises here,
on the first mailbox of the first run, rather than rendering a word the delivery filter
refuses one message at a time and a whole process away from the cause.
"""

import os
import re
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

# Whitespace, the C0 controls and DEL. Everything else a provider may want to be told.
FIELD = re.compile(r"^[^\s\x00-\x1f\x7f]+\Z")

DEFAULT_STATE_DIR = Path("/var/lib/maildivvy/fetch")
DEFAULT_BINDIR = Path("/opt/maildivvy/bin")
DEFAULT_HOLD_BOUND = 3600  # seconds; the hold's bound, and the delivery filter's default


class RenderError(Exception):
    """A row that must not become a configuration file. The message names the column."""


class Mailbox(NamedTuple):
    """One external mailbox as the runner selects it, in the order QUERY names.

    A new column is appended, never inserted: `window`, `target`, `threshold` and
    `held_since` each arrived that way. Unpacking is by name, so nothing shifts.
    """

    id: int
    pop3_login: str | None
    address: str
    pop3_host: str
    pop3_port: int
    label: str
    window: int | None
    target: str
    threshold: object
    held_since: datetime | None


# ⛔ Two of these lines are constants and must stay constants. Every other slot is a
# name, a number, a path or a label.
TEMPLATE = (
    "account {account}",
    "host {host}",
    "port {port}",
    "tls on",
    "tls_starttls off",
    "auth on",
    "user {user}",
    'passwordeval "{bindir}/maildivvy-credential {id}"',
    "keep {keep}",
    "only_new on",
    "uidls_file {state}/uidls",
    'delivery mda "{delivery}"',
)


def check_field(value, column):
    """The one rule the login, the address and the host are held to."""
    if not isinstance(value, str) or not FIELD.match(value):
        raise RenderError(
            f"{column} {value!r} holds whitespace or a control character, or is empty; "
            "it would become a directive of its own in the file mpop obeys")
    return value


def account_name(mailbox_id):
    """mpop's name for this account. It is not part of mpop's state key."""
    return f"em{mailbox_id}"


def state_dir(root, mailbox_id):
    return Path(root) / str(mailbox_id)


def login_of(mailbox):
    """The login presented to the provider: the stored one, else the address as typed."""
    return mailbox.pop3_login or mailbox.address


def keep_of(mailbox):
    """The provider-side window as mpop's duration.

    mpop's clock starts at its FIRST SIGHTING of the message, not at the message's Date
    header, so a message already three weeks old when first seen is deleted
    three weeks later than a reader of "from its date" would expect.
    """
    if mailbox.window is None:
        # `keep on` would be mpop's reading of a missing window and deletes nothing.
        # The column is NOT NULL, so a None here is a query that lost it.
        raise RenderError(
            f"external mailbox {mailbox.id} has no delete_window_days; the column is "
            "NOT NULL, so this is a query that lost it")
    return f"{int(mailbox.window)}d"


def delivery_command(mailbox, bindir, hold_bound=DEFAULT_HOLD_BOUND):
    """What mpop pipes each retrieved message into, and the only way the filter is told.

    The domain's threshold is rendered here and nowhere else: the filter
    holds no database connection, and this is the one invocation of it in the tree.
    `--held-since` is the other half of the antivirus hold: the runner records
    when a hold began and renders it back, so that past the bound the filter delivers
    the message marked *unavailable* instead of holding it for ever.
    """
    if mailbox.threshold is None:
        raise RenderError(
            f"domain {mailbox.label} has no spam_threshold; the column is NOT NULL, so "
            "this is a query that lost it")
    # ⛔ `exec`: mpop runs this line through `sh -c`, and dash forks for it. A shell left
    # waiting would hold the retrieval pipe's write end and hide from the filter that
    # mpop abandoned the message it is reading (`lib/retrieval.py`).
    # `--retrieval`: a pipe that never reached the filter is then said, and recorded
    argv = ["exec", f"{bindir}/maildivvy-deliver", "--retrieval", "--domain", mailbox.label,
            "--spam-threshold", f"{float(mailbox.threshold):.2f}"]
    if mailbox.held_since is not None:
        argv += ["--held-since", mailbox.held_since.isoformat(),
                 "--hold-bound-seconds", str(int(hold_bound))]
    return " ".join(argv)


def render(mailbox, state_root=DEFAULT_STATE_DIR, bindir=DEFAULT_BINDIR,
           hold_bound=DEFAULT_HOLD_BOUND):
    """The mpoprc text for one external mailbox."""
    check_field(mailbox.address, "address")
    user = check_field(login_of(mailbox), "pop3_login")
    host = check_field(mailbox.pop3_host, "pop3_host")
    return "\n".join(TEMPLATE).format(
        account=account_name(mailbox.id), host=host, port=int(mailbox.pop3_port),
        user=user, bindir=bindir, id=mailbox.id, keep=keep_of(mailbox),
        state=state_dir(state_root, mailbox.id),
        delivery=delivery_command(mailbox, bindir, hold_bound)) + "\n"


def write_config(text, state):
    """Write the mpoprc into the mailbox's state directory, 0600 at creation.

    ⛔ The mode is given to `open(O_CREAT)`, never set afterwards: a file
    that is world-readable for a moment has been world-readable. The file holds no
    secret, but it names the command that prints one, and the same rule covers the
    trace and the listing session's copy of the state file, which do.
    """
    state = Path(state)
    os.makedirs(state, mode=0o700, exist_ok=True)  # the mode at creation here too
    path = state / "mpoprc"
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as out:
        out.write(text)
    return path
