"""The words the delivery filter writes: the withheld report, and the spam notice.

⛔ THE REPORT MAY NOT CLAIM MALWARE FOR A MESSAGE NOBODY EXAMINED.
`infected` and `unscanned` are different facts and get different words: one says
something was found, the other says the message was too large to look at and that
nothing is known about it either way. An unrecognised reason raises, because the
default a programmer reaches for is the first branch, and the first branch is the
malware wording.

⛔ EVERYTHING QUOTED OUT OF THE WITHHELD MESSAGE IS THE SENDER'S OWN TEXT.
The header block below is built by joining strings, so a CR or an LF inside a value is
not an escaping problem - it is a new header, and a pair of them is a new body under
this machine's own From line. Every value therefore goes through `one_line` first and
is encoded only afterwards: encoding first would hide the break inside an encoded word
for the next reader to decode.

⛔ READING A HEADER OF THAT MESSAGE MUST NEVER RAISE. The read happens
inside the branch that writes the report, and the message it describes is already in
the archive. Uncaught, the sender picks the exception: the filter exits on a traceback,
no report is written, nobody is told anything was withheld, and the delivery failure
walks into the fetch runner's bounded retry.

⛔ THE SPAM NOTICE MAY NOT SAY WHO WILL RECEIVE THE MESSAGE. It is composed
here, before the message is stored and long before the fan-out reads the domain's
delivery switch, so at the moment these words are written nobody knows whether a person
will see them.
"""

import email.header
import email.utils
import html as html_lib

from maildivvy.lib import scan, store

WITHHELD_HEADER = "X-Maildivvy-Withheld-Id"
REASON_HEADER = "X-Maildivvy-Report-Reason"
# ⛔ What the filter's own block says in both fields when the message is not a report,
# or not withheld. A field the pass reads is trusted in its
# first occurrence, which is ours only if we wrote one; left out, the first occurrence
# was the sender's, and a sender's reason made clean mail a report.
NONE = "none"

# ⛔ The trailing space is part of it: the prefix is spliced into the Subject line by
# textual surgery, so what is written is exactly these characters.
SPAM_SUBJECT_PREFIX = "[spam] "

# Every C0 control character, and DEL.
CONTROLS = {chr(c) for c in [*range(0x20), 0x7F]}
RULE = "-" * 70
WRAP = 70
ATTACHMENT_LIMIT = 20


class UnknownReason(Exception):
    """Raised rather than guessing which sentence to print."""


def one_line(value):
    """Collapse an untrusted value to one line of printable characters."""
    return " ".join("".join(" " if ch in CONTROLS else ch for ch in str(value)).split())


def header_value(value):
    """`one_line`, and then RFC 2047 where what is left is not ASCII."""
    text = one_line(value)
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return email.header.Header(text, "utf-8").encode()
    return text


def quoted(original, name, missing):
    """One header of the withheld message, as one safe line, never raising."""
    try:
        value = original.get(name, missing)
    except Exception:  # noqa: BLE001 - see this module's docstring: the sender picks it
        return f"(an unreadable {name} header)"
    return one_line(value if value is not None else missing)


def attachment_names(original, limit=ATTACHMENT_LIMIT):
    """The names the withheld message gives its parts; never raises."""
    names = []
    try:
        for part in original.walk():
            name = part.get_filename()
            if name:
                names.append(one_line(name))
            if len(names) >= limit:
                break
    except Exception:  # noqa: BLE001 - walking a hostile MIME tree is not worth the report
        return ["(an unreadable attachment name)"]
    return names


# The headline and the body lines of each reason. Two different facts, two different
# wordings, and a reason that is in neither raises.
WORDS = {
    scan.INFECTED: (
        "A message addressed to this domain was withheld: malware.",
        ["The antivirus scanner examined this message and found malware in it.",
         f"The message was filed into the {store.QUARANTINE} folder of this domain's",
         "archive and was not delivered to anybody."],
    ),
    scan.UNSCANNED: (
        "A message addressed to this domain was withheld: it was too large to scan.",
        ["This message was larger than the scanning limit, so nobody looked at it.",
         "NOTHING IS KNOWN ABOUT IT either way - it is not known to be harmful and",
         "it is not known to be safe. It was filed into the "
         f"{store.QUARANTINE} folder of this",
         "domain's archive and was not delivered to anybody."],
    ),
}


def compose(reason, original, withheld_id, domain):
    """The report's bytes. `original` is the withheld message, parsed."""
    if reason not in WORDS:
        raise UnknownReason(
            f"no report wording for reason {reason!r} - refusing rather than defaulting, "
            "because the default would claim malware for a message nobody examined")
    headline, body = WORDS[reason]

    domain = one_line(domain)  # every value this block joins is collapsed first
    sender = quoted(original, "From", "(no From header)")
    subject = quoted(original, "Subject", "(no Subject header)")
    message_id = quoted(original, "Message-ID", "")
    names = attachment_names(original)

    lines = [
        f"From: maildivvy@{domain}",
        f"To: {store.ARCHIVE}@{domain}",
        f"Subject: {header_value(f'[withheld] {subject}')}",
        f"Date: {email.utils.formatdate(localtime=True)}",
        # The withheld id is this report's link to the message it replaces, so it is its
        # identity too and no second unique value is needed.
        f"Message-ID: <{withheld_id}@{domain}>",
        # ⛔ The body is UTF-8 and says so: it quotes a sender's From and Subject, which
        # are frequently not ASCII, and undeclared the line a reader checks is the line
        # that arrives as mojibake.
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        f"{WITHHELD_HEADER}: {withheld_id}",
        f"{REASON_HEADER}: {reason}",
        "",
        headline,
        "",
        *body,
        "",
        "The message it replaces:",
        f"  From:        {sender}",
        f"  Subject:     {subject}",
        f"  Attachments: {', '.join(names) if names else '(none named)'}",
        f"  Message-ID:  {message_id or '(none)'}",
        f"  Withheld id: {withheld_id}",
        "",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8", "replace")


def spam_notice(score, threshold, html=False):
    """The notice that goes at the top of a marked message's own text.

    It claims three things and no more: what the scanner scored the message, what this
    domain counts as spam, and that what follows is otherwise the message as it arrived.
    """
    paragraphs = [
        "This message was marked as spam by the mail system.",
        f"Its spam score was {float(score):.2f}, and this domain treats a score of "
        f"{float(threshold):.2f} or above as spam. The score was measured when the "
        "message arrived. The threshold is a setting an administrator can change, and "
        "changing it does not re-mark a message that has already arrived.",
        f'Nothing was removed. Apart from this notice and the "{SPAM_SUBJECT_PREFIX.strip()}" '
        "added to the Subject line, what follows is the message as it arrived.",
    ]
    if html:
        block = "".join(f"<p>{html_lib.escape(p, quote=True)}</p>" for p in paragraphs)
        return ('<div style="border:1px solid #999;padding:8px;margin:0 0 12px 0">'
                f"{block}</div>\n")
    return f"{RULE}\n" + "".join(f"{wrap(p)}\n\n" for p in paragraphs) + f"{RULE}\n\n"


def wrap(paragraph, width=WRAP):
    """Lines short enough to be prepended to a quoted-printable leaf without rewrapping."""
    lines, line = [], ""
    for word in paragraph.split():
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    lines.append(line)
    return "\n".join(lines)
