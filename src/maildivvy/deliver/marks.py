"""What the delivery filter writes into a message's own bytes, before storage.

⛔ THE VERDICT HEADERS GO IN BEFORE THE DELIVERY AGENT STORES THE MESSAGE.
Once the file is stored and hardlinked, a header written into it changes every holder's
copy at once and no longer matches the size Dovecot indexed. Rewriting is safe here and
fatal afterwards.

⛔ THE BLOCK GOES AT THE TOP AND NOTHING IS STRIPPED, so our
occurrence of a field is the first one and the first one is what the pass reads. The
mark and the score are written into every message, spam or not: a header omitted
because there was no number leaves the *sender's* header of that name as the only
occurrence, and with the mark absent the message reads as not spam.

⛔ THE SPAM DECISION IS TAKEN ONCE, HERE. The score is compared with the
receiving domain's threshold at the moment the message arrives and the answer travels
in the bytes, so the mark a reader sees and the verdict the ledger holds can never
disagree, and lowering a threshold governs only what arrives afterwards. A message with
no score is not spam, and neither is one whose score is not a finite number: the
comparison raised on one such answer and the filter delivered nothing at all.

⛔ THE SUBJECT IS MARKED BY SURGERY ON THE HEADER BLOCK, never by parsing
the message and asking for its bytes back: that re-folds long headers and re-encodes
their encoded words, rewriting lines nobody asked to touch, and on real mail a signature
or a trace header is over the fold width.

⛔ THE BODY NOTICE RUNS BEHIND A ROUND-TRIP CONTROL. If the library
cannot hand back the bytes it was given, everything it writes afterwards is its
rendering of the message rather than the message. Everything that could refuse is asked
before anything is written, so no half-marked message is ever produced, and each of the
nine declines is named in the mark-detail header with the bytes exactly as they arrived.
"""

import base64
import codecs
import email
import email.policy
import math
import quopri

from maildivvy.deliver import report

SCAN_HEADER = "X-Maildivvy-Scan"
SCAN_DETAIL_HEADER = "X-Maildivvy-Scan-Detail"
SPAM_MARK_HEADER = "X-Maildivvy-Spam-Mark"
SPAM_SCORE_HEADER = "X-Maildivvy-Spam-Score"
SPAM_ACTION_HEADER = "X-Maildivvy-Spam-Action"
SPAM_DETAIL_HEADER = "X-Maildivvy-Spam-Detail"
MARK_DETAIL_HEADER = "X-Maildivvy-Spam-Mark-Detail"

# The literal written where the scanner gave no number. Never an omitted header.
NO_SCORE = "unavailable"

# The leaves a reader actually reads, and the only ones the notice is put into.
NOTICE_TYPES = ("text/plain", "text/html")

# ⛔ A text leaf inside one of these looks perfectly injectable and is not: the signature
# or the envelope covers the bytes, and a notice voids it in silence - the reader is told
# the message is broken, not that we marked it.
PROTECTED_TYPES = ("multipart/signed", "multipart/encrypted", "application/pkcs7-mime")

# The transfer encodings this program knows how to put bytes back into.
KNOWN_ENCODINGS = ("", "7bit", "8bit", "binary", "base64", "quoted-printable")

PARSE_FAILED = "parse-failed"
ROUND_TRIP_UNEQUAL = "round-trip-unequal"
DEFECTS = "defects"
PROTECTED_TYPE = "protected-type"
UNKNOWN_TRANSFER_ENCODING = "unknown-transfer-encoding"
UNKNOWN_CHARSET = "unknown-charset"
NOT_ENCODABLE = "notice-not-encodable"
NO_TEXT_LEAF = "no-text-leaf"
SERIALISE_FAILED = "serialise-failed"

SKIP_REASONS = (PARSE_FAILED, ROUND_TRIP_UNEQUAL, DEFECTS, PROTECTED_TYPE,
                UNKNOWN_TRANSFER_ENCODING, UNKNOWN_CHARSET, NOT_ENCODABLE,
                NO_TEXT_LEAF, SERIALISE_FAILED)


# --- the header block ----------------------------------------------------------------------------


def verdict_headers(verdict, detail, score, action, spam, score_detail, mark_detail, withheld_id):
    """The block the filter prepends, in order. A detail with nothing to say is left out."""
    headers = [
        (SCAN_HEADER, verdict),
        (SCAN_DETAIL_HEADER, detail),
        # ⛔ Both of these into every message, and the score never omitted.
        (SPAM_MARK_HEADER, "yes" if spam else "no"),
        (SPAM_SCORE_HEADER, NO_SCORE if score is None else f"{float(score):.2f}"),
        (SPAM_ACTION_HEADER, action or NO_SCORE),
        (SPAM_DETAIL_HEADER, score_detail),
        (MARK_DETAIL_HEADER, mark_detail),
        # ⛔ And both of these into every message too: the pass
        # reads them, so a sender's copy must never be the first occurrence. A message
        # filed with this block is never a report; the report has no block.
        (report.WITHHELD_HEADER, withheld_id or report.NONE),
        (report.REASON_HEADER, report.NONE),
    ]
    return [(name, value) for name, value in headers if value is not None]


def insert_headers(raw, headers):
    """Put the headers at the top of the message, above its own, in its own line ending.

    A value is collapsed to one line first: a CR or an LF inside one is not an escaping
    problem here, it is a new header.
    """
    eol = line_ending(split_header_block(raw)[0]).decode("ascii")
    block = "".join(f"{name}: {report.one_line(value)}{eol}" for name, value in headers)
    return block.encode("utf-8", "replace") + raw


def split_header_block(raw):
    """Split at the FIRST blank line: (header block, separator, everything else).

    ⛔ The separator is whichever blank line comes first, not whichever spelling this
    program prefers. A message with `\\n` endings holds no `\\r\\n\\r\\n` anywhere, and
    looking only for the CRLF form would hand the whole message back as a header block
    and put the Subject surgery inside somebody's body.
    """
    found = [(raw.find(sep), sep) for sep in (b"\r\n\r\n", b"\n\n")]
    found = [(pos, sep) for pos, sep in found if pos != -1]
    if not found:
        return raw, b"", b""
    pos, sep = min(found)
    return raw[:pos], sep, raw[pos + len(sep):]


def line_ending(header_block):
    return b"\r\n" if b"\r\n" in header_block else b"\n"


# --- the spam decision ----------------------------------------------------------------------------


def is_spam(score, threshold):
    """At or above the threshold, equality included; anything else is not spam.

    Only a finite number counts. A score that is absent, a boolean, a string or a
    NaN is *no score*, which is never spam whatever the threshold: the comparison
    raised on one such answer and the filter then delivered nothing at all.
    """
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return False
    return math.isfinite(score) and float(score) >= float(threshold)


# --- the Subject ----------------------------------------------------------------------------------


def mark_subject(raw, prefix):
    """Splice `prefix` into the first Subject of the header block, textually."""
    head, sep, rest = split_header_block(raw)
    eol = line_ending(head)
    out, done = [], False
    for line in head.splitlines(keepends=True):
        if not done and line[:8].lower() == b"subject:":
            value = line[8:]
            line = (b"Subject: " + prefix + value[1:] if value.startswith(b" ")
                    else b"Subject:" + prefix + value)
            done = True
        out.append(line)
    if not done:
        # No Subject at all: the message gains one rather than the mark being dropped,
        # because the prefix is the half of the mark a reader sees first.
        new = b"Subject: " + prefix.rstrip()
        out = [*out, eol + new] if out else [new]
    return b"".join(out) + sep + rest


# --- the body notice ------------------------------------------------------------------------------


def mark_spam(raw, score, threshold):
    """Both marks. Returns (bytes, detail); `detail` names the notice's decline, or None."""
    eol = line_ending(split_header_block(raw)[0]).decode("ascii")
    marked = mark_subject(raw, report.SPAM_SUBJECT_PREFIX.encode("ascii"))
    notice = report.spam_notice(score, threshold).replace("\n", eol)
    notice_html = report.spam_notice(score, threshold, html=True).replace("\n", eol)
    return mark_body(marked, notice, notice_html)


def mark_body(raw, notice_text, notice_html):
    """Put the notice at the top of every text leaf. Returns (bytes, detail).

    `detail` is None when the notice went in, and otherwise one of `SKIP_REASONS`. On
    every decline the bytes come back exactly as they arrived and the Subject mark,
    written before this ran, stands alone.
    """
    head, _, _ = split_header_block(raw)
    # ⚠️ `refold_source="none"` is not decoration: under the default the library re-folds
    # every header line over 78 characters and re-encodes its encoded words, which is a
    # rewrite of lines this program has no business touching - and on real mail, where a
    # DKIM-Signature or a Received line is always over 78, that is the usual case.
    policy = email.policy.default.clone(linesep=line_ending(head).decode("ascii"),
                                        refold_source="none")

    # ⛔ The round trip runs before any write.
    try:
        message = email.message_from_bytes(raw, policy=policy)
        again = message.as_bytes()
    except Exception as err:  # noqa: BLE001 - any parse fault at all
        return raw, f"{PARSE_FAILED}: {type(err).__name__}"
    if again != raw:
        return raw, ROUND_TRIP_UNEQUAL

    parts = list(message.walk())
    if any(part.defects for part in parts):
        return raw, DEFECTS
    if any(part.get_content_type() in PROTECTED_TYPES for part in parts):
        return raw, PROTECTED_TYPE

    # Everything that could refuse is asked before anything is written, so a decline
    # leaves no half-marked message behind.
    leaves = []
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in NOTICE_TYPES:
            continue
        charset = part.get_content_charset() or "us-ascii"
        encoding = (part.get("Content-Transfer-Encoding") or "").strip().lower()
        if encoding not in KNOWN_ENCODINGS:
            return raw, f"{UNKNOWN_TRANSFER_ENCODING}: {encoding}"
        text = notice_html if part.get_content_type() == "text/html" else notice_text
        try:
            codecs.lookup(charset)
            encoded = text.encode(charset)
        except LookupError:
            return raw, f"{UNKNOWN_CHARSET}: {charset}"
        except (UnicodeEncodeError, ValueError):
            return raw, f"{NOT_ENCODABLE}: {charset}"
        leaves.append((part, encoding, encoded))

    if not leaves:
        # ⛔ A decline says so rather than claiming success: silence here is
        # indistinguishable from a notice nobody can see.
        return raw, NO_TEXT_LEAF

    for part, encoding, encoded in leaves:
        set_payload(part, encoded + (part.get_payload(decode=True) or b""), encoding)
    try:
        return message.as_bytes(), None
    except Exception as err:  # noqa: BLE001 - any write fault at all
        return raw, f"{SERIALISE_FAILED}: {type(err).__name__}"


def set_payload(part, data, encoding):
    """Put `data` back into `part` in the encoding the leaf already declares.

    ⛔ `set_content` would pick an encoding of its own and rewrite the header to match.
    The Content-Transfer-Encoding is never touched here, so the bytes are produced in
    whatever it already says.
    """
    if encoding == "base64":
        part.set_payload(base64.encodebytes(data).decode("ascii"))
    elif encoding == "quoted-printable":
        part.set_payload(quopri.encodestring(data).decode("ascii"))
    else:
        part.set_payload(data.decode("ascii", "surrogateescape"))
