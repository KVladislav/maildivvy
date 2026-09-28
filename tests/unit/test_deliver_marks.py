"""The marks the delivery filter writes into a message's own bytes, before storage.

Everything here is pure: bytes in, bytes out. The filter's own run against real
scanners and a real delivery agent is tested on the test machine.

Three rules are behind every test in this file:

- the verdict headers go in at the top and nothing is stripped, so our occurrence is
  the first one and the first one is what the pass reads;
- the Subject mark is textual surgery on the header block, never a parse and a
  re-serialisation, because the archive's file is the only copy and every receiver
  holds a hardlink to it;
- the body notice runs behind a round-trip control and declines on any doubt, naming
  the reason in a header, with the bytes exactly as they arrived.
"""

import base64
import email
import email.policy
import quopri

import pytest

from maildivvy.deliver import marks, report

PREFIX = report.SPAM_SUBJECT_PREFIX.encode("ascii")
NOTICE = "-- marked as spam --\n"
NOTICE_HTML = "<div>marked as spam</div>\n"

PLAIN = (b"From: someone@example.org\r\n"
         b"Subject: an ordinary message\r\n"
         b"Content-Type: text/plain; charset=utf-8\r\n"
         b"\r\n"
         b"plain words\r\n")


def marked_body(raw, notice=NOTICE, html=NOTICE_HTML):
    return marks.mark_body(raw, notice, html)


def parse(raw):
    return email.message_from_bytes(raw, policy=email.policy.default)


def header_lines(raw):
    head, _, _ = marks.split_header_block(raw)
    return head.splitlines()


# --- the header block: at the top, nothing stripped --------------------


def test_the_mark_and_the_score_go_into_every_message_spam_or_not():
    clean = marks.verdict_headers(verdict="clean", detail=None, score=None, action="no action",
                                  spam=False, score_detail=None, mark_detail=None, withheld_id=None)
    names = [name for name, _ in clean]
    assert names.count(marks.SPAM_MARK_HEADER) == 1
    assert names.count(marks.SPAM_SCORE_HEADER) == 1
    assert dict(clean)[marks.SPAM_MARK_HEADER] == "no"
    # ⛔ The literal, never an omitted header: an omitted one leaves the sender's own
    # header of that name as the first occurrence, which is the one the pass reads.
    assert dict(clean)[marks.SPAM_SCORE_HEADER] == marks.NO_SCORE == "unavailable"


def test_a_score_is_written_to_two_decimals_and_a_spam_message_says_yes():
    headers = dict(marks.verdict_headers(verdict="clean", detail=None, score=9.0,
                                         action="add header", spam=True, score_detail=None,
                                         mark_detail=None, withheld_id=None))
    assert headers[marks.SPAM_SCORE_HEADER] == "9.00"
    assert headers[marks.SPAM_MARK_HEADER] == "yes"


def test_only_the_details_are_left_out_when_there_are_none():
    quiet = [name for name, _ in marks.verdict_headers(
        verdict="clean", detail=None, score=1.0, action="no action", spam=False,
        score_detail=None, mark_detail=None, withheld_id=None)]
    assert marks.SCAN_DETAIL_HEADER not in quiet
    assert marks.MARK_DETAIL_HEADER not in quiet and marks.SPAM_DETAIL_HEADER not in quiet
    # the two fields the pass reads are never left out, not even with nothing to say:
    # the sender's copy would then be the first occurrence
    assert dict(marks.verdict_headers(
        verdict="clean", detail=None, score=1.0, action="no action", spam=False,
        score_detail=None, mark_detail=None, withheld_id=None))[report.WITHHELD_HEADER] \
        == report.NONE
    assert report.REASON_HEADER in quiet
    loud = dict(marks.verdict_headers(
        verdict="infected", detail="stream: Eicar-Signature FOUND", score=None,
        action="unavailable", spam=False, score_detail="rspamd: closed without answering",
        mark_detail="no-text-leaf", withheld_id="abc123"))
    assert loud[marks.SCAN_DETAIL_HEADER].endswith("FOUND")
    assert loud[marks.MARK_DETAIL_HEADER] == "no-text-leaf"
    assert loud[marks.SPAM_DETAIL_HEADER].startswith("rspamd")
    assert loud[report.WITHHELD_HEADER] == "abc123"


def test_our_headers_land_above_a_senders_copy_of_the_same_field():
    """A sender can neither mark their own message spam nor mark it clean: the first
    occurrence is ours, and theirs is never stripped, only outranked."""
    forged = (f"{marks.SPAM_MARK_HEADER}: yes\r\n{marks.SPAM_SCORE_HEADER}: 99.00\r\n"
              f"{report.WITHHELD_HEADER}: forged\r\n").encode() + PLAIN
    out = marks.insert_headers(forged, marks.verdict_headers(
        verdict="clean", detail=None, score=0.5, action="no action", spam=False,
        score_detail=None, mark_detail=None, withheld_id=None))
    message = parse(out)
    assert message.get_all(marks.SPAM_MARK_HEADER) == ["no", "yes"]
    assert message.get_all(marks.SPAM_SCORE_HEADER) == ["0.50", "99.00"]
    # Ours is written even when there is no id, so theirs is outranked too
    assert message.get_all(report.WITHHELD_HEADER) == [report.NONE, "forged"]
    assert out.endswith(PLAIN)  # every byte the sender wrote is still there, below ours


def test_the_block_is_written_in_the_messages_own_line_ending():
    crlf = marks.insert_headers(PLAIN, [("X-Test", "one")])
    assert crlf.startswith(b"X-Test: one\r\nFrom:")
    lf = marks.insert_headers(PLAIN.replace(b"\r\n", b"\n"), [("X-Test", "one")])
    assert lf.startswith(b"X-Test: one\nFrom:")


def test_a_header_value_can_never_carry_a_line_break_into_the_block():
    out = marks.insert_headers(PLAIN, [("X-Test", "one\r\nX-Forged: two\r\n\r\nbody")])
    message = parse(out)
    assert message.get_all("X-Forged") is None
    assert message.get("X-Test") == "one X-Forged: two body"


# --- the spam decision, taken once -------------------------------------


@pytest.mark.parametrize("score, threshold, spam", [
    (8.0, 8.0, True),    # at the threshold: equality is included
    (8.01, 8.0, True),
    (7.99, 8.0, False),
    (-3.0, 8.0, False),
    (150.0, 150.0, True),
])
def test_at_or_above_the_threshold_is_spam(score, threshold, spam):
    assert marks.is_spam(score, threshold) is spam


def test_no_score_is_not_spam_whatever_the_threshold():
    assert marks.is_spam(None, 1.0) is False


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf"), "8.0", True, object()])
def test_a_score_that_is_not_a_finite_number_is_no_score_and_never_raises(score):
    """The scanner client already reduces these to None; the comparison
    raised here once and delivered nothing at all, so the filter guards too."""
    assert marks.is_spam(score, 8.0) is False


def test_the_filter_honours_a_threshold_below_the_documented_floor():
    """The bounds are the database's constraint, not a property of the filter."""
    assert marks.is_spam(0.5, 0.25) is True


# --- the Subject: surgery on the header block --------------------------


def test_the_prefix_lands_after_the_first_subject_with_its_space():
    out = marks.mark_subject(PLAIN, PREFIX)
    assert b"Subject: [spam] an ordinary message\r\n" in out
    assert len(out) == len(PLAIN) + len(PREFIX)  # exactly the prefix, nothing else


def test_the_prefix_lands_after_a_subject_with_no_space_after_the_colon():
    raw = PLAIN.replace(b"Subject: an", b"Subject:an")
    out = marks.mark_subject(raw, PREFIX)
    assert b"Subject:[spam] an ordinary message\r\n" in out
    assert len(out) == len(raw) + len(PREFIX)


def test_a_second_subject_header_is_left_alone():
    raw = PLAIN.replace(b"Subject: an ordinary message\r\n",
                        b"Subject: first\r\nSubject: second\r\n")
    out = marks.mark_subject(raw, PREFIX)
    assert b"Subject: [spam] first\r\n" in out and b"Subject: second\r\n" in out
    assert out.count(PREFIX) == 1


def test_only_the_first_line_of_a_folded_subject_is_marked():
    raw = PLAIN.replace(b"Subject: an ordinary message\r\n",
                        b"Subject: a subject that goes on\r\n and on\r\n")
    out = marks.mark_subject(raw, PREFIX)
    assert b"Subject: [spam] a subject that goes on\r\n and on\r\n" in out


def test_a_continuation_line_that_begins_with_the_word_subject_does_not_fool_it():
    raw = (b"From: someone@example.org\r\n"
           b"X-Note: a note\r\n Subject: not a header at all\r\n"
           b"Subject: the real one\r\n\r\nbody\r\n")
    out = marks.mark_subject(raw, PREFIX)
    assert b" Subject: not a header at all\r\n" in out
    assert b"Subject: [spam] the real one\r\n" in out
    assert out.count(PREFIX) == 1


def test_both_line_endings_are_marked_and_the_body_below_is_untouched():
    for eol in (b"\r\n", b"\n"):
        raw = PLAIN.replace(b"\r\n", eol)
        out = marks.mark_subject(raw, PREFIX)
        assert b"Subject: [spam] an ordinary message" + eol in out
        assert out.endswith(b"plain words" + eol)
        assert len(out) == len(raw) + len(PREFIX)


def test_a_bare_newline_message_is_split_at_its_own_blank_line_not_at_a_crlf_pair():
    """A message with `\\n` endings holds no `\\r\\n\\r\\n` anywhere. Looking only for
    the CRLF spelling would read the whole message as a header block and cut into
    somebody's body."""
    raw = b"From: someone@example.org\nSubject: hello\n\nbody\nSubject: inside the body\n"
    head, sep, rest = marks.split_header_block(raw)
    assert head == b"From: someone@example.org\nSubject: hello"
    assert sep == b"\n\n" and rest == b"body\nSubject: inside the body\n"
    out = marks.mark_subject(raw, PREFIX)
    assert out.endswith(b"body\nSubject: inside the body\n")  # the body's Subject is not ours
    assert out.count(PREFIX) == 1


def test_an_encoded_word_subject_keeps_its_raw_encoding_behind_a_plain_prefix():
    raw = PLAIN.replace(b"Subject: an ordinary message",
                        b"Subject: =?utf-8?B?dMOpbMOpcGhvbmU=?=")
    out = marks.mark_subject(raw, PREFIX)
    assert b"Subject: [spam] =?utf-8?B?dMOpbMOpcGhvbmU=?=\r\n" in out
    assert parse(out)["Subject"] == "[spam] téléphone"  # and it still decodes


def test_a_message_with_no_subject_gains_one_without_a_trailing_space():
    raw = b"From: someone@example.org\r\nTo: nobody@example.org\r\n\r\nbody\r\n"
    out = marks.mark_subject(raw, PREFIX)
    assert b"Subject: [spam]\r\n\r\nbody\r\n" in out
    assert not out.count(b"[spam] ")  # the prefix's trailing space belongs to a value
    assert out.endswith(b"\r\nbody\r\n")


# --- the body notice: per text leaf, in its own charset and encoding --------------


def test_the_notice_goes_at_the_top_of_a_plain_text_leaf():
    out, detail = marked_body(PLAIN)
    assert detail is None
    assert out.endswith(NOTICE.replace("\n", "\r\n").encode() + b"plain words\r\n")
    assert header_lines(out) == header_lines(PLAIN)  # not one header line moved


def test_both_leaves_of_an_alternative_get_it_and_an_attachment_is_byte_equal():
    raw = (b"From: a@example.org\r\nSubject: shapes\r\nMIME-Version: 1.0\r\n"
           b'Content-Type: multipart/mixed; boundary="outer"\r\n\r\n'
           b"--outer\r\n"
           b'Content-Type: multipart/alternative; boundary="inner"\r\n\r\n'
           b"--inner\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nthe words\r\n"
           b"--inner\r\nContent-Type: text/html; charset=us-ascii\r\n\r\n<p>the words</p>\r\n"
           b"--inner--\r\n\r\n"
           b"--outer\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\nAAECAwQF\r\n"
           b"--outer--\r\n")
    out, detail = marked_body(raw)
    assert detail is None
    leaves = [p for p in parse(out).walk() if p.get_content_maintype() != "multipart"]
    assert leaves[0].get_payload(decode=True).startswith(NOTICE.replace("\n", "\r\n").encode())
    assert leaves[1].get_payload(decode=True).startswith(NOTICE_HTML.replace("\n", "\r\n").encode())
    assert leaves[2].get_payload(decode=True) == bytes(range(6))  # byte-equal, untouched
    assert b"AAECAwQF" in out


def test_a_legacy_charset_leaf_gets_the_notice_in_that_charset_not_in_utf8():
    raw = (b"From: a@example.org\r\nSubject: legacy\r\n"
           b"Content-Type: text/plain; charset=iso-8859-1\r\n"
           b"Content-Transfer-Encoding: 8bit\r\n\r\nGr\xfc\xdfe\r\n")
    out, detail = marked_body(raw, notice="Grüße: gemarkeerd\n")
    assert detail is None
    assert b"charset=iso-8859-1" in out
    assert b"Gr\xfc\xdfe: gemarkeerd" in out  # the leaf's own charset, one byte per character
    assert out.endswith(b"Gr\xfc\xdfe\r\n")


def test_a_base64_leaf_comes_back_base64_and_decodes_to_notice_then_original():
    body = base64.encodebytes(b"the original words\r\n").decode("ascii").replace("\n", "\r\n")
    raw = (b"From: a@example.org\r\nSubject: b64\r\n"
           b"Content-Type: text/plain; charset=us-ascii\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + body.encode())
    out, detail = marked_body(raw)
    assert detail is None
    assert b"Content-Transfer-Encoding: base64\r\n" in out  # never rewritten
    leaf = parse(out)
    assert leaf.get_payload(decode=True) == NOTICE.encode() + b"the original words\r\n"


def test_a_quoted_printable_leaf_comes_back_quoted_printable():
    raw = (b"From: a@example.org\r\nSubject: qp\r\n"
           b"Content-Type: text/plain; charset=utf-8\r\n"
           b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
           + quopri.encodestring("café words\r\n".encode()) + b"\r\n")
    out, detail = marked_body(raw)
    assert detail is None
    assert b"Content-Transfer-Encoding: quoted-printable\r\n" in out
    assert parse(out).get_payload(decode=True).startswith(NOTICE.replace("\n", "\r\n").encode())
    assert "café words" in parse(out).get_payload(decode=True).decode("utf-8")


def test_exactly_one_header_line_differs_across_real_world_shapes():
    """The strongest form: mark a message and compare it with the original line by
    line. Only the Subject may differ, and every non-text leaf must be byte-equal."""
    shapes = [
        PLAIN,
        PLAIN.replace(b"charset=utf-8", b"charset=iso-8859-15"),
        (b"From: a@example.org\r\nSubject: mixed\r\nMIME-Version: 1.0\r\n"
         b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
         b"--b\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nwords\r\n"
         b"--b\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n"
         b"--b--\r\n"),
        (b"From: a@example.org\r\nSubject: alternative\r\nMIME-Version: 1.0\r\n"
         b'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
         b"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nwords\r\n"
         b"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>words</p>\r\n"
         b"--b--\r\n"),
        PLAIN.replace(b"\r\n", b"\n"),
    ]
    for raw in shapes:
        out, detail = marks.mark_spam(raw, 9.0, 8.0)
        assert detail is None, (detail, raw)
        differing = [(a, b) for a, b in zip(header_lines(raw), header_lines(out)) if a != b]
        assert len(differing) == 1 and differing[0][1].startswith(b"Subject: [spam] ")
        assert len(header_lines(raw)) == len(header_lines(out))
        for before, after in zip(parse(raw).walk(), parse(out).walk()):
            if before.get_content_maintype() not in ("multipart", "text"):
                assert before.get_payload(decode=True) == after.get_payload(decode=True)


def test_the_subject_is_marked_even_when_the_notice_declines():
    raw = (b"From: a@example.org\r\nSubject: nothing to read\r\n"
           b"Content-Type: application/octet-stream\r\n\r\nbytes\r\n")
    out, detail = marks.mark_spam(raw, 9.0, 8.0)
    assert detail == marks.NO_TEXT_LEAF
    assert b"Subject: [spam] nothing to read\r\n" in out
    assert out.endswith(b"\r\nbytes\r\n")  # and the body is exactly as it arrived


# --- the nine declines, each named in the header -------


def test_the_nine_declines_are_the_nine_the_decision_names():
    assert marks.SKIP_REASONS == (
        "parse-failed", "round-trip-unequal", "defects", "protected-type",
        "unknown-transfer-encoding", "unknown-charset", "notice-not-encodable",
        "no-text-leaf", "serialise-failed")


def test_a_parse_fault_declines_and_returns_the_bytes_as_they_arrived(monkeypatch):
    """No message was found that makes the library raise on the way in, so the fault is
    injected: what is proved is that the catch is blanket and the bytes come back."""
    def boom(*args, **kwargs):
        raise RuntimeError("the parser gave up")

    monkeypatch.setattr(marks.email, "message_from_bytes", boom)
    out, detail = marked_body(PLAIN)
    assert out == PLAIN
    assert detail.startswith(marks.PARSE_FAILED) and "RuntimeError" in detail


def test_an_unequal_round_trip_declines():
    """A raw 8-bit byte in a header: the library hands back an encoded word instead."""
    raw = PLAIN.replace(b"Subject: an ordinary message", b"Subject: caf\xe9")
    out, detail = marked_body(raw)
    assert out == raw and detail == marks.ROUND_TRIP_UNEQUAL


def test_a_parse_defect_declines():
    raw = (b"From: a@example.org\r\nSubject: broken\r\nMIME-Version: 1.0\r\n"
           b'Content-Type: multipart/mixed; boundary="b"\r\n\r\nno parts at all\r\n')
    out, detail = marked_body(raw)
    assert out == raw and detail == marks.DEFECTS


@pytest.mark.parametrize("content_type", ["multipart/signed", "multipart/encrypted"])
def test_a_signed_or_encrypted_part_declines(content_type):
    """The signature covers the bytes and a notice voids it silently: the reader is
    told the message is broken rather than that we marked it."""
    raw = (b"From: a@example.org\r\nSubject: signed\r\nMIME-Version: 1.0\r\n"
           b'Content-Type: ' + content_type.encode() +
           b'; protocol="application/pgp-signature"; micalg=pgp-sha256; boundary="b"\r\n\r\n'
           b"--b\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nthe signed words\r\n"
           b"--b\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN-----\r\n"
           b"--b--\r\n")
    out, detail = marked_body(raw)
    assert out == raw and detail == marks.PROTECTED_TYPE


def test_a_transfer_encoding_the_program_cannot_write_back_declines():
    raw = (b"From: a@example.org\r\nSubject: uue\r\n"
           b"Content-Type: text/plain; charset=us-ascii\r\n"
           b"Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 x\r\n")
    out, detail = marked_body(raw)
    assert out == raw and detail.startswith(marks.UNKNOWN_TRANSFER_ENCODING)
    assert "x-uuencode" in detail


def test_a_charset_no_codec_on_this_machine_knows_declines():
    raw = PLAIN.replace(b"charset=utf-8", b"charset=x-no-such-charset")
    out, detail = marked_body(raw)
    assert out == raw and detail.startswith(marks.UNKNOWN_CHARSET)
    assert "x-no-such-charset" in detail


def test_a_notice_the_leafs_charset_cannot_hold_declines():
    raw = PLAIN.replace(b"charset=utf-8", b"charset=us-ascii")
    out, detail = marked_body(raw, notice="— gemarkeerd als spam\n")
    assert out == raw and detail.startswith(marks.NOT_ENCODABLE)
    assert "us-ascii" in detail


def test_a_message_with_no_text_leaf_says_so_rather_than_claiming_success():
    raw = (b"From: a@example.org\r\nSubject: bytes\r\n"
           b"Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC\r\n")
    out, detail = marked_body(raw)
    assert out == raw and detail == marks.NO_TEXT_LEAF


def test_a_failure_writing_the_result_declines_with_the_bytes_as_they_arrived(monkeypatch):
    """The second serialisation, after the leaves were written. Injected for the same
    reason as the parse fault, and proving the same thing: the original comes back."""
    real = marks.email.message_from_bytes

    def once(*args, **kwargs):
        message = real(*args, **kwargs)
        calls = []
        as_bytes = message.as_bytes

        def counted(*a, **k):
            calls.append(1)
            if len(calls) > 1:
                raise ValueError("the generator gave up")
            return as_bytes(*a, **k)

        message.as_bytes = counted
        return message

    monkeypatch.setattr(marks.email, "message_from_bytes", once)
    out, detail = marked_body(PLAIN)
    assert out == PLAIN
    assert detail.startswith(marks.SERIALISE_FAILED) and "ValueError" in detail


def test_every_decline_leaves_the_declared_transfer_encoding_alone():
    """Nothing is half-marked: on a decline the leaf is what arrived, header included."""
    raw = (b"From: a@example.org\r\nSubject: half\r\nMIME-Version: 1.0\r\n"
           b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
           b"--b\r\nContent-Type: text/plain; charset=us-ascii\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\nd29yZHM=\r\n"
           b"--b\r\nContent-Type: text/plain; charset=x-no-such-charset\r\n\r\nwords\r\n"
           b"--b--\r\n")
    out, detail = marked_body(raw)
    assert out == raw  # the first leaf could have been written; nothing was
    assert detail.startswith(marks.UNKNOWN_CHARSET)
