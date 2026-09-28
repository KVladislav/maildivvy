"""The two scan clients, against stand-in daemons on real unix sockets.

Each test starts a small server on a temporary socket, so the framing the client
writes is read by a peer and the answer it reads is written by one: the zINSTREAM
chunking, the terminator and the NUL-terminated answer, and rspamd's
HTTP answer. Nothing here needs ClamAV or rspamd; the real daemons are
proved on the test VM.
"""

import json
import socket
import struct
import threading

import pytest

from maildivvy.lib import scan

EICAR_NAME = "Win.Test.EICAR_HDB-1"


class Daemon:
    """A stand-in daemon on a unix socket: one connection at a time, handled by `serve`."""

    def __init__(self, path, serve):
        self.path = str(path)
        self.serve = serve
        self.seen = []
        self.stopped = False
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(4)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                if self.stopped:
                    return
                try:
                    self.serve(self, conn)
                except OSError:
                    pass

    def close(self):
        self.stopped = True
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as waker:  # unblocks accept()
            try:
                waker.connect(self.path)
            except OSError:
                pass
        self.thread.join(timeout=5)
        self.sock.close()


@pytest.fixture
def daemon(tmp_path):
    made = []

    def start(serve, name="daemon.sock"):
        made.append(Daemon(tmp_path / name, serve))
        return made[-1]

    yield start
    for one in made:
        one.close()


# --- clamd's zINSTREAM ----------------------------------------------------------


def read_stream(conn):
    """Read one zINSTREAM the way clamd does; returns (command, body)."""
    buf = b""
    while not buf.endswith(b"\0"):
        chunk = conn.recv(1)
        if not chunk:
            return None, b""
        buf += chunk
    command, body = buf[:-1], b""
    while True:
        head = recv_exactly(conn, 4)
        (length,) = struct.unpack("!I", head)
        if length == 0:
            return command.decode(), body
        body += recv_exactly(conn, length)


def recv_exactly(conn, count):
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            raise OSError("peer closed mid-chunk")
        buf += chunk
    return buf


def answering(answer, chunk_limit=None):
    """A clamd that reads the whole stream and answers `answer`, NUL-terminated."""

    def serve(daemon, conn):
        command, body = read_stream(conn)
        daemon.seen.append((command, body))
        if chunk_limit is not None and len(body) > chunk_limit:
            conn.sendall(b"INSTREAM size limit exceeded. ERROR\0")
            return
        conn.sendall(answer.encode() + b"\0")

    return serve


def test_the_bytes_go_over_the_socket_in_length_prefixed_chunks_after_zinstream(daemon):
    body = b"From: a@example.org\r\n\r\n" + b"x" * (scan.CHUNK + 7)
    one = daemon(answering("stream: OK"))
    verdict = scan.scan_virus(body, path=one.path, max_bytes=len(body))
    assert verdict.verdict == scan.CLEAN
    assert one.seen == [("zINSTREAM", body)]  # the peer read the command and every byte


def test_found_is_infected_and_keeps_the_detection_name(daemon):
    one = daemon(answering(f"stream: {EICAR_NAME} FOUND"))
    verdict = scan.scan_virus(b"eicar", path=one.path)
    assert verdict.verdict == scan.INFECTED
    assert verdict.withheld
    assert EICAR_NAME in verdict.detail  # not a boolean: which database answered


def test_error_is_unscanned_never_clean(daemon):
    one = daemon(answering("INSTREAM size limit exceeded. ERROR"))
    verdict = scan.scan_virus(b"x" * 10, path=one.path)
    assert verdict.verdict == scan.UNSCANNED
    assert verdict.withheld
    assert "size limit exceeded" in verdict.detail


# Read on the test VM on 2026-09-22 (clamd 1.5.4): the first is the daemon's own answer
# with its temporary directory full; the other two are the binary's reply formats
# (`<text>. ERROR`, `<name>: <libclamav error> ERROR`) filled with texts it and libclamav
# carry. `INSTREAM size limit exceeded. ERROR` is the only one that is about the message.
@pytest.mark.parametrize("answer", [
    "Error writing to temporary file ERROR",
    "Error processing command. ERROR",
    "stream: Can't allocate memory ERROR",
])
def test_an_error_other_than_the_size_limit_is_unavailable_never_unscanned(daemon, answer):
    """Every clamd ERROR read as *unscanned*, so a daemon failing on a message - its
    temporary directory full, measured on the VM - had that message sent unscanned under
    `outbound_unscanned = send`. Only the size-limit error is a verdict about the message;
    any other is the antivirus unavailable: 451 outbound, the hold inbound."""
    verdict = scan.scan_virus(b"x" * 10, path=daemon(answering(answer)).path)
    assert verdict.verdict == scan.UNAVAILABLE, verdict
    assert not verdict.withheld
    assert answer in verdict.detail


@pytest.mark.parametrize("limit", ["MaxRecursion", "MaxScanSize", "MaxFileSize", "MaxScanTime"])
def test_a_scan_the_daemon_cut_short_at_its_limits_is_unscanned_never_infected(daemon, limit):
    """With `AlertExceedsMax` the daemon names a scan it stopped at one of its limits
    (measured on 1.5.4: an archive nested 25 deep, `MaxRecursion`). Nobody looked at all
    of it, which is *unscanned*; and nothing was found, so it is not *infected*."""
    answer = f"stream: Heuristics.Limits.Exceeded.{limit} FOUND"
    verdict = scan.scan_virus(b"x" * 10, path=daemon(answering(answer)).path)
    assert verdict.verdict == scan.UNSCANNED, verdict
    assert f"Heuristics.Limits.Exceeded.{limit}" in verdict.detail


def test_a_daemon_that_answers_error_and_closes_mid_stream_is_still_unscanned(daemon):
    """Past its own limit clamd answers and closes, so our send fails with the verdict waiting."""

    def answers_then_closes(daemon_, conn):
        conn.recv(64)  # the command, then the first chunk's head and some of its bytes
        conn.recv(4096)
        conn.sendall(b"INSTREAM size limit exceeded. ERROR\0")
        conn.close()

    verdict = scan.scan_virus(b"x" * (scan.CHUNK * 8), path=daemon(answers_then_closes).path,
                              max_bytes=scan.CHUNK * 8)
    assert verdict.verdict == scan.UNSCANNED
    assert "size limit exceeded" in verdict.detail


def test_an_empty_or_unrecognised_answer_is_unavailable(daemon):
    def closes(daemon_, conn):
        read_stream(conn)

    assert scan.scan_virus(b"x", path=daemon(closes, "a.sock").path).verdict == scan.UNAVAILABLE
    other = daemon(answering("stream: what?"), "b.sock")
    verdict = scan.scan_virus(b"x", path=other.path)
    assert verdict.verdict == scan.UNAVAILABLE
    assert "what?" in verdict.detail


def test_a_socket_that_is_not_there_is_unavailable_and_never_raises(tmp_path):
    verdict = scan.scan_virus(b"x", path=tmp_path / "absent.sock")
    assert verdict.verdict == scan.UNAVAILABLE
    assert not verdict.withheld  # unavailable is delivered, marked
    assert "absent.sock" in verdict.detail


def test_the_four_verdicts_never_collapse():
    assert len({scan.CLEAN, scan.INFECTED, scan.UNSCANNED, scan.UNAVAILABLE}) == 4
    withheld = {v for v in (scan.CLEAN, scan.INFECTED, scan.UNSCANNED, scan.UNAVAILABLE)
                if scan.Verdict(v).withheld}
    assert withheld == {scan.INFECTED, scan.UNSCANNED}


# --- our own size gate, before any socket ------------------------------


def test_an_oversize_message_is_unscanned_and_the_socket_is_never_contacted(daemon):
    one = daemon(answering("stream: OK"))
    verdict = scan.scan_virus(b"x" * 101, path=one.path, max_bytes=100)
    assert verdict.verdict == scan.UNSCANNED
    assert verdict.withheld
    assert "101" in verdict.detail and "100" in verdict.detail
    assert one.seen == []  # nothing was sent: the gate is ours, not the daemon's error


def test_a_message_at_the_limit_is_scanned(daemon):
    one = daemon(answering("stream: OK"))
    assert scan.scan_virus(b"x" * 100, path=one.path, max_bytes=100).verdict == scan.CLEAN
    assert len(one.seen[0][1]) == 100


def test_the_limit_is_the_lower_of_the_two_the_daemon_runs_with(tmp_path):
    conf = tmp_path / "clamd.conf"
    conf.write_text("# a comment\nStreamMaxLength 50M\nMaxFileSize 100M\nMaxScanSize 400M\n")
    assert scan.size_limit(conf) == 50 * 1024 * 1024
    conf.write_text("StreamMaxLength 50M\nMaxFileSize 25M\n")
    assert scan.size_limit(conf) == 25 * 1024 * 1024  # the file limit is the lower one here
    conf.write_text("StreamMaxLength 1024\nMaxFileSize 2K\n")
    assert scan.size_limit(conf) == 1024


def test_a_limit_the_file_does_not_state_reads_as_the_daemons_own_default(tmp_path):
    conf = tmp_path / "clamd.conf"
    conf.write_text("MaxFileSize 100M\n")
    assert scan.size_limit(conf) == scan.CLAMD_DEFAULT_LIMIT
    assert scan.size_limit(tmp_path / "absent.conf") == scan.CLAMD_DEFAULT_LIMIT


def test_a_limit_that_is_not_a_size_is_refused_rather_than_guessed(tmp_path):
    conf = tmp_path / "clamd.conf"
    conf.write_text("StreamMaxLength 50MB\nMaxFileSize 50M\n")
    with pytest.raises(ValueError, match="StreamMaxLength"):
        scan.size_limit(conf)


def test_without_a_limit_of_its_own_the_gate_reads_the_daemons_configuration(daemon, tmp_path):
    conf = tmp_path / "clamd.conf"
    conf.write_text("StreamMaxLength 200\nMaxFileSize 100\n")
    one = daemon(answering("stream: OK"))
    verdict = scan.scan_virus(b"x" * 101, path=one.path, conf=conf)
    assert verdict.verdict == scan.UNSCANNED and one.seen == []
    assert scan.scan_virus(b"x" * 100, path=one.path, conf=conf).verdict == scan.CLEAN


# --- rspamd --------------------------------------------------------------------------


def http(payload, status="200 OK", body=None):
    """An rspamd that answers `payload` as JSON (or `body` as given bytes)."""

    def serve(daemon, conn):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        headers, rest = head.split(b"\r\n\r\n", 1)
        length = 0
        for line in headers.decode("latin-1").splitlines()[1:]:
            name, _, value = line.partition(":")
            if name.lower() == "content-length":
                length = int(value)
        while len(rest) < length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            rest += chunk
        daemon.seen.append((headers.decode("latin-1"), rest))
        answer = body if body is not None else json.dumps(payload).encode()
        conn.sendall(f"HTTP/1.1 {status}\r\nContent-Length: {len(answer)}\r\n\r\n".encode() + answer)

    return serve


def test_a_score_comes_back_with_the_message_posted_to_checkv2(daemon):
    one = daemon(http({"score": 4.1, "action": "add header"}))
    result = scan.scan_spam(b"From: a@example.org\r\n\r\nhello\r\n", path=one.path)
    assert (result.score, result.action, result.detail) == (4.1, "add header", None)
    headers, body = one.seen[0]
    assert headers.splitlines()[0] == "POST /checkv2 HTTP/1.1"
    assert body == b"From: a@example.org\r\n\r\nhello\r\n"


def test_the_callers_headers_reach_the_scanner(daemon):
    one = daemon(http({"score": 0.0}))
    scan.scan_spam(b"body", path=one.path, headers={"Settings-ID": "pop3", "IP": "192.0.2.1"})
    headers = one.seen[0][0].lower()
    assert "settings-id: pop3" in headers and "ip: 192.0.2.1" in headers


def test_a_scanner_that_cannot_be_reached_is_no_score_never_spam(tmp_path):
    result = scan.scan_spam(b"body", path=tmp_path / "absent.sock")
    assert result.score is None
    assert result.action == scan.UNAVAILABLE
    assert "absent.sock" in result.detail


def test_no_header_terminator_and_unparseable_json_are_no_score(daemon):
    def half(daemon_, conn):
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Len")

    first = scan.scan_spam(b"body", path=daemon(half, "a.sock").path)
    assert first.score is None and first.action == scan.UNAVAILABLE

    second = scan.scan_spam(b"body", path=daemon(http(None, body=b"{not json"), "b.sock").path)
    assert second.score is None and second.action == scan.UNAVAILABLE
    assert "unparseable" in second.detail


def test_an_answer_that_is_not_an_object_is_no_score(daemon):
    result = scan.scan_spam(b"body", path=daemon(http([1, 2, 3])).path)
    assert result.score is None and result.action == scan.UNAVAILABLE
    assert "not an object" in result.detail


def test_an_error_status_is_no_score(daemon):
    result = scan.scan_spam(b"body", path=daemon(http({"error": "no"}, status="500 Oops")).path)
    assert result.score is None and result.action == scan.UNAVAILABLE
    assert "500" in result.detail


@pytest.mark.parametrize("score", ["abc", True, float("nan"), float("inf"), {"x": 1}])
def test_a_score_that_is_not_a_finite_number_is_no_score_with_its_reason(daemon, score):
    payload = {"score": score, "action": "add header"}
    result = scan.scan_spam(b"body", path=daemon(http(payload)).path)
    assert result.score is None
    assert result.action == "add header"  # the action word is passed on as given
    assert result.detail and "not a number" in result.detail


def test_an_answer_with_no_score_at_all_is_no_score(daemon):
    result = scan.scan_spam(b"body", path=daemon(http({"action": "no action"})).path)
    assert result.score is None and result.action == "no action"
    assert "no score" in result.detail


def test_a_whole_number_score_is_a_score(daemon):
    result = scan.scan_spam(b"body", path=daemon(http({"score": 0, "action": "no action"})).path)
    assert result.score == 0.0 and result.detail is None


# --- the installed version against upstream, for health -----------------------------------


def test_the_clamav_version_is_read_from_the_daemons_answer(daemon):
    def version(daemon_, conn):
        daemon_.seen.append(conn.recv(64))
        conn.sendall(b"ClamAV 1.5.3/28128/Sat Sep 19 06:24:24 2026\0")

    one = daemon(version)
    answer = scan.clamd_version(path=one.path)
    assert one.seen == [b"zVERSION\0"]
    assert answer.engine == "1.5.3"
    assert answer.signatures == 28128
    assert answer.signatures_built.year == 2026


def test_a_daemon_that_does_not_answer_the_version_reads_as_unknown(tmp_path):
    assert scan.clamd_version(path=tmp_path / "absent.sock") is None


def test_upstreams_current_release_is_read_from_the_record_freshclam_reads():
    current = scan.parse_current_cvd('"1.4.6:63:28128:1789853340:1:90:49192:339"')
    assert current.engine == "1.4.6"
    assert current.signatures == 28128
    assert scan.older(current.engine, "1.5.3") and not scan.older("1.5.3", "1.4.6")
    assert scan.older("1.5.3", "1.5.10") and not scan.older("1.5.3", "1.5.3")
    assert scan.parse_current_cvd("") is None
    assert scan.parse_current_cvd('"nonsense"') is None
