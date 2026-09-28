"""The milter program's shape, and the probe that proves the daemon answers.

pymilter is the distribution's `python3-milter` and is not installed here, so the
daemon module is read rather than imported: what these tests hold is the shape the
library's own failure modes demand (``, ``). The class
itself is driven against the real library on the test VM.

The probe is a libmilter negotiation against the socket. It is what install step 14
runs before it binds anything, so it is exercised here against a server
that answers and against three that do not.
"""

import ast
import socket
import struct
import threading
from pathlib import Path

import pytest

from maildivvy.milter import probe

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "maildivvy" / "milter"
DAEMON = PACKAGE / "daemon.py"
PROGRAM = ROOT / "bin" / "maildivvy-milter"


def daemon_tree():
    return ast.parse(DAEMON.read_text(), filename=str(DAEMON))


def class_of(name):
    for node in daemon_tree().body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"{name} is not in {DAEMON}")


def method_of(klass, name):
    for node in klass.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{klass.name} has no {name}")


def decorators(node):
    return [ast.unparse(d) for d in node.decorator_list]


# --- the file name the library will not tolerate ------------------------------

def test_nothing_the_program_can_import_is_named_after_the_library_it_imports():
    # ⛔ pymilter imports a lowercase C extension `milter` from inside its own package.
    # A module of that name anywhere the program's sys.path reaches shadows it and the
    # daemon dies at every start - and under Postfix's fail-closed default that refuses
    # every submission on the machine.
    reachable = [ROOT / "bin", ROOT / "src", PACKAGE]
    for directory in reachable:
        assert not (directory / "milter.py").exists(), directory
    # the package directory itself is `maildivvy/milter/`, which is never a top-level
    # name, and the program is not named after the library either
    assert PROGRAM.name == "maildivvy-milter"
    assert (PACKAGE / "__init__.py").exists()


def test_the_program_puts_only_its_own_library_on_the_path():
    text = PROGRAM.read_text()
    assert "sys.dont_write_bytecode = True" in text
    assert "from maildivvy.milter.run import main" in text


# --- the decision outside the class, the collection undecorated ---------------

def test_the_whole_decision_is_a_plain_function_that_no_class_holds():
    # pymilter's TestCtx rebuilds the milter and discards a hand-bound instance, so a
    # suite driving the class tests the harness
    from maildivvy.milter import decision
    for name in ("decide", "decide_scan"):
        assert callable(getattr(decision, name))
    for node in ast.walk(daemon_tree()):
        if isinstance(node, ast.ClassDef):
            assert not any(isinstance(child, ast.FunctionDef) and child.name in ("decide", "decide_scan")
                           for child in node.body), node.name


def test_header_collection_is_an_undecorated_method_the_decorated_one_delegates_to():
    # ⚠️ `@Milter.noreply` reads `self._protocol`, which exists only once the harness
    # has bound the instance: a hand-built object raises AttributeError on the
    # decorated method. So the logic lives in a plain one.
    binding = class_of("SenderBinding")
    assert decorators(method_of(binding, "note_header")) == []
    assert decorators(method_of(binding, "header")) == ["Milter.noreply"]
    assert "note_header" in ast.unparse(method_of(binding, "header"))


def test_the_login_is_read_at_mail_from_and_the_collection_is_reset_there():
    # one connection carries several messages, and the From headers of one must not
    # leak into the next
    envfrom = ast.unparse(method_of(class_of("SenderBinding"), "envfrom"))
    assert "{auth_authen}" in envfrom
    assert "getsymval" in envfrom
    for reset in ("self.from_headers = []", "self.headers = []", "self.chunks = []"):
        assert reset in envfrom, reset


# --- the probe: the proof the daemon answers, before anything is bound --------------

class Server:
    """A unix socket that answers one negotiation, as libmilter does."""

    def __init__(self, path, answer=b"", close_early=False):
        self.path = str(path)
        self.answer = answer
        self.close_early = close_early
        self.asked = []
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(self.path)
        self.socket.listen(1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        connection, _ = self.socket.accept()
        with connection:
            head = connection.recv(4)
            if len(head) == 4:
                self.asked.append(head + connection.recv(struct.unpack("!I", head)[0]))
            if not self.close_early:
                connection.sendall(self.answer)

    def stop(self):
        self.socket.close()
        self.thread.join(timeout=5)


def negotiation(version=6, actions=0, protocol=0):
    body = b"O" + struct.pack("!III", version, actions, protocol)
    return struct.pack("!I", len(body)) + body


@pytest.fixture
def path(tmp_path):
    return tmp_path / "milter.sock"


def test_the_probe_negotiates_and_reads_back_what_the_daemon_offered(path):
    server = Server(path, answer=negotiation(version=6, actions=15, protocol=255))
    try:
        answered = probe.negotiate(path, timeout=5)
    finally:
        server.stop()
    assert (answered.version, answered.actions, answered.protocol) == (6, 15, 255)
    # what the probe sent is one OPTNEG packet of the version the product speaks
    [asked] = server.asked
    assert asked[4:5] == b"O"
    assert struct.unpack("!I", asked[:4])[0] == len(asked) - 4
    assert struct.unpack("!III", asked[5:17])[0] == probe.PROTOCOL_VERSION


def test_a_socket_nothing_listens_on_is_a_failure_that_names_the_path(path):
    with pytest.raises(probe.NoAnswer, match=str(path)):
        probe.negotiate(path, timeout=5)


def test_a_daemon_that_accepts_and_says_nothing_is_not_an_answer(path):
    # ⛔ the positive control's opposite: `systemctl is-active` reads `active` for a
    # process that binds and then cannot answer, which is the failure this probe exists
    # for
    server = Server(path, close_early=True)
    try:
        with pytest.raises(probe.NoAnswer):
            probe.negotiate(path, timeout=5)
    finally:
        server.stop()


def test_an_answer_that_is_not_a_negotiation_is_refused(path):
    server = Server(path, answer=struct.pack("!I", 5) + b"Xabcd")
    try:
        with pytest.raises(probe.NoAnswer, match="did not negotiate"):
            probe.negotiate(path, timeout=5)
    finally:
        server.stop()
