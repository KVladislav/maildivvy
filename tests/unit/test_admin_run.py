"""The client's address, as the interface learns it from the proxy.

The application serves plain HTTP on a unix socket and nothing else, so the address of
whoever is really making the request cannot be read off the connection: it arrives in a
header the proxy writes. ⛔ **That header is trusted because of the transport, not
because of its name**: this program has one listener, a `0660` socket only the proxy's
group opens, so anything arriving on it came from the proxy. A header the
person's own browser sent is overwritten there, and never appended to.

What is proved here is the parsing, which is the part a machine cannot show: an address
is taken only when it is one, so a value carrying a newline, a name or a chain of hops
cannot reach the journal, the throttle or the unit's log as if it were an address.
"""

from maildivvy.admin import run


class FakeHeaders(dict):
    def get(self, name, default=None):
        for key, value in self.items():
            if key.lower() == name.lower():
                return value
        return default


def test_an_address_the_proxy_wrote_is_taken_as_it_is():
    assert run.client_address("198.51.100.7") == "198.51.100.7"
    assert run.client_address(" 198.51.100.7 ") == "198.51.100.7"
    assert run.client_address("2001:db8::1") == "2001:db8::1"


def test_only_the_first_hop_is_read_and_a_chain_never_widens_it():
    # nginx writes `$remote_addr` alone, never `$proxy_add_x_forwarded_for`; a chain is
    # therefore something the proxy did not write, and only its first entry is an
    # address at all.
    assert run.client_address("198.51.100.7, 203.0.113.9") == "198.51.100.7"
    assert run.client_address("203.0.113.9, 198.51.100.7") == "203.0.113.9"


def test_anything_that_is_not_an_address_is_no_address():
    for value in (None, "", "   ", "unknown", "localhost", "198.51.100.256", "203.0.113.4:5678",
                  "198.51.100.7\nGET /", "<script>", "198.51.100.7 198.51.100.8"):
        assert run.client_address(value) == "", value


def test_the_request_environment_carries_that_address_and_the_socket_carries_none(monkeypatch):
    from wsgiref.simple_server import WSGIRequestHandler

    handler = run.Handler.__new__(run.Handler)
    handler.client_address = ""            # what a unix socket really gives 
    handler.headers = FakeHeaders({"X-Forwarded-For": "198.51.100.7"})
    monkeypatch.setattr(WSGIRequestHandler, "get_environ",
                        lambda self: {"REMOTE_ADDR": "", "REMOTE_HOST": "",
                                      "HTTP_X_FORWARDED_FOR": self.headers.get("X-Forwarded-For")})
    assert run.Handler.get_environ(handler)["REMOTE_ADDR"] == "198.51.100.7"
    assert handler.client_address == ("", 0)   # and wsgiref never meets the empty string

    handler.headers = FakeHeaders({})
    assert run.Handler.get_environ(handler)["REMOTE_ADDR"] == ""


def test_the_units_log_names_whoever_made_the_request_and_invents_nobody():
    handler = run.Handler.__new__(run.Handler)
    handler.client_address = ""
    handler.headers = FakeHeaders({"X-Forwarded-For": "198.51.100.7"})
    assert run.Handler.address_string(handler) == "198.51.100.7"
    handler.headers = FakeHeaders({"X-Forwarded-For": "not an address\nsomething else"})
    assert run.Handler.address_string(handler) == "unix"  # nothing to say, and nothing invented
    handler.headers = FakeHeaders({})
    assert run.Handler.address_string(handler) == "unix"


def test_the_program_binds_a_unix_socket_and_names_no_port_anywhere():
    text = (run.__file__ and open(run.__file__).read())
    assert "AF_INET" not in text and "SO_REUSEADDR" not in text
    assert run.SOCKET == "/run/maildivvy/admin/admin.sock"
    assert run.MODE == 0o660


def test_the_server_handles_no_more_requests_at_once_than_its_threads(monkeypatch):
    # a request past the bound waits for a thread rather than starting one, so a burst
    # of sign-ins never holds more database connections than there are threads
    import os
    import socket
    import threading
    import time

    monkeypatch.setattr(run, "THREADS", 2)
    lock = threading.Lock()
    active, most = [0], [0]

    def application(_environ, start_response):
        with lock:
            active[0] += 1
            most[0] = max(most[0], active[0])
        time.sleep(0.1)
        with lock:
            active[0] -= 1
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    address = f"\0maildivvy-test-{os.getpid()}"       # an abstract socket: no file to clean
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(address)
    sock.listen(16)
    server = run.UnixServer(sock, application)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    answers = []

    def request():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(address)
            client.sendall(b"GET / HTTP/1.0\r\n\r\n")
            answers.append(b"".join(iter(lambda: client.recv(4096), b"")))

    try:
        clients = [threading.Thread(target=request) for _ in range(8)]
        for client in clients:
            client.start()
        for client in clients:
            client.join(timeout=10)
    finally:
        server.shutdown()
        server.server_close()
    assert len(answers) == 8 and all(a.startswith(b"HTTP/1.0 200") for a in answers)
    assert most[0] == 2


# The service as systemd stops it: one slow request in flight, then SIGTERM.
SERVED = """
import sys, time
from maildivvy.admin import run

def application(_environ, start_response):
    print("inside", flush=True)
    time.sleep(1)
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"finished"]

path = sys.argv[1]
run.serve(run.UnixServer(run.listen(path), application), path)
print("returned", flush=True)
"""


def test_sigterm_lets_the_request_in_flight_finish_then_removes_the_socket(tmp_path):
    import os
    import signal
    import socket
    import subprocess
    import sys
    import time
    from pathlib import Path

    path = tmp_path / "admin.sock"
    source = str(Path(run.__file__).resolve().parents[2])
    served = subprocess.Popen([sys.executable, "-c", SERVED, str(path)],
                              env={**os.environ, "PYTHONPATH": source},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if path.is_socket():
                break
            time.sleep(0.05)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(path))
            client.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert served.stdout.readline() == "inside\n"   # the request is being answered
            served.send_signal(signal.SIGTERM)
            answer = b"".join(iter(lambda: client.recv(4096), b""))
        rest, err = served.communicate(timeout=10)
    finally:
        served.kill()
    assert answer.startswith(b"HTTP/1.0 200") and answer.endswith(b"finished"), answer
    assert served.returncode == 0 and "returned" in rest, (served.returncode, err)
    assert not path.exists()
