"""What the two stub providers share: the test certificate, the control file, the
command log, the threaded TLS server and its command line.

The stubs run on the test VM, where mpop and Postfix talk to them, under the
distribution's python3: the standard library only, nothing to install.

- **Control**: a JSON file the stub reads again at the start of every session, so a
  test rescripts a running stub by rewriting it (`write_control` replaces it whole).
- **Log**: one JSON object per line, appended as it happens: every command line the
  stub received (`session`, `command`, `argument`) and what it did (`event`). It is
  the only record, the same in-process and on the VM; `read_log` reads it back.
- **Lifecycle**: `start()` listens (port 0 lets the kernel choose, `port` tells),
  `stop()` closes the listener and every open connection, a hung one included. As a
  process: `--listen host:port`, a first stdout line `listening <host> <port>`, and
  SIGTERM stops it with exit 0.
"""

import argparse
import json
import os
import signal
import socket
import socketserver
import ssl
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

MAX_LINE = 65536


@dataclass(frozen=True)
class Certificate:
    ca: Path  # what a client trusts
    cert: Path  # the server's certificate, issued by `ca`
    key: Path


def make_certificate(directory, hostname):
    """A throwaway CA and a server certificate for `hostname` and 127.0.0.1, by openssl."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    ca, ca_key = d / "ca.pem", d / "ca.key"
    cert, key, request, extensions = d / "cert.pem", d / "key.pem", d / "cert.csr", d / "cert.ext"
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-noenc"]

    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    openssl("req", "-x509", *ec, "-keyout", ca_key, "-out", ca, "-days", "30",
            "-subj", "/CN=maildivvy stub CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", *ec, "-keyout", key, "-out", request, "-subj", f"/CN={hostname}")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{hostname},IP:127.0.0.1\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n")
    openssl("x509", "-req", "-in", request, "-CA", ca, "-CAkey", ca_key, "-set_serial",
            str(int.from_bytes(os.urandom(8), "big")), "-days", "30",
            "-extfile", extensions, "-out", cert)
    return Certificate(ca, cert, key)


def write_control(path, **settings):
    """Replace the control file whole, so no session reads half of it."""
    path = Path(path)
    partial = path.with_name(path.name + ".partial")
    partial.write_text(json.dumps(settings))
    partial.replace(path)


def read_log(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def text(line):
    """A received line as text, its line end removed; bytes that are not UTF-8 kept visible."""
    return line.rstrip(b"\r\n").decode("utf-8", "backslashreplace")


class Log:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, **record):
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(line)


class Connection:
    """One client: its socket, plain or TLS, read line by line."""

    def __init__(self, sock, stopping):
        self.sock = sock
        self.stopping = stopping
        self._buffer = bytearray()

    def starttls(self, context):
        """Switch to TLS; returns what the client sent ahead of the handshake, discarded."""
        early = bytes(self._buffer)
        self._buffer.clear()
        self.sock = context.wrap_socket(self.sock, server_side=True)
        return early

    def readline(self):
        """A line with its end, or b"" once the client closed."""
        while b"\n" not in self._buffer:
            if len(self._buffer) > MAX_LINE:
                raise ValueError("line too long")
            chunk = self.sock.recv(4096)
            if not chunk:
                return b""
            self._buffer += chunk
        end = self._buffer.index(b"\n") + 1
        line = bytes(self._buffer[:end])
        del self._buffer[:end]
        return line

    def send(self, data):
        self.sock.sendall(data)

    def hold(self):
        """Answer nothing and keep the connection until the client closes or the stub stops."""
        self.sock.settimeout(0.2)
        while not self.stopping.is_set():
            try:
                if not self.sock.recv(4096):
                    return
            except TimeoutError:
                continue
            except OSError:
                return

    def abort(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def close(self):
        self.sock.close()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Stub:
    """A threaded server whose subclass speaks the protocol in `session(conn, number)`."""

    name = "stub"

    def __init__(self, cert, key, log, control, host="127.0.0.1", port=0):
        self.tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.tls.load_cert_chain(cert, key)
        self.log_path = Path(log)
        self.log = Log(log)
        self.control_path = Path(control)
        self.address = (host, port)
        self.stopping = threading.Event()
        self._lock = threading.Lock()
        self._connections = set()
        self._sessions = 0
        self._server = None
        self._thread = None

    def control(self):
        return json.loads(self.control_path.read_text())

    @property
    def port(self):
        return self._server.server_address[1]

    def start(self):
        stub = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                stub._serve(self.request)

        self.stopping.clear()
        self._server = _Server(self.address, Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, args=(0.05,),
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._server is None:
            return
        self.stopping.set()
        self._server.shutdown()
        self._server.server_close()
        with self._lock:
            for conn in self._connections:
                conn.abort()
        self._thread.join(timeout=5)
        self._server = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def _serve(self, sock):
        conn = Connection(sock, self.stopping)
        with self._lock:
            self._sessions += 1
            number = self._sessions
            self._connections.add(conn)
        self.log.write(stub=self.name, session=number, event="connect")
        try:
            self.session(conn, number)
        except (OSError, ValueError) as error:  # ssl.SSLError is an OSError
            self.log.write(stub=self.name, session=number, event="error", detail=str(error))
        finally:
            with self._lock:
                self._connections.discard(conn)
            conn.close()
            self.log.write(stub=self.name, session=number, event="closed")

    def record(self, number, line):
        verb, _, argument = text(line).partition(" ")
        self.log.write(stub=self.name, session=number, command=verb.upper(), argument=argument)
        return verb.upper(), argument

    def session(self, conn, number):
        raise NotImplementedError


def main(description, make_stub, add_arguments=lambda parser: None):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--listen", default="127.0.0.1:0", help="host:port, port 0 for any")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--control", required=True)
    add_arguments(parser)
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    stub = make_stub(args, cert=args.cert, key=args.key, log=args.log,
                     control=args.control, host=host, port=int(port)).start()
    done = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: done.set())
    print(f"listening {host} {stub.port}", flush=True)
    while not done.wait(1):
        pass
    stub.stop()
