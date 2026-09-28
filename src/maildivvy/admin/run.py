"""Starting the interface: the preflight, the unix socket, and readiness after the bind.

    maildivvy-admin [--socket <path>] [--socket-group <group>] [--etc <dir>]
    maildivvy-admin --check

⛔ **Nothing binds before every file the service reads has been opened**.
A service that comes up and fails on its first request leaves nobody
to read the message: systemd reports it active, the socket answers, and the failure
reaches whoever tries to sign in. `--check` does all of that and stops before the bind,
so it runs on a machine where the socket is already held by the running service.

⚠️ **Ready is said after the bind, never before**: the unit is
`Type=notify`, and `READY=1` goes out once the socket is listening, so a restart that
has returned means the next request is answered rather than refused.

The socket is `0660`, owned by this user and the proxy's group, and it is the only
thing this program listens on: there is no TCP port anywhere in it. The server
is threaded rather than forked - ten threads means ten concurrent requests, which is
the whole load a handful of administrators make.
"""

import argparse
import ipaddress
import os
import shutil
import socket
import socketserver
import sys
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

from maildivvy.lib.config import ETC, ConfigError

SOCKET = "/run/maildivvy/admin/admin.sock"
MODE = 0o660
BACKLOG = 64
REQUEST_TIMEOUT = 60

# The header the proxy writes the person's own address into. ⛔ It is trusted because of
# the TRANSPORT, not because of its name: this program listens on one `0660` unix socket
# that only the proxy's group opens, so whatever arrives on it came from the proxy, which
# overwrites this header rather than appending to it.
FORWARDED_FOR = "X-Forwarded-For"

EX_CONFIG = 78          # sysexits: something a person has to fix in a file


def client_address(value):
    """The address in what the proxy forwarded, or `""` when there is no address in it.

    Only an address is ever returned: a name, a port, a second hop or anything carrying a
    newline would otherwise reach the journal, the login throttle and this unit's own log
    as if somebody's address were being read.
    """
    first = (value or "").split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(first))
    except ValueError:
        return ""


class Handler(WSGIRequestHandler):
    """The wsgiref handler, taught that a unix socket has no client address of its own."""

    timeout = REQUEST_TIMEOUT

    def forwarded(self):
        return client_address(self.headers.get(FORWARDED_FOR) if self.headers else None)

    def address_string(self):
        # what this unit's log says a request came from: the person, when the proxy said
        # who they were, and the socket itself otherwise - never an invented value
        return self.forwarded() or "unix"

    def get_environ(self):
        # ⛔ a unix socket's `client_address` is the empty string, and wsgiref reads
        # `self.client_address[0]`, which raises IndexError before the request is ever
        # parsed: every request answers nothing at all while the unit reads active.
        if not isinstance(self.client_address, tuple):
            self.client_address = ("", 0)
        environment = super().get_environ()
        # the client on the other end of the socket is the proxy; the person's own
        # address arrives in a header, and is trusted only because this is that socket
        environment["REMOTE_ADDR"] = self.forwarded()
        return environment


class UnixServer(socketserver.ThreadingMixIn, WSGIServer):
    """A threaded WSGI server on a socket that is already bound and listening."""

    address_family = socket.AF_UNIX
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, sock, application):
        socketserver.BaseServer.__init__(self, sock.getsockname(), Handler)
        self.socket = sock
        self.server_name = "maildivvy-admin"
        self.server_port = 0
        self.setup_environ()
        self.set_app(application)

    def get_environ(self):
        return self.base_environ


def listen(path, group=None, mode=MODE, backlog=BACKLOG):
    """Bind and listen on the unix socket, never wider than `mode`, even for an instant."""
    path = Path(path)
    if path.is_socket():
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o777 & ~mode)
    try:
        sock.bind(str(path))
    finally:
        os.umask(previous)
    os.chmod(path, mode)
    if group:
        shutil.chown(path, group=group)
    sock.listen(backlog)
    return sock


def notify(state="READY=1"):
    """Tell systemd, if it asked to be told. Returns whether anything was sent."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect(address)
        sock.sendall(state.encode())
    return True


def parse(argv):
    parser = argparse.ArgumentParser(
        prog="maildivvy-admin",
        description="Serve the administration interface on a unix socket. TLS is the "
                    "reverse proxy's, and this program opens no TCP port.")
    parser.add_argument("--socket", default=SOCKET, help="the unix socket the proxy opens")
    parser.add_argument("--socket-group", default=None,
                        help="the group that may open the socket; this user's own by default")
    parser.add_argument("--etc", default=str(ETC), help="the configuration root")
    parser.add_argument("--check", action="store_true",
                        help="read every file the service needs and exit, binding nothing")
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse(argv if argv is not None else sys.argv[1:])
    etc = Path(arguments.etc)

    from maildivvy.admin import auth

    problems = auth.preflight(etc)
    if problems:
        for problem in problems:
            sys.stderr.write(f"maildivvy-admin: {problem}\n")
        return EX_CONFIG

    from maildivvy.admin.app import create_app

    try:
        application = create_app(etc=etc)
    except ConfigError as err:
        sys.stderr.write(f"maildivvy-admin: {err}\n")
        return EX_CONFIG
    if arguments.check:
        print(f"maildivvy-admin: every file reads as expected; {arguments.socket} not bound")
        return 0

    sock = listen(arguments.socket, group=arguments.socket_group)
    server = UnixServer(sock, application)
    notify()                                   # ready, and not one moment before the bind
    print(f"maildivvy-admin: serving on {arguments.socket}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        Path(arguments.socket).unlink(missing_ok=True)
    return 0
