"""The milter program's arguments: what it binds, what it reads and what it asks.

    maildivvy-milter [--socket <path>] [--db-conf <path>] [--clamd-socket <path>]
    maildivvy-milter --probe [--socket <path>]

⚠️ THE SENDER DIRECTORY IS NAMED EXPLICITLY. The unit passes
`--db-conf`, so the program can never fall back on another consumer's connection file:
one it cannot read fails closed at the lookup and defers every submission, while its
own files read exactly as expected.

`--probe` is install step 14's proof that the daemon answers before anything is bound
to it. It imports no part of the library, so it also works when the daemon
itself cannot start.
"""

import argparse
import sys

SOCKET = "/var/spool/postfix/maildivvy/milter.sock"
DB_CONF = "/etc/maildivvy/milter/db.conf"
CLAMD_SOCKET = "/run/clamav/clamd.ctl"

EX_UNAVAILABLE = 69  # sysexits: the probe got no answer from the socket


def parse(argv):
    parser = argparse.ArgumentParser(
        prog="maildivvy-milter",
        description="Bind a submitted message's From header to the authenticated login, "
                    "and scan what is submitted before Postfix queues it.")
    parser.add_argument("--socket", default=SOCKET,
                        help="the unix socket Postfix's submission service names")
    parser.add_argument("--db-conf", default=DB_CONF,
                        help="this program's own database connection file")
    parser.add_argument("--clamd-socket", default=CLAMD_SOCKET, help="the antivirus's socket")
    parser.add_argument("--probe", action="store_true",
                        help="negotiate with the socket, print what answered, and exit")
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse(argv if argv is not None else sys.argv[1:])
    if arguments.probe:
        from maildivvy.milter import probe

        try:
            answered = probe.negotiate(arguments.socket)
        except probe.NoAnswer as err:
            sys.stderr.write(f"maildivvy-milter: {err}\n")
            return EX_UNAVAILABLE
        print(f"{arguments.socket} negotiated version {answered.version}, "
              f"actions {answered.actions}, protocol {answered.protocol}")
        return 0

    from maildivvy.milter import daemon

    return daemon.serve(arguments.socket, arguments.db_conf, arguments.clamd_socket)
