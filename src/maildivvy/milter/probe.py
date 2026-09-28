"""One libmilter negotiation against the socket: the proof that the daemon answers.

⛔ `systemctl is-active` reads `active` for a milter that started, could not open its
socket and will never answer a thing. Postfix's own default is
`tempfail`, so binding such a daemon refuses every submission on the machine. Install
step 14 therefore asks the socket itself, in the protocol's own words, before it binds
anything.

The wire format is libmilter's: a four-byte length, one command byte, then the
command's data. `SMFIC_OPTNEG` ('O') carries the version, the actions we would ask for
and the protocol steps we would skip; the daemon answers with the same command and its
own three numbers, which are what this prints.
"""

import socket
import struct
from dataclasses import dataclass

OPTNEG = b"O"  # SMFIC_OPTNEG, both ways
PROTOCOL_VERSION = 6  # what Postfix's `milter_protocol = 6` speaks
HEADER = 4  # the length field in front of every packet
LIMIT = 4096  # no negotiation is anywhere near this


class NoAnswer(Exception):
    """The socket did not negotiate. The message names the path and what happened."""


@dataclass(frozen=True)
class Negotiation:
    """What the daemon offered back: its version, its actions and its protocol steps."""

    version: int
    actions: int
    protocol: int


def negotiate(path, timeout=10):
    """Send one OPTNEG to `path` and read the daemon's own back, or raise NoAnswer."""
    packet = OPTNEG + struct.pack("!III", PROTOCOL_VERSION, 0, 0)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(struct.pack("!I", len(packet)) + packet)
            answer = read_packet(sock)
    except OSError as err:
        raise NoAnswer(f"{path}: {err}") from None
    if len(answer) != 13 or answer[:1] != OPTNEG:
        raise NoAnswer(f"{path}: did not negotiate; it answered {answer!r:.60}")
    return Negotiation(*struct.unpack("!III", answer[1:13]))


def read_packet(sock):
    """One length-prefixed packet, or NoAnswer when the daemon says nothing at all."""
    head = read_exactly(sock, HEADER)
    length = struct.unpack("!I", head)[0]
    if not 1 <= length <= LIMIT:
        raise OSError(f"answered a packet of {length} bytes")
    return read_exactly(sock, length)


def read_exactly(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise OSError("closed without answering" if not buf else "answered only part of a packet")
        buf += chunk
    return buf
