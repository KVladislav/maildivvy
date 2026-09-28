"""One unauthenticated transaction on 465, printed as JSON: what the server answers.

Install step 14 reads this three times: with a milter bound to a socket nothing listens
on (the rollback drill), with nothing bound at all, and with the real binding in place.
⛔ A single reading would prove nothing: `milter_default_action = tempfail` means an
unreachable milter refuses temporarily, and so does half of what can go wrong with a
submission, so the drill's answer is only meaningful beside the other two.

Nothing authenticates here: the answer to MAIL FROM is the reading, and an
authenticated submission is the integration suite's.
"""

import json
import socket
import ssl
import sys

ADDRESS = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 465
SENDER = "probe@maildivvy-install.invalid"


def answer(stream):
    """One SMTP reply, continuation lines included; its code and its whole text."""
    lines = []
    while True:
        line = stream.readline().decode("utf-8", "replace").rstrip("\r\n")
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            break
    return {"code": lines[0][:3], "text": " ".join(lines)}


def main():
    out = {}
    try:
        # the certificate is the machine's own and is read by name elsewhere;
        # what is read here is the SMTP answer, so the handshake is not verified
        context = ssl._create_unverified_context()
        with socket.create_connection((ADDRESS, PORT), timeout=30) as raw:
            with context.wrap_socket(raw) as sock:
                stream = sock.makefile("rb")
                out["greeting"] = answer(stream)
                sock.sendall(b"EHLO maildivvy-install.invalid\r\n")
                out["ehlo"] = answer(stream)
                sock.sendall(f"MAIL FROM:<{SENDER}>\r\n".encode())
                out["mail"] = answer(stream)
                sock.sendall(b"QUIT\r\n")
    except Exception as err:
        out["error"] = f"{type(err).__name__}: {err}"
    print(json.dumps(out))


if __name__ == "__main__":
    main()
