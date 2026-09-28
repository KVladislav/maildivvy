"""A stub provider SMTP relay: STARTTLS, then AUTH, then it accepts and keeps every
message, delivering nothing. Postfix's per-sender relay talks to it.

Before STARTTLS it offers no AUTH and refuses one (530); before AUTH it refuses
MAIL (530), as a provider's submission relay does.

Control file (JSON, read again at every session):

- `accounts`: `{"<user>": "<password>"}`, the logins it accepts (AUTH PLAIN or LOGIN).
- `refuse_auth`: refuse every AUTH with 535, a correct one included.
- `implicit_tls`: TLS from the first byte, as a provider's port 465 speaks it (RFC 8314):
  the handshake comes before the greeting, AUTH is offered at once and STARTTLS never.

The log has every command line received (the AUTH continuation lines as `(auth)`),
an `auth` event with the user, the password and whether it was accepted, and one
`message` event per accepted message: `auth_user`, `mail_from`, `rcpt_to`, and `data`,
the message as received with the dot-stuffing removed, decoded as Latin-1 so that
`data.encode("latin-1")` gives its bytes back.
"""

import base64
import binascii

from stubserver import Stub, main, text

CRLF = b"\r\n"


def address(argument, keyword):
    """The address in `FROM:<a> params` / `TO:<a>`, or None."""
    head, _, rest = argument.partition(":")
    if head.strip().upper() != keyword or "<" not in rest or ">" not in rest:
        return None
    return rest[rest.index("<") + 1:rest.index(">")]


class SMTPStub(Stub):
    name = "smtp"

    def session(self, conn, number):
        control = self.control()
        state = {"tls": False, "user": None, "from": None, "to": [], "queued": 0}

        def reply(line):
            conn.send(line.encode() + CRLF)

        def reset():
            state["from"], state["to"] = None, []

        def continuation(prompt):
            reply(f"334 {prompt}")
            line = conn.readline()
            self.log.write(stub=self.name, session=number, command="(auth)",
                           argument=text(line))
            return text(line)

        def decode(value):
            return base64.b64decode(value, validate=True).decode("utf-8", "backslashreplace")

        def authenticate(argument):
            mechanism, _, initial = argument.partition(" ")
            mechanism = mechanism.upper()
            if mechanism == "PLAIN":
                token = initial or continuation("")
                if token == "*":
                    return None
                parts = decode("" if token == "=" else token).split("\0")
                if len(parts) != 3:
                    raise ValueError("PLAIN needs three parts")
                return parts[1], parts[2]
            if mechanism == "LOGIN":
                user = decode(initial or continuation("VXNlcm5hbWU6"))
                return user, decode(continuation("UGFzc3dvcmQ6"))
            return mechanism

        if control.get("implicit_tls"):
            conn.starttls(self.tls)
            state["tls"] = True
        reply("220 maildivvy-stub ESMTP relay")
        while True:
            line = conn.readline()
            if not line:
                return
            verb, argument = self.record(number, line)
            if verb in ("EHLO", "HELO"):
                reset()
                features = ["maildivvy-stub", "8BITMIME", "ENHANCEDSTATUSCODES"]
                features.append("AUTH PLAIN LOGIN" if state["tls"] else "STARTTLS")
                for feature in features[:-1]:
                    reply(f"250-{feature}")
                reply(f"250 {features[-1]}")
            elif verb == "STARTTLS":
                if state["tls"]:
                    reply("503 5.5.1 TLS already active")
                    continue
                reply("220 2.0.0 Ready to start TLS")
                early = conn.starttls(self.tls)
                if early:
                    self.log.write(stub=self.name, session=number, event="discarded",
                                   detail=early.decode("latin-1"))
                state.update(tls=True, user=None)
                reset()
            elif verb == "AUTH":
                if not state["tls"]:
                    reply("530 5.7.0 Must issue a STARTTLS command first")
                elif state["user"] is not None:
                    reply("503 5.5.1 Already authenticated")
                else:
                    try:
                        credential = authenticate(argument)
                    except (binascii.Error, ValueError):
                        reply("501 5.5.2 Cannot decode the response")
                        continue
                    if credential is None:
                        reply("501 5.7.0 Authentication cancelled")
                        continue
                    if isinstance(credential, str):
                        reply(f"504 5.5.4 Unrecognized authentication type {credential}")
                        continue
                    user, password = credential
                    accepted = (not control.get("refuse_auth")
                                and control.get("accounts", {}).get(user) == password)
                    self.log.write(stub=self.name, session=number, event="auth", user=user,
                                   password=password, accepted=accepted)
                    if accepted:
                        state["user"] = user
                        reply("235 2.7.0 Authentication successful")
                    else:
                        reply("535 5.7.8 Authentication credentials invalid")
            elif verb == "MAIL":
                sender = address(argument, "FROM")
                if state["user"] is None:
                    reply("530 5.7.0 Authentication required")
                elif sender is None:
                    reply("501 5.5.4 Syntax: MAIL FROM:<address>")
                else:
                    state["from"], state["to"] = sender, []
                    reply("250 2.1.0 Ok")
            elif verb == "RCPT":
                recipient = address(argument, "TO")
                if state["from"] is None:
                    reply("503 5.5.1 Need MAIL first")
                elif recipient is None:
                    reply("501 5.5.4 Syntax: RCPT TO:<address>")
                else:
                    state["to"].append(recipient)
                    reply("250 2.1.5 Ok")
            elif verb == "DATA":
                if not state["to"]:
                    reply("503 5.5.1 Need RCPT first")
                    continue
                reply("354 End data with <CR><LF>.<CR><LF>")
                data = bytearray()
                while True:
                    line = conn.readline()
                    if not line:
                        return
                    if line in (b".\r\n", b".\n"):
                        break
                    data += line[1:] if line.startswith(b".") else line
                state["queued"] += 1
                self.log.write(stub=self.name, session=number, event="message",
                               auth_user=state["user"], mail_from=state["from"],
                               rcpt_to=state["to"], data=bytes(data).decode("latin-1"))
                reply(f"250 2.0.0 Ok: queued as stub-{number}-{state['queued']}")
                reset()
            elif verb == "RSET":
                reset()
                reply("250 2.0.0 Ok")
            elif verb == "NOOP":
                reply("250 2.0.0 Ok")
            elif verb == "QUIT":
                reply("221 2.0.0 Bye")
                return
            else:
                reply("502 5.5.2 Command not recognized")


if __name__ == "__main__":
    main("Stub provider SMTP relay: STARTTLS, AUTH, messages kept and never delivered.",
         lambda args, **kw: SMTPStub(**kw))
