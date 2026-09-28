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
