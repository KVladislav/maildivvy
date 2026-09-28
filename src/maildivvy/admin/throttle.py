"""A sign-in throttle, keyed on the client's address and the login.

say the interface reads the client's address from the proxy - the one it
forwards over the unix socket, validated as an address, trusted because of the transport
and never from a header from anywhere else - and feeds it to a login throttle. This is
that throttle: it counts a login's recent FAILURES from one address, and once there are
too many within the window it turns further attempts away until the window passes. A
success clears the count, so an ordinary fumble costs nothing.

⛔ THE KEY IS (address, login), NOT the address alone: a shared proxy or NAT would put a
whole office behind one address, and one person's typos must not lock out the rest. A
different address, or a different login, has a count of its own.

It is in-process memory: one interface process serves a handful of administrators,
the ban of a published service is fail2ban's on the mail ports,
and the firewall already holds this port to the administrator networks.
A restart clears it, which is the safe direction - it never locks anyone out for longer
than the window.
"""

import threading
import time

# The chosen limits (recorded as a decision line in the progress log). A brute-force
# attempt from one address against one login is slowed to a crawl; a person who mistypes
# a password a few times is not touched.
WINDOW_SECONDS = 15 * 60
MAX_FAILURES = 10


class Throttle:
    def __init__(self, window=WINDOW_SECONDS, limit=MAX_FAILURES, clock=time.monotonic):
        self.window = window
        self.limit = limit
        self.clock = clock
        self._failures = {}                 # (address, login) -> [timestamps within the window]
        self._lock = threading.Lock()

    def _recent(self, key, now):
        return [t for t in self._failures.get(key, []) if now - t < self.window]

    def blocked(self, address, login):
        """True when this address has failed this login too many times lately."""
        now = self.clock()
        key = (address or "", login or "")
        with self._lock:
            recent = self._recent(key, now)
            self._failures[key] = recent
            return len(recent) >= self.limit

    def record_failure(self, address, login):
        now = self.clock()
        key = (address or "", login or "")
        with self._lock:
            recent = self._recent(key, now)
            recent.append(now)
            self._failures[key] = recent

    def record_success(self, address, login):
        """A right password clears the count, so only a run of failures ever throttles."""
        with self._lock:
            self._failures.pop((address or "", login or ""), None)
