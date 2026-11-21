"""A sign-in throttle, keyed on the client's address and the login.

say the interface reads the client's address from the proxy - the one it
forwards over the unix socket, validated as an address, trusted because of the transport
and never from a header from anywhere else - and feeds it to a login throttle. This is
that throttle: it counts a login's recent attempts from one address, and once there are
too many within the window it turns further attempts away until the window passes. A
success clears the count, so only failures are left in it and an ordinary fumble costs
nothing.

⛔ THE KEY IS (address, login), NOT the address alone: a shared proxy or NAT would put a
whole office behind one address, and one person's typos must not lock out the rest. A
different address, or a different login, has a count of its own.

It is in-process memory: one interface process serves a handful of administrators,
the ban of a published service is fail2ban's on the mail ports,
and the firewall already holds this port to the administrator networks.
A restart clears it, which is the safe direction - it never locks anyone out for longer
than the window.
"""

import collections
import threading
import time

# The chosen limits (recorded as a decision line in the progress log). A brute-force
# attempt from one address against one login is slowed to a crawl; a person who mistypes
# a password a few times is not touched.
WINDOW_SECONDS = 15 * 60
MAX_FAILURES = 10
# ⛔ How many logins one address may have failing at once: past it, a login it has no
# count for yet gets one only if it is an administrator's (`exists`), and any other is
# checked without being kept. Without it one address could flood the store until its own
# count on one login is pushed out.
# ⛔ THE CAP BOUNDS THE STORE, NOT THE PEOPLE. It once turned such a login away outright,
# so a hundred made-up logins from the office's NAT answered every administrator's right
# password with 429 for as long as they kept coming. An administrator's login is now
# turned away only by its own failures; a login nobody signs in with is still checked
# (one refusal for every no, the same work), it can never succeed, and it is not kept.
MAX_LOGINS = 100
# The most (address, login) pairs kept at once, a backstop for many addresses: every key
# is swept once its window has passed, and past this the oldest goes first.
MAX_KEYS = 10_000


class Throttle:
    def __init__(self, window=WINDOW_SECONDS, limit=MAX_FAILURES, logins=MAX_LOGINS,
                 keys=MAX_KEYS, clock=time.monotonic):
        self.window = window
        self.limit = limit
        self.logins = logins
        self.keys = keys
        self.clock = clock
        # (address, login) -> [timestamps], in the order each key was last tried, so the
        # keys whose windows have passed gather at the front, where the sweep reads
        self._failures = {}
        self._per_address = collections.Counter()     # address -> keys it holds
        self._lock = threading.Lock()

    def __len__(self):
        return len(self._failures)

    def attempt(self, address, login, exists=None):
        """Count an attempt BEFORE its password is checked; False when it is turned away.

        ⛔ Counting first is what makes the limit hold under concurrency: requests that
        are all in flight at once cannot each pass the check before any is recorded. A
        right password clears the count again (`record_success`).

        `exists(login)` is asked only once the address holds its cap of logins and this
        one has no count yet: True keeps a count for it past the cap, anything else lets
        the attempt through uncounted, since that login cannot sign in. It is called
        outside the lock, because it may ask the database.
        """
        key = (address or "", login or "")
        known = None
        while True:
            now = self.clock()
            with self._lock:
                self._sweep(now)
                if key in self._failures:
                    recent = [t for t in self._failures.pop(key) if now - t < self.window]
                elif self._per_address[key[0]] < self.logins or known:
                    recent = []
                    self._per_address[key[0]] += 1
                elif known is not None or exists is None:
                    # past the cap, a login nobody signs in with: through, and not kept
                    return known is not None
                else:
                    recent = None
                if recent is not None:
                    # moved to the back even when turned away, so a key under attack is
                    # never the oldest one
                    self._failures[key] = (recent + [now] if len(recent) < self.limit
                                           else recent)
                    return len(recent) < self.limit
            known = bool(exists(key[1]))

    def _sweep(self, now):
        while self._failures:
            key, times = next(iter(self._failures.items()))
            if len(self._failures) < self.keys and now - times[-1] < self.window:
                return
            self._drop(key)

    def _drop(self, key):
        if self._failures.pop(key, None) is not None:
            self._per_address[key[0]] -= 1
            if not self._per_address[key[0]]:
                del self._per_address[key[0]]

    def record_success(self, address, login):
        """A right password clears the count, so only a run of failures ever throttles."""
        with self._lock:
            self._drop((address or "", login or ""))
