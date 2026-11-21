"""The sign-in throttle: keyed on the client address and the login."""

import threading

from flask import Flask

from maildivvy.admin import app as application
from maildivvy.admin import auth
from maildivvy.admin.throttle import MAX_FAILURES, MAX_LOGINS, Throttle


def test_a_login_is_throttled_after_its_limit_of_failures_from_one_address():
    now = [0.0]
    throttle = Throttle(window=900, limit=3, clock=lambda: now[0])
    for _ in range(3):
        assert throttle.attempt("192.0.2.1", "ivan")
    assert not throttle.attempt("192.0.2.1", "ivan")
    # the key is (address, login): a different address, or a different login, is untouched
    assert throttle.attempt("192.0.2.2", "ivan")
    assert throttle.attempt("192.0.2.1", "olga")


def test_a_right_password_clears_the_count_so_an_ordinary_fumble_costs_nothing():
    throttle = Throttle(window=900, limit=3, clock=lambda: 0.0)
    for _ in range(3):
        throttle.attempt("192.0.2.1", "ivan")
    assert not throttle.attempt("192.0.2.1", "ivan")
    throttle.record_success("192.0.2.1", "ivan")
    assert throttle.attempt("192.0.2.1", "ivan")


def test_failures_fall_out_of_the_window():
    now = [0.0]
    throttle = Throttle(window=100, limit=3, clock=lambda: now[0])
    for _ in range(3):
        throttle.attempt("192.0.2.1", "ivan")
    assert not throttle.attempt("192.0.2.1", "ivan")
    now[0] = 101                                       # the window has passed
    assert throttle.attempt("192.0.2.1", "ivan")


def test_the_chosen_limits_are_the_ones_recorded():
    # the decision line in the progress log: 10 failures in a 15-minute window
    from maildivvy.admin.throttle import WINDOW_SECONDS
    assert (MAX_FAILURES, WINDOW_SECONDS) == (10, 15 * 60)


# --- the throttle's own size --------------------------------------------------------------

def test_logins_tried_once_leave_nothing_behind_once_their_window_has_passed():
    now = [0.0]
    throttle = Throttle(window=100, limit=3, clock=lambda: now[0])
    for n in range(1000):
        throttle.attempt(f"192.0.2.{n % 250}", f"guess{n}")
    assert len(throttle) == 1000
    now[0] = 101
    throttle.attempt("192.0.2.1", "ivan")
    assert len(throttle) == 1                         # only the attempt just made


def test_the_number_of_keys_is_capped_and_the_oldest_go_first():
    now = [0.0]
    throttle = Throttle(window=900, limit=3, keys=5, clock=lambda: now[0])
    for n in range(20):
        now[0] = n
        throttle.attempt("192.0.2.1", f"guess{n}")
    assert len(throttle) == 5
    for _ in range(2):                                 # guess19 is kept, with its count
        throttle.attempt("192.0.2.1", "guess19")
    assert not throttle.attempt("192.0.2.1", "guess19")


def test_one_address_has_a_bounded_number_of_logins_failing_at_once():
    now = [0.0]
    throttle = Throttle(window=100, limit=3, logins=4, clock=lambda: now[0])
    for n in range(4):
        assert throttle.attempt("192.0.2.1", f"guess{n}")
    assert not throttle.attempt("192.0.2.1", "guess4")    # one more login is turned away
    assert throttle.attempt("192.0.2.1", "guess0")        # a login it has a count for is not
    assert throttle.attempt("192.0.2.2", "guess4")        # nor is another address
    throttle.record_success("192.0.2.1", "guess1")
    assert throttle.attempt("192.0.2.1", "guess4")        # a success frees its place
    now[0] = 101
    assert throttle.attempt("192.0.2.1", "guess5")        # and so does the window


def test_a_flood_of_other_logins_never_pushes_out_a_blocked_count():
    now = [0.0]
    throttle = Throttle(window=900, limit=3, clock=lambda: now[0])
    for _ in range(3):
        throttle.attempt("192.0.2.1", "ivan")
    for n in range(20_000):                            # twice the store's own bound
        now[0] = n / 100
        throttle.attempt("192.0.2.1", f"guess{n}")
    assert not throttle.attempt("192.0.2.1", "ivan")


def test_a_parallel_burst_gets_no_more_guesses_than_the_limit():
    # the attempt is counted before the password is checked, so requests that are all in
    # flight at once cannot all pass the check before any of them is recorded
    throttle = Throttle(window=900, limit=MAX_FAILURES)
    start = threading.Barrier(30)
    let_in = []

    def guess():
        start.wait()
        let_in.append(throttle.attempt("192.0.2.1", "ivan"))

    threads = [threading.Thread(target=guess) for _ in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert let_in.count(True) == MAX_FAILURES


# --- the route ----------------------------------------------------------------------------

def test_a_login_no_account_could_have_is_refused_before_it_costs_anything(monkeypatch):
    made = Flask("maildivvy-test")
    application.register(made)
    application.guard_every_endpoint(made)
    store = Throttle()
    made.config.update(MAILDIVVY_SECRET="x" * 32, MAILDIVVY_THROTTLE=store)

    def touched(*_args, **_kwargs):
        raise AssertionError("a login no account could have reached the database or a hash")

    monkeypatch.setattr(application, "connection", touched)
    monkeypatch.setattr(auth, "sha512_crypt", touched)
    client = made.test_client()
    for login in ("a" * 400_000, "x" * 65, "-ivan", "ivan smith"):
        answer = client.post("/sign-in", data={"login": login, "password": "wrong"})
        assert answer.status_code == 200 and auth.REFUSAL in answer.get_data(as_text=True)
    assert len(store) == 0                             # and none of them was kept as a key


def test_past_the_addresss_cap_an_administrators_login_is_still_tried_and_still_counted():
    throttle = Throttle(window=900, limit=3, logins=4, clock=lambda: 0.0)
    asked = []

    def exists(login):
        asked.append(login)
        return login in ("admin", "break-glass")

    for n in range(4):
        assert throttle.attempt("192.0.2.1", f"guess{n}", exists=exists)
    assert asked == []                                 # nothing is asked below the cap
    # the cap is full: the administrator's login gets a count of its own past it ...
    for _ in range(3):
        assert throttle.attempt("192.0.2.1", "admin", exists=exists)
    assert not throttle.attempt("192.0.2.1", "admin", exists=exists)   # ... and its limit
    assert throttle.attempt("192.0.2.1", "break-glass", exists=exists)
    # a login nobody signs in with is let through to its refusal, and not kept
    kept = len(throttle)
    for _ in range(20):
        assert throttle.attempt("192.0.2.1", "guess-more", exists=exists)
    assert len(throttle) == kept
    assert asked.count("admin") == 1                   # asked once, while it had no count


def test_a_flood_of_made_up_logins_from_the_office_leaves_the_administrators_sign_in(
        app_db, ids, database):
    from admin_db import ADMIN, Browser

    browser = Browser(app_db)
    for n in range(MAX_LOGINS + 5):
        browser.sign_in(f"made-up-{n}", "wrong")
    answer = browser.sign_in()
    assert answer.status_code == 303 and answer.headers["Location"] == "/"
    assert browser.get("/").status_code == 200
    # the administrator's own failures still throttle it
    other = Browser(app_db)
    for _ in range(MAX_FAILURES):
        assert other.sign_in(ADMIN, "wrong").status_code == 200
    assert other.sign_in().status_code == 429

