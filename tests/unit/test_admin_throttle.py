"""The sign-in throttle: keyed on the client address and the login."""

from maildivvy.admin.throttle import MAX_FAILURES, Throttle


def test_a_login_is_throttled_after_its_limit_of_failures_from_one_address():
    now = [0.0]
    throttle = Throttle(window=900, limit=3, clock=lambda: now[0])
    for _ in range(3):
        assert not throttle.blocked("192.0.2.1", "ivan")
        throttle.record_failure("192.0.2.1", "ivan")
    assert throttle.blocked("192.0.2.1", "ivan")
    # the key is (address, login): a different address, or a different login, is untouched
    assert not throttle.blocked("192.0.2.2", "ivan")
    assert not throttle.blocked("192.0.2.1", "olga")


def test_a_right_password_clears_the_count_so_an_ordinary_fumble_costs_nothing():
    throttle = Throttle(window=900, limit=3, clock=lambda: 0.0)
    for _ in range(3):
        throttle.record_failure("192.0.2.1", "ivan")
    assert throttle.blocked("192.0.2.1", "ivan")
    throttle.record_success("192.0.2.1", "ivan")
    assert not throttle.blocked("192.0.2.1", "ivan")


def test_failures_fall_out_of_the_window():
    now = [0.0]
    throttle = Throttle(window=100, limit=3, clock=lambda: now[0])
    for _ in range(3):
        throttle.record_failure("192.0.2.1", "ivan")
    assert throttle.blocked("192.0.2.1", "ivan")
    now[0] = 101                                       # the window has passed
    assert not throttle.blocked("192.0.2.1", "ivan")


def test_the_chosen_limits_are_the_ones_recorded():
    # the decision line in the progress log: 10 failures in a 15-minute window
    from maildivvy.admin.throttle import WINDOW_SECONDS
    assert (MAX_FAILURES, WINDOW_SECONDS) == (10, 15 * 60)
