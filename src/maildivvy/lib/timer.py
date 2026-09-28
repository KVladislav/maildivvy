"""How often the pipeline runs, read off the installed fetch timer.

The administration interface says when the next collection is due, and health judges
whether collection has stopped; both read the period here, from
the unit the machine actually runs, never from a constant.
"""

import re
from datetime import timedelta
from pathlib import Path

FETCH_TIMER = "/etc/systemd/system/maildivvy-fetch.timer"

EVERY_MINUTES = re.compile(r"^\*:0/(\d+)$")
EVERY_SECONDS = re.compile(r"^\*:\*:0/(\d+)$")


def timer_period(path=FETCH_TIMER):
    """The fetch timer's period from its `OnCalendar`, or None when it cannot be read.

    ⚠️ None is a sentence on the screen, never a guess. The
    source wrote "3 minutes" as a constant beside a timer nothing held it to, so an
    operator who changed the cadence got a screen quietly lying about it. This is read
    from the unit the machine actually runs.
    """
    try:
        text = Path(path).read_text()
    except OSError:
        return None
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if not sep or name.strip() != "OnCalendar":
            continue
        spec = value.strip()
        minutes = EVERY_MINUTES.match(spec)
        if minutes:
            return timedelta(minutes=int(minutes.group(1)))
        seconds = EVERY_SECONDS.match(spec)
        if seconds:
            return timedelta(seconds=int(seconds.group(1)))
        if spec == "hourly":
            return timedelta(hours=1)
        if spec == "minutely":
            return timedelta(minutes=1)
    return None
