"""Whether the retrieval a delivery belongs to still waits for it.

⛔ mpop 1.4.23 PIPES A MESSAGE INTO THE DELIVERY FILTER AS IT READS IT, AND WHEN THE
CONNECTION ENDS INSIDE THE BODY IT LEAVES BY ITS ERROR PATH WITHOUT CLOSING THE PIPE
(`pop3_delivery`'s `error_exit` frees the delivery method and never calls `pclose`).
The pipe is closed by mpop's exit, so the filter reads end-of-file on half a message,
which it cannot tell from a whole one, and would store it. mpop records nothing, so the
next run brings the message whole: the archive holds a truncated copy and a whole one,
and the fan-out gives the truncated one to every reader. Measured on the test machine.

On a message read to its end mpop closes the pipe and WAITS for the filter (`pclose`).
That is the difference this module reads. The fetch runner makes a pipe of its own and
hands both ends to mpop, keeping neither; the filter inherits them, closes its copy of
the write end at once, and before it stores anything asks whether the write end is
still held. While mpop waits in `pclose` it is; once mpop has exited nothing holds it,
and the read end reads end-of-file. Nothing is ever written into the pipe.

What makes "nothing else holds it" true: the runner closes both ends after the start,
the filter closes its copy first thing, and the delivery line `exec`s the filter, so no
shell waits between mpop and the filter holding a copy (dash 0.5.12 forks for `sh -c`,
measured). mpop's exit closes all its descriptors in one step, while the filter reaches
the check only after both scanners have answered.
"""

import os
import select
import sys

# The environment variable mpop and everything it starts inherit: "<read> <write>".
VARIABLE = "MAILDIVVY_RETRIEVAL"
# ⛔ The words a delivery the filter could not check is said in:
# the fetch runner carries each such line into its own journal, and health counts them as
# a WARN. The message is still filed: a wiring fault must not cost mail.
UNCHECKED = "retrieval unchecked"


def environment(read, write, base=None):
    """The environment mpop runs with: the caller's, plus the two descriptors' numbers."""
    return {**(os.environ if base is None else base), VARIABLE: f"{read} {write}"}


def watch(environ=None, expected=False):
    """The read end to ask later, with the inherited write end closed; None when this
    process was not started under a retrieval (a filter run by hand, a test).

    `expected`: the fetch started this delivery for a retrieval (`--retrieval` on the
    delivery line), so a pipe that is missing is the wiring broken, and said as such."""
    value = (os.environ if environ is None else environ).get(VARIABLE)
    if not value:
        if expected:
            sys.stderr.write(f"maildivvy: {UNCHECKED}: started for a retrieval with no {VARIABLE}; "
                             "this delivery is not checked against it\n")
        return None
    try:
        read, write = (int(fd) for fd in value.split())
        os.close(write)
        os.fstat(read)
    except (ValueError, OSError) as err:
        # A wiring fault must not cost mail: the message is filed as before and the
        # fault is said, rather than every message refused and in time skipped.
        sys.stderr.write(f"maildivvy: {UNCHECKED}: {VARIABLE}={value!r} is not a retrieval pipe "
                         f"({err}); this delivery is not checked against it\n")
        return None
    return read


def unchecked(text):
    """The lines of a retrieval's output that say a delivery was not checked."""
    return [line.strip() for line in text.splitlines() if UNCHECKED in line]


def waiting(read):
    """True while the retrieval that started this process still waits for it."""
    if read is None:
        return True
    ready, _, _ = select.select([read], [], [], 0)
    # nothing is ever written into the pipe, so readable is end-of-file: nobody holds
    # the write end any more
    return not ready or os.read(read, 1) != b""
