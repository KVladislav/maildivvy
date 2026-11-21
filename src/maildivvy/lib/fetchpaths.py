"""Where the fetcher's state and the installed programs are, for every program that needs one.

The fetch runner renders each external mailbox's mpop configuration into its own state
directory and mpop keeps there what it has already retrieved; the request queue removes
that directory with the mailbox, and the backup copies the root. Each reads the layout
here rather than from the renderer.
"""

from pathlib import Path

STATE_DIR = Path("/var/lib/maildivvy/fetch")
BINDIR = Path("/opt/maildivvy/bin")


def state_dir(root, mailbox_id):
    """One external mailbox's state directory under `root`, named by its row's id."""
    return Path(root) / str(mailbox_id)
