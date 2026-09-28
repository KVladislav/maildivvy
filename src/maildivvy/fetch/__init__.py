"""The fetch runner: one mpop per external mailbox, and what it records.

`render` writes the client's configuration, `outcome` reads its exit code and its own
lines, `state` reads and writes mpop's UIDL file, `locks` is the namespace the fetch
and a deletion share, and `runner` drives them. `credential` is the helper mpop runs
on a pipe.
"""
