"""The submission milter: it binds the From header to the authenticated login and scans.

⛔ THIS PACKAGE IS DELIBERATELY NOT A MODULE CALLED `milter.py`.
pymilter imports a lowercase C extension of that name from inside its own package, so
a top-level module of the same name on the program's path shadows it and the daemon
dies at every start - and under Postfix's fail-closed default that refuses every
submission on the machine. `maildivvy/milter/` is never a top-level name; the modules
in it are named after what they do.

`decision.py` is the whole decision as plain functions, `probe.py` the negotiation that
proves the daemon answers before anything is bound to it, `daemon.py` the
thin pymilter shell, and `run.py` the program's arguments.
"""
