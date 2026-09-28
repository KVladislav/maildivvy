"""`maildivvy-health`: one command that reports every subsystem in detail.

The product runs its own checks and exports the result for the operator's monitoring;
it pushes nothing. Each check is PASS, WARN, FAIL or UNKNOWN; a subsystem takes
its worst check and the whole takes its worst subsystem, with FAIL above UNKNOWN, so a
reading that could not be taken never hides a problem already found. UNKNOWN is never PASS.

- `report.py`: the states, the text, the JSON file and the plugin exit code;
- `checks.py` and the modules it names: the fifteen subsystems;
- `helper.py`: the readings that need the mail owner (the store, the fetch state) or
  root (the firewall, the ban, the milter's socket, the scanner's container), taken by
  a socket-activated helper and handed back as JSON;
- `upstream.py`: the scanners' upstream releases, asked at most every few hours;
- `run.py`: the command.

A check names what it read, never a credential or a message's content.
"""
