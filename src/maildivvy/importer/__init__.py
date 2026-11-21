"""The import of a directory of message files.

`source` reads the directory, or a manifest of it, into checked records and judges each
against what the target already holds; `result` writes one line per file and the totals.
`incoming` files records into a domain archive's INBOX for the pass to record, `sent`
into a person's Sent and the archive's `Sent/<account>`, and `run` is the command.
"""
