"""The administration interface: sessions, sign-in, the journal and the screens.

It runs as `maildivvy-admin`, reads and writes rows through the `maildivvy_admin`
database role and nothing else, and serves plain HTTP on a unix socket that only the
reverse proxy opens. It reaches no network, touches no file of
the mail store, and deletes no row: every destruction is a request the pipeline
performs.
"""
