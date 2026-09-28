# Maildivvy, install step 8: the Sent hook's script, installed with the configuration
# that binds it. Dovecot runs it after an APPEND to the one folder that
# advertises \Sent has committed, and it hands the message to `maildivvy-sent-hook`.
#
# `imapsieve` is what makes the `imap.mailbox` environment item exist at all: without
# it the test below is false, the script still compiles and runs to status=ok, and
# nothing whatever happens.
require ["imapsieve", "environment", "variables", "vnd.dovecot.pipe"];

# The mailbox the append went to, passed to the program as its one argument: a Sieve
# environment item reaches the program only when the script passes it explicitly.
# The hook refuses any mailbox but Sent for itself.
if environment :matches "imap.mailbox" "*" {
  set "mailbox" "${1}";
}

# `pipe`, never `execute`: `execute` gives the program no stdin (`Bad file descriptor`),
# and the hook is handed the message there. The program is looked up in
# `sieve_pipe_bin_dir`.
pipe "maildivvy-sent-hook" ["${mailbox}"];

# ⛔ `pipe` CANCELS THE IMPLICIT KEEP, so without this the sender's own copy is expunged
# by the very hook that is meant to record it. `pipe :copy` is refused on 2.4.2
# (`unknown tagged argument ':copy'`), which is why the keep is a statement of its own.
keep;
