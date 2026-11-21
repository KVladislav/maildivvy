-- 0006: a store that cannot take mail is a fetch cause of its own.
--
-- The delivery filter exits 73 when its probe finds the archive's store full, read-only
-- or Dovecot not answering, and the fetch runner holds collection on it with the cause
-- `store` rather than counting it against the message. `last_fetch_cause` is a closed
-- list, so its CHECK is dropped and added again with the new value, in
-- the order of reading: what the runner decides from the delivery's own status comes
-- before what it reads from mpop's words. No column, table or grant changes.
--
-- previous release: the constraint accepts every value it accepted before and one more,
-- so the rows already there pass it and every value the previous release's runner
-- writes is still accepted. That runner never writes `store`: an upgrade pauses
-- collection from before the migrations until the new programs are in place, and keeps
-- it paused when it fails in between. The previous release's fetch screen names a cause
-- it does not know as itself, and its health prints the cause as it reads it.

ALTER TABLE external_mailbox
    DROP CONSTRAINT external_mailbox_last_fetch_cause_check,
    ADD CONSTRAINT external_mailbox_last_fetch_cause_check CHECK (last_fetch_cause IN
        ('unrecorded', 'timeout', 'stuck_message', 'store', 'unreachable', 'transient'));

SELECT check_grants();
