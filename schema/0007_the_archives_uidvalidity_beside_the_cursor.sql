-- 0007: the archive folder's UIDVALIDITY is kept beside the cursor.
--
-- The ledger names an archive message by its UID (`message.archive_uid`, the cursor's
-- `last_uid`), and a UID names one file only while the folder's UIDVALIDITY stays what it
-- was. The pass writes the value when it first reads a folder whose row holds none, and
-- every tick, and every request that links by UID, compares it with Dovecot's and asks
-- that the cursor's own UID is still there: either changed stops them with nothing linked.
--
-- Nullable, with no default: a row made before this migration holds none until the pass's
-- next tick of its folder fills it. The pipeline's grant on `pass_cursor` is table-level,
-- so it covers the new column, and health holds no grant on the table and is given none.
-- The previous release's pass names its columns and never this one, so it runs on as it did.

ALTER TABLE pass_cursor ADD COLUMN uidvalidity bigint CHECK (uidvalidity > 0);

SELECT check_grants();
