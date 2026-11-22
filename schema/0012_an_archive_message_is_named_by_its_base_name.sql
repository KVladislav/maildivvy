-- 0012: an archive message is named by its file's base name, and the cursor by its file's
-- too (`0100`).
--
-- The ledger named a message of a domain archive's INBOX or quarantine by its Dovecot
-- UID, a number Dovecot gives again when a folder loses its `dovecot-uidlist` or its
-- index. The file's base name (Dovecot's storage id) never changes and is the name of
-- every hardlink into a person's mailbox: it is the key now, and the UID the pass's
-- cursor and a cache the pass keeps right.
--
-- 1. `message.archive_base`, unique per domain where set. The pass writes it from the
--    storage id it reads already; a row written before this migration gains it on its
--    folder's first tick under the new pass, from one listing of the folder by UID, while
--    the numbering still holds. The rows of the archive's `Sent/<account>` (the Sent hook,
--    the import's `sent`) keep none, as they keep no UID: the same imported bytes may be
--    both an incoming and a sent file under one name.
-- 2. An index on the rows still waiting for it: the tick asks every minute whether its
--    folder has any, and the index is empty once each folder's first tick is done.
-- 3. `pass_cursor.last_base`, the base name of the file at `last_uid`: a folder whose
--    UID at the cursor names another file than the one the cursor was moved to was
--    numbered again, also under the same UIDVALIDITY with that UID still there.
--
-- Nullable, with no default. The pipeline's grants on `message` and `pass_cursor` are
-- table-level and cover the columns; the interface's SELECT on `message` is table-wide;
-- health and the Sent hook hold no grant on either column and need none.
--
-- previous release: its pass never names either column, and the upgrade stops it from
-- before the migrations until the new programs are in place. Run again after the
-- upgrade's way back, it writes rows with no base and moves the cursor without its base:
-- the new pass, back, gives those rows their names first, by UID, before it reads the
-- cursor's base, so neither is taken for a renumbering.

ALTER TABLE message ADD COLUMN archive_base text
    CHECK (archive_base ~ '^[^/:]{1,255}$');
COMMENT ON COLUMN message.archive_base IS
$$The archive file's base name (Dovecot's storage id), the message's durable key; NULL for a
message of the archive's Sent folders, and until the pass's first tick of its folder.$$;

CREATE UNIQUE INDEX message_archive_base_idx
    ON message (domain_id, archive_base) WHERE archive_base IS NOT NULL;
CREATE INDEX message_unnamed_idx
    ON message (domain_id, (state = 'delivered')) WHERE archive_uid IS NOT NULL AND archive_base IS NULL;

ALTER TABLE pass_cursor ADD COLUMN last_base text
    CHECK (last_base ~ '^[^/:]{1,255}$');

SELECT check_grants();
