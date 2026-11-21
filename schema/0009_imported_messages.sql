-- 0009: a message imported from a directory of message files keeps the moment of its
-- import beside the moment it arrived in the old store.
--
-- An imported row's `received_at` is the moment the message arrived where it was kept
-- before, so a top-up selects history by its date; `imported_at` is the real moment of
-- the insert, `clock_timestamp()` as the pass gives it, NULL for every row that was not
-- imported. `received_at` keeps its default for every other writer.
--
-- Nullable, with no default, so nothing else changes. The pipeline's INSERT and UPDATE on
-- `message` and the interface's SELECT are table-wide and cover the new column; the Sent
-- hook's column-level SELECT does not name it and does not need to, and health holds no
-- grant on `message`. The previous release's programs never name the column, so they
-- run on as they did.

ALTER TABLE message ADD COLUMN imported_at timestamptz;

COMMENT ON COLUMN message.imported_at IS
$$The moment an imported message was recorded; NULL for one that was not imported, whose
received_at is that moment.$$;

SELECT check_grants();
