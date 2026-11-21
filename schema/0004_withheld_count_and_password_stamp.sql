-- 0004: the interface's withheld count reads an index, and a password change is stamped
-- at the moment of its UPDATE.
--
-- Both only add or replace a body: an index, and a trigger function with the same
-- signature, which keeps its owner and its trigger. No role is granted anything, and the
-- previous release's programs read and write as before.

-- Every page of the interface counts the withheld messages for its sidebar. Nothing
-- indexed `state`, so each page read the whole of `message`. ⚠️ NOT A NARROWING OF
-- message_withheld_id_idx: a quarantined message whose withheld id could not be read is
-- stored withheld with a NULL id, and a count over that index would miss it.
-- The build holds writes to `message` for its length, about a second at a year's rows;
-- CONCURRENTLY cannot run inside the applier's transaction.
CREATE INDEX message_withheld_idx ON message (id) WHERE state = 'withheld';

-- ⛔ clock_timestamp(), the moment of the UPDATE, not now(), the start of the transaction
-- that makes it. A sign-in that began after a slow password change began, and read the
-- old hash, has a session created at its own start; stamped with now(), the change came
-- before that session, and the session outlived it.
CREATE OR REPLACE FUNCTION account_stamp_password_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
        NEW.password_set_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

SELECT check_grants();
