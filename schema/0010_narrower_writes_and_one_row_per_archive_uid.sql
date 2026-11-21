-- 0010: the interface writes only what its screens write, and the ledger holds one row
-- per archive message.
--
-- Three narrowings of what was granted or allowed and never used:
--
-- 1. One row per (domain, archive folder, UID). The folder is the row's state: a
--    `delivered` row's UID counts in INBOX, any other's in the quarantine, and
--    no state changes across that line (`release` turns `withheld` into `released`).
--    Until now only the pass's cursor kept a UID from being recorded twice; the unique
--    index keeps it, and is the index the ledger's lookups by UID read.
-- 2. `maildivvy_admin` writes the queue, the journal and its sessions column by column:
--    a request is asked for (kind, target, payload, who asked, break-glass), never given
--    a state, a result or a moment; a journal row never a moment; a session is opened
--    and its last-seen time moved, nothing else. It no longer updates an external
--    mailbox's address, which no screen changes, and of its state it may only set
--    `deactivated`: activation is a request the pipeline performs after the provider
--    check (a trigger, since a grant cannot name a value).
-- 3. No request row is inserted carrying `payload.gone`. That key is the list of
--    directories a deletion still has to remove: the pipeline writes it on its
--    own row with UPDATE and removes what it names, as the mail owner. The pipeline never
--    inserts a request, so the key can only ever be its own.
--
-- previous release: every write the 0.2 interface makes is one these grants keep
-- (`INSERT INTO request (kind, target, payload, asked_by, break_glass)`, the journal's
-- six columns, a session's three and its `last_seen_at`, `state = 'deactivated'`), and it
-- never names `gone`. Its pass and requests are stopped by the upgrade from before the
-- migrations until the new programs are in place, so its `--renumber`, which gives a
-- folder's rows their new numbers one at a time, never runs against the unique index.
-- The index fails this migration, naming the duplicates, on a ledger that holds a UID
-- twice already; nothing in either release writes one.

DO $$
DECLARE
    twice text;
BEGIN
    SELECT string_agg(format('domain %s %s UID %s (%s rows)', domain_id,
                             CASE WHEN inbox THEN 'INBOX' ELSE 'Quarantine' END, archive_uid, n), '; ')
      INTO twice
      FROM (SELECT domain_id, state = 'delivered' AS inbox, archive_uid, count(*) AS n
              FROM message WHERE archive_uid IS NOT NULL
             GROUP BY 1, 2, 3 HAVING count(*) > 1 ORDER BY 1, 2, 3 LIMIT 20) AS d;
    IF twice IS NOT NULL THEN
        RAISE EXCEPTION 'the ledger records an archive UID twice: %', twice
            USING HINT = 'each archive message has one row; remove the extra rows before upgrading';
    END IF;
END $$;

CREATE UNIQUE INDEX message_archive_uid_idx
    ON message (domain_id, (state = 'delivered'), archive_uid) WHERE archive_uid IS NOT NULL;

REVOKE INSERT ON request, audit FROM maildivvy_admin;
REVOKE INSERT, UPDATE ON session FROM maildivvy_admin;
REVOKE UPDATE (address, address_canonical) ON external_mailbox FROM maildivvy_admin;
GRANT INSERT (kind, target, payload, asked_by, break_glass) ON request TO maildivvy_admin;
GRANT INSERT (actor, action, target, detail, break_glass, request_id) ON audit TO maildivvy_admin;
GRANT INSERT (token_hash, account_id, break_glass), UPDATE (last_seen_at) ON session TO maildivvy_admin;

-- ⛔ THE INTERFACE TURNS AN EXTERNAL MAILBOX OFF, NEVER ON. `active` is set by the
-- pipeline's `activate_external_mailbox` once the provider answered and a backup exists;
-- an UPDATE as the interface's role that sets it is refused, whatever its form or path.
CREATE FUNCTION external_mailbox_the_interface_only_deactivates() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state AND NEW.state <> 'deactivated'
       AND current_user = 'maildivvy_admin' THEN
        RAISE EXCEPTION 'the interface may only deactivate an external mailbox; activation is a request';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION external_mailbox_the_interface_only_deactivates() FROM PUBLIC;

CREATE TRIGGER external_mailbox_the_interface_only_deactivates
    BEFORE UPDATE OF state ON external_mailbox
    FOR EACH ROW EXECUTE FUNCTION external_mailbox_the_interface_only_deactivates();

-- ⛔ `gone` IS THE PIPELINE'S, WRITTEN BY UPDATE ON ITS OWN ROW. A row inserted with it,
-- by any role, would have the drain end sessions and remove the directories it names.
CREATE FUNCTION request_is_never_inserted_with_gone() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.payload ? 'gone' THEN
        RAISE EXCEPTION 'a request is never inserted with a gone list: it is the pipeline''s, written on its own row';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION request_is_never_inserted_with_gone() FROM PUBLIC;

CREATE TRIGGER request_is_never_inserted_with_gone
    BEFORE INSERT ON request
    FOR EACH ROW EXECUTE FUNCTION request_is_never_inserted_with_gone();

-- The grants read back, as 0008 left the function, and the interface's new column lists
-- and the two triggers with them.
CREATE OR REPLACE FUNCTION check_grants() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    wrong text[] := '{}';
    col text;
    who text;
    act text;
    rel record;
    pipeline_writes text[] := ARRAY['state', 'state_changed_at', 'state_changed_by', 'last_fetch_at',
        'last_fetch_status', 'last_fetch_cause', 'last_fetch_detail', 'last_test_at', 'last_test_status',
        'last_test_detail', 'stuck_since', 'stuck_runs', 'skip_streak', 'frozen_since', 'last_listing_at',
        'last_skip_at', 'last_skip_uidl', 'held_since', 'imap_uidvalidity', 'imap_last_uid',
        'snapshot_started_at', 'snapshot_finished_at', 'snapshot_status', 'snapshot_detail',
        'snapshot_paused_since', 'snapshot_refused', 'snapshot_left_out'];
    admin_writes text[] := ARRAY['state', 'state_changed_at', 'state_changed_by', 'frozen_since', 'skip_streak',
        'protocol', 'snapshot_requested_at'];
    views jsonb := '{"maildivvy_dovecot": ["mailbox_opens"],
                     "maildivvy_postfix": ["postfix_sender_login", "postfix_sasl_password", "postfix_generic",
                                           "postfix_transport", "postfix_relayhost", "postfix_tls_policy"],
                     "maildivvy_milter": ["milter_sender"]}';
    may boolean;
BEGIN
    -- every column external_mailbox has now: the interface and health read all but the
    -- credential; the pipeline reads it all
    FOR col IN SELECT attname FROM pg_attribute
               WHERE attrelid = 'external_mailbox'::regclass AND attnum > 0 AND NOT attisdropped LOOP
        FOREACH who IN ARRAY ARRAY['maildivvy_admin', 'maildivvy_health'] LOOP
            IF has_column_privilege(who, 'external_mailbox', col, 'SELECT') <> (col <> 'credential') THEN
                wrong := wrong || format('%s %s SELECT external_mailbox.%s', who,
                                         CASE WHEN col = 'credential' THEN 'can' ELSE 'cannot' END, col);
            END IF;
        END LOOP;
        IF NOT has_column_privilege('maildivvy_pipeline', 'external_mailbox', col, 'SELECT') THEN
            wrong := wrong || format('maildivvy_pipeline cannot SELECT external_mailbox.%s', col);
        END IF;
    END LOOP;
    FOREACH act IN ARRAY ARRAY['INSERT', 'UPDATE'] LOOP
        IF NOT has_column_privilege('maildivvy_admin', 'external_mailbox', 'credential', act) THEN
            wrong := wrong || format('maildivvy_admin cannot %s external_mailbox.credential', act);
        END IF;
    END LOOP;
    -- the fetch columns are the pipeline's; the interface clears two and no counter;
    -- the protocol and the snapshot's request are the interface's alone
    FOR col IN SELECT DISTINCT unnest(pipeline_writes || admin_writes) LOOP
        may := col = ANY (pipeline_writes);
        IF has_column_privilege('maildivvy_pipeline', 'external_mailbox', col, 'UPDATE') <> may THEN
            wrong := wrong || format('maildivvy_pipeline %s UPDATE external_mailbox.%s',
                                     CASE WHEN may THEN 'cannot' ELSE 'can' END, col);
        END IF;
        may := col = ANY (admin_writes);
        IF has_column_privilege('maildivvy_admin', 'external_mailbox', col, 'UPDATE') <> may THEN
            wrong := wrong || format('maildivvy_admin %s UPDATE external_mailbox.%s',
                                     CASE WHEN may THEN 'cannot' ELSE 'can' END, col);
        END IF;
    END LOOP;
    FOR rel IN SELECT c.oid, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v') ORDER BY c.relname LOOP
        -- the interface deletes nothing; health writes nothing
        IF has_table_privilege('maildivvy_admin', rel.oid, 'DELETE, TRUNCATE') THEN
            wrong := wrong || format('maildivvy_admin DELETE %s', rel.relname);
        END IF;
        FOREACH act IN ARRAY ARRAY['INSERT', 'UPDATE', 'DELETE'] LOOP
            IF has_table_privilege('maildivvy_health', rel.oid, act)
                    OR (act <> 'DELETE' AND has_any_column_privilege('maildivvy_health', rel.oid, act)) THEN
                wrong := wrong || format('maildivvy_health %s %s', act, rel.relname);
            END IF;
        END LOOP;
        -- the daemons and the milter: their own views, and no table or other view
        FOR who IN SELECT jsonb_object_keys(views) LOOP
            may := (views -> who) ? rel.relname;
            IF has_any_column_privilege(who, rel.oid, 'SELECT') <> may THEN
                wrong := wrong || format('%s %s %s', who, CASE WHEN may THEN 'cannot read' ELSE 'reads' END,
                                         rel.relname);
            END IF;
            IF has_any_column_privilege(who, rel.oid, 'INSERT, UPDATE, REFERENCES')
                    OR has_table_privilege(who, rel.oid, 'DELETE, TRUNCATE, TRIGGER') THEN
                wrong := wrong || format('%s writes %s', who, rel.relname);
            END IF;
        END LOOP;
    END LOOP;
    -- the queue and the journal: the interface reads them and never changes either
    FOREACH col IN ARRAY ARRAY['request', 'audit'] LOOP
        IF NOT has_table_privilege('maildivvy_admin', col, 'SELECT') THEN
            wrong := wrong || format('maildivvy_admin cannot SELECT %s', col);
        END IF;
        IF has_table_privilege('maildivvy_admin', col, 'UPDATE') THEN
            wrong := wrong || format('maildivvy_admin UPDATE %s', col);
        END IF;
    END LOOP;
    IF NOT has_table_privilege('maildivvy_pipeline', 'mailbox_receives', 'SELECT') THEN
        wrong := wrong || 'maildivvy_pipeline cannot SELECT mailbox_receives'::text;
    END IF;
    -- the only removal the interface has: two functions of the owner's, over session
    -- rows alone, executable by the interface and by nobody else
    IF EXISTS (SELECT 1 FROM pg_proc p
                WHERE p.proname IN ('end_session', 'expire_sessions')
                  AND (NOT p.prosecdef OR p.proowner <> 'maildivvy_owner'::regrole)) THEN
        wrong := wrong || 'end_session and expire_sessions must be SECURITY DEFINER, owned by maildivvy_owner'::text;
    END IF;
    -- ⛔ the definer functions pin search_path with pg_temp LAST, or a caller's temporary
    -- schema shadows public and the function runs the caller's code as the owner
    FOR who IN SELECT proname FROM pg_proc WHERE proname IN ('end_session', 'expire_sessions') LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_proc p
                        WHERE p.proname = who
                          AND 'search_path=pg_catalog, public, pg_temp' = ANY (p.proconfig)) THEN
            wrong := wrong || format('%s must SET search_path = pg_catalog, public, pg_temp', who);
        END IF;
    END LOOP;
    -- ⛔ and no caller may make such a temporary table at all
    IF has_database_privilege('public', current_database(), 'TEMP') THEN
        wrong := wrong || 'TEMPORARY on the database must be revoked from PUBLIC'::text;
    END IF;
    FOREACH act IN ARRAY ARRAY['end_session(text)', 'expire_sessions()'] LOOP
        IF NOT has_function_privilege('maildivvy_admin', act, 'EXECUTE') THEN
            wrong := wrong || format('maildivvy_admin cannot EXECUTE %s', act);
        END IF;
        FOREACH who IN ARRAY ARRAY['public', 'maildivvy_pipeline', 'maildivvy_senthook',
                                   'maildivvy_health', 'maildivvy_milter', 'maildivvy_dovecot',
                                   'maildivvy_postfix'] LOOP
            IF has_function_privilege(who, act, 'EXECUTE') THEN
                wrong := wrong || format('%s can EXECUTE %s', who, act);
            END IF;
        END LOOP;
    END LOOP;
    -- The narrowed grants. The interface writes settings, not a domain's label
    -- or a person's login; neither the pipeline nor health reads a password hash; the Sent
    -- hook has a role that only names a message.
    IF has_column_privilege('maildivvy_admin', 'domain', 'label', 'UPDATE') THEN
        wrong := wrong || 'maildivvy_admin can UPDATE domain.label'::text;
    END IF;
    IF has_column_privilege('maildivvy_admin', 'account', 'login', 'UPDATE') THEN
        wrong := wrong || 'maildivvy_admin can UPDATE account.login'::text;
    END IF;
    -- Health reads what its checks read and nothing of the mail
    FOREACH col IN ARRAY ARRAY['message', 'delivery', 'mailbox', 'audit', 'pass_cursor', 'session',
                               'break_glass'] LOOP
        IF has_any_column_privilege('maildivvy_health', col, 'SELECT') THEN
            wrong := wrong || format('maildivvy_health reads %s', col);
        END IF;
    END LOOP;
    IF has_column_privilege('maildivvy_health', 'account', 'comment', 'SELECT') THEN
        wrong := wrong || 'maildivvy_health can SELECT account.comment'::text;
    END IF;
    IF NOT (has_table_privilege('maildivvy_health', 'request', 'SELECT')
            AND has_table_privilege('maildivvy_health', 'schema_version', 'SELECT')
            AND has_column_privilege('maildivvy_health', 'domain', 'label', 'SELECT')
            AND has_column_privilege('maildivvy_health', 'domain', 'external_mailbox_id', 'SELECT')) THEN
        wrong := wrong || 'maildivvy_health must read request, schema_version, domain.label and domain.external_mailbox_id'::text;
    END IF;
    FOREACH who IN ARRAY ARRAY['maildivvy_pipeline', 'maildivvy_health'] LOOP
        IF has_column_privilege(who, 'account', 'password_hash', 'SELECT') THEN
            wrong := wrong || format('%s can SELECT account.password_hash', who);
        END IF;
        IF has_column_privilege(who, 'domain', 'archive_password_hash', 'SELECT') THEN
            wrong := wrong || format('%s can SELECT domain.archive_password_hash', who);
        END IF;
    END LOOP;
    IF NOT (has_column_privilege('maildivvy_senthook', 'domain', 'label', 'SELECT')
            AND has_column_privilege('maildivvy_senthook', 'account', 'login', 'SELECT')
            AND has_column_privilege('maildivvy_senthook', 'mailbox', 'id', 'SELECT')
            AND has_table_privilege('maildivvy_senthook', 'message', 'INSERT')
            AND has_column_privilege('maildivvy_senthook', 'message', 'id', 'SELECT')
            AND has_table_privilege('maildivvy_senthook', 'delivery', 'INSERT')
            AND has_column_privilege('maildivvy_senthook', 'delivery', 'message_id', 'SELECT')) THEN
        wrong := wrong || 'maildivvy_senthook must read domain/account/mailbox and INSERT message and delivery'::text;
    END IF;
    IF has_any_column_privilege('maildivvy_senthook', 'external_mailbox'::regclass, 'SELECT, INSERT, UPDATE')
       OR has_column_privilege('maildivvy_senthook', 'account', 'password_hash', 'SELECT')
       OR has_table_privilege('maildivvy_senthook', 'account', 'DELETE')
       OR has_table_privilege('maildivvy_senthook', 'request', 'SELECT, INSERT')
       OR has_table_privilege('maildivvy_senthook', 'audit', 'INSERT') THEN
        wrong := wrong || 'maildivvy_senthook must not touch the credential, the hash, DELETE, or the queue and journal'::text;
    END IF;

    -- The interface's writes on the queue, the journal and its sessions are the columns
    -- its screens write, and nothing on an external mailbox's address.
    FOR rel IN SELECT * FROM (VALUES
                   ('request', 'INSERT', ARRAY['kind', 'target', 'payload', 'asked_by', 'break_glass']),
                   ('audit', 'INSERT', ARRAY['actor', 'action', 'target', 'detail', 'break_glass', 'request_id']),
                   ('session', 'INSERT', ARRAY['token_hash', 'account_id', 'break_glass']),
                   ('session', 'UPDATE', ARRAY['last_seen_at'])) AS w (tbl, act, cols) LOOP
        FOR col IN SELECT attname FROM pg_attribute
                   WHERE attrelid = rel.tbl::regclass AND attnum > 0 AND NOT attisdropped LOOP
            may := col = ANY (rel.cols);
            IF has_column_privilege('maildivvy_admin', rel.tbl, col, rel.act) <> may THEN
                wrong := wrong || format('maildivvy_admin %s %s %s.%s',
                                         CASE WHEN may THEN 'cannot' ELSE 'can' END, rel.act, rel.tbl, col);
            END IF;
        END LOOP;
    END LOOP;
    FOREACH col IN ARRAY ARRAY['address', 'address_canonical'] LOOP
        IF has_column_privilege('maildivvy_admin', 'external_mailbox', col, 'UPDATE') THEN
            wrong := wrong || format('maildivvy_admin can UPDATE external_mailbox.%s', col);
        END IF;
    END LOOP;
    FOREACH col IN ARRAY ARRAY['external_mailbox_the_interface_only_deactivates',
                               'request_is_never_inserted_with_gone'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = col AND tgenabled <> 'D') THEN
            wrong := wrong || format('trigger %s is missing or disabled', col);
        END IF;
    END LOOP;

    IF cardinality(wrong) > 0 THEN
        RAISE EXCEPTION 'the grants the schema relies on do not hold: %', array_to_string(wrong, '; ')
            USING HINT = 'grant or revoke in the migration that changed them; on external_mailbox, column by column';
    END IF;
    RETURN true;
END;
$$;

SELECT check_grants();
