-- 0008: an external mailbox may be collected over IMAP, and a snapshot of every
-- folder of an IMAP mailbox may be asked for.
--
-- external_mailbox gains the protocol, the incremental mark (the INBOX's UIDVALIDITY and
-- the last UID collected under it) and the snapshot's eight columns. An IMAP row keeps
-- every message at the provider, held by a CHECK. The mark is cleared by a trigger, for
-- every writer, when the protocol, the host or the login changes, as a host change clears
-- the password. `last_fetch_cause` gains `mark`, a run that found no mark it can
-- trust, and `request.kind` gains `discard_snapshot`; both closed lists are dropped and
-- added again as 0006 did. The server columns keep their `pop3_` names and hold the IMAP
-- server's values too. external_mailbox is granted column by column, so every
-- new column is named for each role that reads or writes it, and the grant check is
-- replaced to read the new write lists back.
--
-- previous release: it never names a new column, and every one is nullable or has a
-- default (`protocol` is `pop3`), so its interface's inserts and its runner's reads and
-- writes run as before; every row there is a POP3 row with no mark, which passes each new
-- CHECK, and the trigger has no mark to clear on the rows it changes. The two closed lists
-- accept every value they accepted before and one more, which it never writes: an upgrade
-- pauses collection from before the migrations until the new programs are in place, so
-- its runner never meets an IMAP row or writes `mark`, and only the new interface asks
-- for `discard_snapshot`. Its fetch screen names a cause it does not know as itself.
-- Nothing is revoked, and check_grants keeps its signature.

ALTER TABLE external_mailbox
    ADD COLUMN protocol text NOT NULL DEFAULT 'pop3' CHECK (protocol IN ('pop3', 'imap')),
    -- RFC 9051 numbers both in 32 bits; a last UID of 0 is an INBOX that was empty
    ADD COLUMN imap_uidvalidity bigint CHECK (imap_uidvalidity BETWEEN 0 AND 4294967295),
    ADD COLUMN imap_last_uid bigint CHECK (imap_last_uid BETWEEN 0 AND 4294967295),
    ADD COLUMN snapshot_requested_at timestamptz,
    ADD COLUMN snapshot_started_at timestamptz,
    ADD COLUMN snapshot_finished_at timestamptz,
    ADD COLUMN snapshot_status text
        CHECK (snapshot_status IN ('pending', 'running', 'paused', 'done', 'failed')),
    ADD COLUMN snapshot_detail text,
    ADD COLUMN snapshot_paused_since timestamptz,
    ADD COLUMN snapshot_refused integer CHECK (snapshot_refused >= 0),
    ADD COLUMN snapshot_left_out integer CHECK (snapshot_left_out >= 0),
    -- ⛔ AN IMAP MAILBOX DELETES NOTHING AT THE PROVIDER: nothing of ours
    -- may ever change it, so its row says to keep every message, whoever writes it.
    ADD CONSTRAINT external_mailbox_imap_keeps_at_provider CHECK (protocol = 'pop3' OR keep_at_provider),
    -- A UID means nothing without the UIDVALIDITY it was given under (RFC 9051 §2.3.1.1).
    ADD CONSTRAINT external_mailbox_imap_mark_whole
        CHECK ((imap_uidvalidity IS NULL) = (imap_last_uid IS NULL)),
    -- the runner's own decisions first, `mark` among them, then what it reads of the
    -- delivery, then of the provider
    DROP CONSTRAINT external_mailbox_last_fetch_cause_check,
    ADD CONSTRAINT external_mailbox_last_fetch_cause_check CHECK (last_fetch_cause IN
        ('unrecorded', 'timeout', 'mark', 'stuck_message', 'store', 'unreachable', 'transient'));

ALTER TABLE request
    DROP CONSTRAINT request_kind_check,
    ADD CONSTRAINT request_kind_check CHECK (kind IN (
        'create_domain', 'create_mailbox', 'connect', 'top_up', 'deliver_one', 'release',
        'delete_account', 'delete_mailbox', 'delete_external_mailbox', 'delete_domain',
        'transfer', 'refetch', 'test_credential', 'activate_external_mailbox',
        'discard_snapshot'));

COMMENT ON COLUMN external_mailbox.protocol IS
$$How the mailbox is collected: pop3 by mpop, or imap by the runner's own read-only
client. The pop3_ server columns hold the server of this protocol.$$;
COMMENT ON COLUMN external_mailbox.pop3_login IS
$$The login the fetcher presents, over POP3 or IMAP as protocol says; NULL means the
address as typed. It must stay byte-equal for the life of the mailbox, or a POP3 fetcher
refetches its whole window and an IMAP row loses its mark.$$;
COMMENT ON COLUMN external_mailbox.pop3_host IS
$$The provider's server for the protocol in protocol, POP3 or IMAP: a name, never an
address. A change clears the stored password and the IMAP mark.$$;
COMMENT ON COLUMN external_mailbox.pop3_port IS
$$The port of pop3_host, implicit TLS for either protocol. The column's default, 995, is
POP3's; IMAP's is 993.$$;
COMMENT ON COLUMN external_mailbox.pop3_cert_fingerprint IS
$$The one server certificate the fetcher accepts at pop3_host, POP3 or IMAP, in place of
the trust store and the host name; NULL verifies against the trust store.$$;
COMMENT ON COLUMN external_mailbox.imap_uidvalidity IS
$$The INBOX's UIDVALIDITY when the mark was set; with imap_last_uid, both or neither. Only
activation sets it; a run that finds none, or another, collects nothing (cause mark).$$;
COMMENT ON COLUMN external_mailbox.imap_last_uid IS
$$The last INBOX UID collected, or passed, under imap_uidvalidity: the next run takes the
UIDs above it. Advanced after each message the delivery filter filed.$$;
COMMENT ON COLUMN external_mailbox.snapshot_requested_at IS
$$When a person asked for a snapshot of every folder; written by the interface alone.$$;
COMMENT ON COLUMN external_mailbox.snapshot_started_at IS
$$When the snapshot's first slice began; written by the pipeline.$$;
COMMENT ON COLUMN external_mailbox.snapshot_finished_at IS
$$When the snapshot was done or failed; written by the pipeline.$$;
COMMENT ON COLUMN external_mailbox.snapshot_status IS
$$Where the snapshot stands, NULL when none was asked for; written by the pipeline. Its
progress is in the snapshot's own manifest, beside its files.$$;
COMMENT ON COLUMN external_mailbox.snapshot_detail IS
$$What the last slice said: why it paused or failed, or what it left out.$$;
COMMENT ON COLUMN external_mailbox.snapshot_paused_since IS
$$When the snapshot was first left paused by a slice, kept while every slice since has left
it paused, NULL once one leaves it otherwise; written by the pipeline. Health warns of a
snapshot paused for longer than a day.$$;
COMMENT ON COLUMN external_mailbox.snapshot_refused IS
$$How many messages the provider refused to send that the snapshot does not hold, after
every slice that asked for them again; written by each slice, NULL with no snapshot.
Health warns of a done snapshot missing any.$$;
COMMENT ON COLUMN external_mailbox.snapshot_left_out IS
$$How many folders at the provider the snapshot leaves out: a name that cannot be a folder
in the store, or one EXAMINE refused; written by each slice, NULL with no snapshot.
Health warns of a done snapshot that left any out.$$;

-- ⛔ A CHANGE OF SERVER OR LOGIN CLEARS THE IMAP MARK, FOR EVERY WRITER. A UID
-- names a message of one mailbox at one server under one login, so a mark carried to
-- another would skip, or take again, whatever lies between the two numberings. A run
-- that then finds no mark collects nothing and says `mark` until the mailbox is
-- activated again, which sets one. A trigger, not the screen, and IS DISTINCT
-- FROM, so a NULL login is compared and a save that writes the same values back clears
-- nothing.
CREATE FUNCTION external_mailbox_clear_mark_on_server_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.protocol IS DISTINCT FROM OLD.protocol
       OR NEW.pop3_host IS DISTINCT FROM OLD.pop3_host
       OR NEW.pop3_login IS DISTINCT FROM OLD.pop3_login THEN
        NEW.imap_uidvalidity := NULL;
        NEW.imap_last_uid := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER external_mailbox_clear_mark_on_server_change
    BEFORE UPDATE ON external_mailbox
    FOR EACH ROW EXECUTE FUNCTION external_mailbox_clear_mark_on_server_change();

-- The interface and health read every new column. The pipeline's SELECT on the table
-- covers them; it writes the mark and the snapshot's progress, and the interface writes
-- the protocol and the snapshot's request, which nothing else does.
GRANT SELECT (protocol, imap_uidvalidity, imap_last_uid, snapshot_requested_at, snapshot_started_at,
              snapshot_finished_at, snapshot_status, snapshot_detail, snapshot_paused_since,
              snapshot_refused, snapshot_left_out)
    ON external_mailbox TO maildivvy_admin, maildivvy_health;
GRANT UPDATE (imap_uidvalidity, imap_last_uid, snapshot_started_at, snapshot_finished_at,
              snapshot_status, snapshot_detail, snapshot_paused_since, snapshot_refused,
              snapshot_left_out)
    ON external_mailbox TO maildivvy_pipeline;
GRANT INSERT (protocol) ON external_mailbox TO maildivvy_admin;
GRANT UPDATE (protocol, snapshot_requested_at) ON external_mailbox TO maildivvy_admin;

-- The grants read back, as 0002 left the function but for the write lists: each column
-- either list names is written by exactly the roles whose list names it.
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

    IF cardinality(wrong) > 0 THEN
        RAISE EXCEPTION 'the grants the schema relies on do not hold: %', array_to_string(wrong, '; ')
            USING HINT = 'grant or revoke in the migration that changed them; on external_mailbox, column by column';
    END IF;
    RETURN true;
END;
$$;

SELECT check_grants();
