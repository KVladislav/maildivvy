-- 0002: what a provider mailbox may differ in - an SMTP login of its own, mail kept at the
-- provider, and a provider certificate pinned by its fingerprint.
--
-- Four columns on external_mailbox, the SASL view's login rule, and one view more for
-- Postfix: the TLS policy of a pinned SMTP server. external_mailbox is granted column by
-- column, so each new column is named for every role that reads or writes it, and the
-- grants are read back at the end with Postfix's sixth view among them.

ALTER TABLE external_mailbox
    -- ⛔ No colon: Postfix splits its SASL value `login:password` at the FIRST colon, so a
    -- login carrying one would send the rest of the login as part of the password.
    ADD COLUMN smtp_login text CHECK (smtp_login ~ '^[^[:space:][:cntrl:]:]+$'),
    ADD COLUMN keep_at_provider boolean NOT NULL DEFAULT false,
    -- A SHA-256 certificate fingerprint as mpop and Postfix both read it: 32 bytes in upper
    -- case hex, a colon between each two. The interface writes it in this one spelling.
    ADD COLUMN pop3_cert_fingerprint text
        CHECK (pop3_cert_fingerprint ~ '^([0-9A-F]{2}:){31}[0-9A-F]{2}$'),
    ADD COLUMN smtp_cert_fingerprint text
        CHECK (smtp_cert_fingerprint ~ '^([0-9A-F]{2}:){31}[0-9A-F]{2}$');

COMMENT ON COLUMN external_mailbox.smtp_login IS
$$The login the relay presents; NULL means the POP3 login, or the address when the POP3
login is empty or holds a colon (a POP3-only mode such as recent:).$$;
COMMENT ON COLUMN external_mailbox.keep_at_provider IS
$$True renders the fetcher's keep on: nothing is ever deleted at the provider, and
delete_window_days is kept for when it is switched off again.$$;
COMMENT ON COLUMN external_mailbox.pop3_cert_fingerprint IS
$$The one POP3 server certificate the fetcher accepts, in place of the trust store and
the host name; NULL verifies against the trust store.$$;
COMMENT ON COLUMN external_mailbox.smtp_cert_fingerprint IS
$$A certificate the relay accepts for this SMTP host and port, in place of the trust store
and the host name. Postfix keys its TLS policy by server, never by sender, so a pin here
holds for every mailbox that sends through the same host and port (postfix_tls_policy).$$;

-- The SASL value: the SMTP login, else the POP3 login, else the address as entered.
-- A POP3 login with a colon in it is a POP3-only mode such as `recent:`, and
-- could not be a SASL login anyway, so the address stands in for it. The columns are
-- the same, so the view keeps its grant.
CREATE OR REPLACE VIEW postfix_sasl_password AS
    SELECT lower(e.address)                                                AS mkey,
           coalesce(e.smtp_login,
                    CASE WHEN strpos(e.pop3_login, ':') = 0 THEN e.pop3_login END,
                    e.address) || ':' || e.credential                    AS mvalue
    FROM external_mailbox e
    JOIN domain d ON d.external_mailbox_id = e.id
    WHERE e.state = 'active' AND e.credential IS NOT NULL;

-- smtp_tls_policy_maps: a pinned SMTP server's certificate. ⚠️ POSTFIX LOOKS A
-- TLS POLICY UP BY THE NEXT HOP, NEVER BY THE SENDER: the key is the transport's own
-- `[host]:port`, so every pin given for one server and port is joined into one `match`,
-- and holds for every mailbox that sends there. Only a mailbox that sends counts, the
-- rows postfix_transport gives a transport to, so a disabled mailbox's old pin binds
-- nobody. The host is folded, since Postfix folds the key before it asks.
CREATE VIEW postfix_tls_policy AS
    SELECT '[' || lower(e.smtp_host) || ']:' || e.smtp_port                     AS mkey,
           'fingerprint match=' || string_agg(DISTINCT e.smtp_cert_fingerprint, '|'
                                              ORDER BY e.smtp_cert_fingerprint) AS mvalue
    FROM external_mailbox e
    JOIN domain d ON d.external_mailbox_id = e.id
    WHERE e.state = 'active' AND e.credential IS NOT NULL
      AND e.smtp_cert_fingerprint IS NOT NULL
    GROUP BY lower(e.smtp_host), e.smtp_port;

GRANT SELECT ON postfix_tls_policy TO maildivvy_postfix;

-- The interface and health read every column but the credential; the interface writes
-- the four settings. The pipeline's SELECT on the table covers them already.
GRANT SELECT (smtp_login, keep_at_provider, pop3_cert_fingerprint, smtp_cert_fingerprint)
    ON external_mailbox TO maildivvy_admin, maildivvy_health;
GRANT INSERT (smtp_login, keep_at_provider, pop3_cert_fingerprint, smtp_cert_fingerprint)
    ON external_mailbox TO maildivvy_admin;
GRANT UPDATE (smtp_login, keep_at_provider, pop3_cert_fingerprint, smtp_cert_fingerprint)
    ON external_mailbox TO maildivvy_admin;

-- The grants read back, as 0001 left the function but for Postfix's sixth view.
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
        'last_skip_at', 'last_skip_uidl', 'held_since'];
    admin_writes text[] := ARRAY['state', 'state_changed_at', 'state_changed_by', 'frozen_since', 'skip_streak'];
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
    -- the fetch columns are the pipeline's; the interface clears two and no counter
    FOREACH col IN ARRAY pipeline_writes LOOP
        IF NOT has_column_privilege('maildivvy_pipeline', 'external_mailbox', col, 'UPDATE') THEN
            wrong := wrong || format('maildivvy_pipeline cannot UPDATE external_mailbox.%s', col);
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
