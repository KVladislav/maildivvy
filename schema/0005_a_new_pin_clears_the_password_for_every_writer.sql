-- 0005: a certificate pin set or changed clears the stored provider password in the
-- trigger, for every writer, as a host change does. The rule is the pin
-- decision's amendment of 2026-11-10; this is the migration it waited for.
--
-- Until now the interface's servers form cleared it in its own UPDATE, deciding from the
-- row it had read before, and the trigger compared the hosts alone. The function is
-- replaced with the same signature, so it keeps its owner and its trigger. No table,
-- column or grant changes. The previous release's interface still clears the password
-- itself on a new pin, which the trigger now does as well: the same row results.

-- ⛔ A NEW PIN CLEARS THE STORED PASSWORD, FOR EVERY WRITER. A pin replaces the trust
-- store and the name check, so it decides who receives the password just as a host does.
-- A pin set where there was none, or changed, clears it; a pin removed returns to the
-- trust store and the host name, the check every unpinned mailbox has, and keeps it
-- (NEW NOT NULL, so a removal is not a change here). IS DISTINCT FROM, so a NULL is
-- compared, not lost: writing a row's pins and hosts back as they were clears nothing.
CREATE OR REPLACE FUNCTION external_mailbox_clear_credential_on_host_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.pop3_host IS DISTINCT FROM OLD.pop3_host
       OR NEW.smtp_host IS DISTINCT FROM OLD.smtp_host
       OR (NEW.pop3_cert_fingerprint IS NOT NULL
           AND NEW.pop3_cert_fingerprint IS DISTINCT FROM OLD.pop3_cert_fingerprint)
       OR (NEW.smtp_cert_fingerprint IS NOT NULL
           AND NEW.smtp_cert_fingerprint IS DISTINCT FROM OLD.smtp_cert_fingerprint) THEN
        NEW.credential := NULL;
    END IF;
    RETURN NEW;
END;
$$;

SELECT check_grants();
