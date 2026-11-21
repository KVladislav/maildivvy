-- 0003: a pinned SMTP server's policy holds only where every mailbox sending there names
-- the same pin (amendment of 2026-11-11).
--
-- 0002 joined every sending mailbox's pin for one `[host]:port` into one `match`, because
-- Postfix keys a TLS policy by next hop, never by sender. One mailbox's pin then accepted
-- a certificate for every other mailbox at that server, and handed it their passwords.
-- The view is replaced with the same columns, so it keeps its grant and the previous
-- release's Postfix reads it as before.

-- smtp_tls_policy_maps. ⚠️ POSTFIX LOOKS A TLS POLICY UP BY THE NEXT HOP, NEVER BY THE
-- SENDER, so the answer for one server must be one every mailbox sending there accepts:
--   - every one names the same pin: that pin;
--   - they name different pins, or some name none (the trust store and the host name,
--): no certificate is acceptable to all of them, so the answer is a fingerprint
--     no certificate has, and nothing is relayed there, with no password presented, until
--     they agree. The trust store is not the fallback: it would overrule a pin, which
--     accepts that one certificate and refuses every other;
--   - none names a pin: no row, and the server is verified as has it.
-- Only a mailbox that sends counts, the rows postfix_transport gives a transport to, so a
-- disabled mailbox's old pin binds nobody. The host is folded, since Postfix folds the key
-- before it asks.
CREATE OR REPLACE VIEW postfix_tls_policy AS
    SELECT '[' || lower(e.smtp_host) || ']:' || e.smtp_port                     AS mkey,
           'fingerprint match=' ||
           CASE WHEN count(*) = count(e.smtp_cert_fingerprint)
                     AND count(DISTINCT e.smtp_cert_fingerprint) = 1
                THEN min(e.smtp_cert_fingerprint)
                ELSE repeat('00:', 31) || '00'
           END                                                                  AS mvalue
    FROM external_mailbox e
    JOIN domain d ON d.external_mailbox_id = e.id
    WHERE e.state = 'active' AND e.credential IS NOT NULL
    GROUP BY lower(e.smtp_host), e.smtp_port
    HAVING count(e.smtp_cert_fingerprint) > 0;

COMMENT ON COLUMN external_mailbox.smtp_cert_fingerprint IS
$$A certificate the relay accepts for this SMTP host and port, in place of the trust store
and the host name. Postfix keys its TLS policy by server, never by sender, so the pin holds
only while every mailbox that sends through the same host and port names it; while they
differ, nothing is relayed there (postfix_tls_policy).$$;

SELECT check_grants();
