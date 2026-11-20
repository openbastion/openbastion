-- ADR-0100 : les réglages Kerberos d'un compte RDP (royaume et KDC), en JSON. NULL : NTLMv2, le
-- comportement d'avant. Posés, la session s'authentifie par Kerberos seul, sans repli vers NTLM.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS kerberos JSONB;
