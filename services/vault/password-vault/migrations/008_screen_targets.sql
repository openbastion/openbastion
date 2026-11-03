-- Target TLS identity for graphical protocols (ADR-0071). Existing SSH accounts
-- remain unchanged; a VNC/RDP account cannot receive a scope until both values
-- have been pinned through the audited SetTLSPin operation.
ALTER TABLE privileged_accounts
    ADD COLUMN IF NOT EXISTS tls_certificate_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_domain TEXT NOT NULL DEFAULT '';

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'privileged_accounts_tls_pin_pair'
    ) THEN
        ALTER TABLE privileged_accounts ADD CONSTRAINT privileged_accounts_tls_pin_pair
            CHECK ((tls_certificate_sha256 = '' AND target_domain = '') OR
                   (protocol IN ('vnc', 'rdp') AND tls_certificate_sha256 <> '' AND target_domain <> ''));
    END IF;
END $$;
