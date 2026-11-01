-- ADR-0066 : le dernier usage de chaque clé de sécurité, pour que l'administrateur qui liste les
-- clés d'un compte sache laquelle est perdue avant de la révoquer.
ALTER TABLE mfa_webauthn_credentials ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
