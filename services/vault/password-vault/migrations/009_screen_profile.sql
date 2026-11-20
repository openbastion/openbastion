-- ADR-0132 : le profil d'écran d'un compte RDP (canaux et profondeurs permis, et leurs défauts),
-- en JSON. NULL : tout est permis, le comportement d'avant (graphics et 32 bits par défaut).
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS screen_profile JSONB;
