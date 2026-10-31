-- ADR-0041 : les échecs consécutifs de la rotation planifiée d'un compte, remis à zéro par
-- toute rotation réussie ; au N-ième, une alerte est écrite à l'audit.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS rotation_failures INTEGER NOT NULL DEFAULT 0;
