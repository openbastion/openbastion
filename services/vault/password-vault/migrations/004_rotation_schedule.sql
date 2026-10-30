-- ADR-0040 : les rotations planifiées sont exécutées. Un intervalle par compte (en jours) ; la
-- date à laquelle le Vault a pris le compte pour la dernière fois (réussie ou non) : un compte
-- n'est pas retenté avant une heure, et un seul réplica le prend.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS rotation_interval_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS rotation_attempted_at TIMESTAMPTZ;

-- Les comptes déjà réglés « scheduled » n'avaient pas d'intervalle : 30 jours, et ils
-- commencent à tourner, comme leur politique le promettait.
UPDATE privileged_accounts SET rotation_interval_days = 30
 WHERE rotation_policy = 'scheduled' AND rotation_interval_days = 0;
