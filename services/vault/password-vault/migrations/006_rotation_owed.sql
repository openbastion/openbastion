-- ADR-0044 : une rotation après usage est une dette enregistrée. Depuis quand le compte doit
-- une rotation (une session sur lui s'est terminée) ; vide : il ne doit rien. Effacée par toute
-- rotation réussie ; le balayage du Vault la paie.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS rotation_owed_since TIMESTAMPTZ;
