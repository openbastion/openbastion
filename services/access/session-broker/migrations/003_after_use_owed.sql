-- ADR-0044 : la fin d'une session active laisse une dette envers le Vault — le prévenir, pour
-- qu'il fasse tourner un compte post_use. Écrite dans la même écriture que la fin ; effacée
-- quand le Vault l'a reçue ; le balayage du Broker la renvoie sinon.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS after_use_owed BOOLEAN NOT NULL DEFAULT FALSE;

-- Les sessions dont le Vault n'a pas encore été prévenu : peu de lignes, lues à chaque balayage.
CREATE INDEX IF NOT EXISTS sessions_after_use_owed_idx ON sessions (id) WHERE after_use_owed;
