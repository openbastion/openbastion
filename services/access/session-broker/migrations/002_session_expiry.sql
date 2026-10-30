-- ADR-0034 : une session ou une demande arrivée à échéance est marquée `expired` par le
-- balayage du Broker, une fois, et l'expiration est écrite dans la trace. `expiry_audited`
-- dit si l'événement `session.expire` a été accepté par l'Audit Service : FALSE tant qu'il
-- reste à écrire (audit en panne), repris au balayage suivant. Vrai par défaut : une ligne
-- que ce balayage n'a pas expirée n'a rien à écrire.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expiry_audited BOOLEAN NOT NULL DEFAULT TRUE;

-- Les expirations à écrire : peu de lignes, lues à chaque balayage.
CREATE INDEX IF NOT EXISTS sessions_expiry_to_audit_idx ON sessions (expired_at) WHERE status = 'expired' AND NOT expiry_audited;
-- Les sessions qui peuvent arriver à échéance, par échéance.
CREATE INDEX IF NOT EXISTS sessions_expiring_idx ON sessions (expires_at) WHERE status IN ('active', 'pending_approval');
