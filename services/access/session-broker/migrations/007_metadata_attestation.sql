-- ADR-0116 : l'attestation des métadonnées de session. Chaque ligne porte sa révision, l'identifiant
-- de la clé qui l'a signée et son HMAC-SHA-256, calculé par le Session Broker sous une clé que
-- PostgreSQL ne détient jamais. Une ligne dont le MAC ne se vérifie pas n'est pas utilisée.
--
-- Migration sûre (ADR-0116 §8) : elle exige une fenêtre de maintenance. Elle refuse de s'appliquer
-- tant qu'une session est en attente ou active, qu'une expiration reste à auditer, ou qu'une fin de
-- session reste à dire au Vault (ADR-0044) : ces lignes seraient sinon gelées sans signature. L'historique existant est marqué
-- legacy_unverified : visible en lecture seule, jamais signé après coup (il a pu être altéré avant),
-- jamais reconnecté ni utilisé pour une action privilégiée.
--
-- Idempotente : rejouée sur une base qui a déjà les colonnes, elle ne fait rien (ni contrôle, ni
-- marquage : une ligne signée n'est jamais redevenue legacy).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = 'sessions' AND column_name = 'metadata_revision') THEN
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM sessions WHERE status IN ('pending_approval', 'active') AND expires_at >= now()) THEN
    RAISE EXCEPTION 'ADR-0116: terminate every pending and active session before this migration (maintenance window)';
  END IF;
  IF EXISTS (SELECT 1 FROM sessions WHERE status = 'expired' AND NOT expiry_audited) THEN
    RAISE EXCEPTION 'ADR-0116: let the Session Broker audit every expiry before this migration';
  END IF;
  IF EXISTS (SELECT 1 FROM sessions WHERE after_use_owed) THEN
    RAISE EXCEPTION 'ADR-0116: let the Session Broker tell the Vault of every ended session (after_use_owed) before this migration';
  END IF;
  ALTER TABLE sessions ADD COLUMN metadata_revision BIGINT NOT NULL DEFAULT 0;
  ALTER TABLE sessions ADD COLUMN metadata_key_id TEXT NOT NULL DEFAULT '';
  ALTER TABLE sessions ADD COLUMN metadata_mac BYTEA;
  ALTER TABLE sessions ADD COLUMN legacy_unverified BOOLEAN NOT NULL DEFAULT false;
  UPDATE sessions SET legacy_unverified = true;
END
$$;
