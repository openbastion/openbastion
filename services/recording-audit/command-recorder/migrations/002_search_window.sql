-- ADR-0080 : la recherche des commandes lit la fenêtre sur le début de l'enregistrement de
-- chaque session (la création de sa clé), les plus récentes d'abord.
CREATE INDEX IF NOT EXISTS idx_session_recording_keys_created ON session_recording_keys (created_at DESC, session_id);
