-- ADR-0133 : un mot de passe fourni par l'opérateur, saisi par le proxy, laisse un marqueur de sa
-- taille et de son empreinte salée (SHA-256(sel || texte), le sel à côté), jamais son texte. Un
-- marqueur du Vault n'en porte aucune ; un marqueur de l'opérateur porte les trois.
ALTER TABLE video_recording_events ADD COLUMN IF NOT EXISTS paste_bytes INTEGER;
ALTER TABLE video_recording_events ADD COLUMN IF NOT EXISTS paste_salt TEXT;
ALTER TABLE video_recording_events ADD COLUMN IF NOT EXISTS paste_sha256 TEXT;
ALTER TABLE video_recording_events DROP CONSTRAINT IF EXISTS video_recording_events_event_type_check;
ALTER TABLE video_recording_events DROP CONSTRAINT IF EXISTS video_recording_events_source_check;
ALTER TABLE video_recording_events DROP CONSTRAINT IF EXISTS video_recording_events_kind_check;
ALTER TABLE video_recording_events ADD CONSTRAINT video_recording_events_kind_check CHECK (
    (event_type = 'secret_injection_started' AND source = 'vault'
        AND paste_bytes IS NULL AND paste_salt IS NULL AND paste_sha256 IS NULL)
    OR (event_type = 'secret_paste_started' AND source = 'operator'
        -- NOT NULL said: a CHECK lets a NULL comparison through.
        AND paste_bytes IS NOT NULL AND paste_salt IS NOT NULL AND paste_sha256 IS NOT NULL
        AND paste_bytes BETWEEN 1 AND 512
        AND paste_salt ~ '^[0-9a-f]{32}$' AND paste_sha256 ~ '^[0-9a-f]{64}$'));
