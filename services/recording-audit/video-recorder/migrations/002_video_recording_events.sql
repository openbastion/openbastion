-- Deliberately no FK to video_recordings: the marker may precede the first persisted image/recording row.
CREATE TABLE IF NOT EXISTS video_recording_events (
    event_id    TEXT COLLATE "C" PRIMARY KEY CHECK (length(event_id) BETWEEN 1 AND 128),
    session_id  TEXT NOT NULL,
    event_type  TEXT NOT NULL CHECK (event_type IN ('secret_injection_started')),
    protocol    TEXT NOT NULL CHECK (protocol IN ('vnc', 'rdp')),
    source      TEXT NOT NULL CHECK (source = 'vault'),
    account_id  TEXT NOT NULL CHECK (length(account_id) BETWEEN 1 AND 256),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_video_recording_events_timeline
    ON video_recording_events (session_id, occurred_at, event_id);

CREATE OR REPLACE FUNCTION prevent_video_recording_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'video recording events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS video_recording_events_no_update ON video_recording_events;
CREATE TRIGGER video_recording_events_no_update
    BEFORE UPDATE OR DELETE ON video_recording_events
    FOR EACH ROW EXECUTE FUNCTION prevent_video_recording_event_mutation();

DROP TRIGGER IF EXISTS video_recording_events_no_truncate ON video_recording_events;
CREATE TRIGGER video_recording_events_no_truncate
    BEFORE TRUNCATE ON video_recording_events
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_video_recording_event_mutation();
