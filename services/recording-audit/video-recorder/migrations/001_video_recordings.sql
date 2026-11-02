CREATE TABLE IF NOT EXISTS video_recordings (
    session_id    TEXT PRIMARY KEY,
    key_id        TEXT NOT NULL,
    wrapped_dek   BYTEA NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('incomplete', 'complete')),
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS video_recording_segments (
    session_id          TEXT NOT NULL REFERENCES video_recordings(session_id),
    first_sequence      BIGINT NOT NULL CHECK (first_sequence > 0),
    last_sequence       BIGINT NOT NULL CHECK (last_sequence >= first_sequence),
    object_key          TEXT NOT NULL UNIQUE,
    ciphertext_sha256   BYTEA NOT NULL CHECK (octet_length(ciphertext_sha256) = 32),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, first_sequence)
);

CREATE INDEX IF NOT EXISTS idx_video_recording_segments_session_last
    ON video_recording_segments (session_id, last_sequence);
