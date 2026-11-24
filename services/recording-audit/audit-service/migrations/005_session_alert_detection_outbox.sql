-- ADR-0117: durable detection work is separate from alert_outbox (webhook delivery, ADR-0057).
-- The source event is retained by audit_events; no event body or credential is duplicated here.
CREATE TABLE IF NOT EXISTS session_alert_detection_outbox (
    source_event_id  TEXT PRIMARY KEY,
    catalog_version  TEXT NOT NULL CHECK (catalog_version <> ''),
    attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_code  TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_session_alert_detection_due
    ON session_alert_detection_outbox (next_attempt_at, source_event_id);
