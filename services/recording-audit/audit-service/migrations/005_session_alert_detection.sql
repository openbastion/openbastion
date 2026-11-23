-- ADR-0117: durable operator alert occurrences and the detection outbox are
-- separate from alert_outbox (ADR-0057), which remains webhook delivery only.
CREATE TABLE IF NOT EXISTS session_alert_detection_outbox (
    source_event_id TEXT PRIMARY KEY REFERENCES audit_events(id),
    catalog_version TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_session_alert_detection_due
    ON session_alert_detection_outbox (next_attempt_at, created_at, source_event_id);

CREATE TABLE IF NOT EXISTS session_alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    status TEXT NOT NULL CHECK (status IN ('unacknowledged','acknowledged')),
    summary VARCHAR(512) NOT NULL CHECK (octet_length(summary) <= 512),
    detected_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    acknowledgement_event_id TEXT,
    UNIQUE (source_event_id, rule_id),
    CHECK ((acknowledged_at IS NULL AND acknowledged_by IS NULL AND acknowledgement_event_id IS NULL AND status = 'unacknowledged') OR
           (acknowledged_at IS NOT NULL AND acknowledged_by IS NOT NULL AND acknowledgement_event_id IS NOT NULL AND status = 'acknowledged'))
);
CREATE INDEX IF NOT EXISTS idx_session_alerts_status_detected
    ON session_alerts (status, detected_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_session_alerts_severity_status_detected
    ON session_alerts (severity, status, detected_at DESC);
