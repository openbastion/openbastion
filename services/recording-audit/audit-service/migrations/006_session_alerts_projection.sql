-- ADR-0117: the operator projection is separate from the signed source chain.
-- Migration 005 created the durable detection outbox; this migration adds the
-- source-retention constraint and the idempotent projection used by the worker.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'session_alert_detection_outbox_source_event_fk'
          AND conrelid = 'public.session_alert_detection_outbox'::regclass
    ) THEN
        ALTER TABLE session_alert_detection_outbox
            ADD CONSTRAINT session_alert_detection_outbox_source_event_fk
            FOREIGN KEY (source_event_id) REFERENCES audit_events(id);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS session_alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    source_event_id TEXT NOT NULL REFERENCES audit_events(id),
    session_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('unacknowledged', 'acknowledged')),
    summary VARCHAR(512) NOT NULL CHECK (octet_length(summary) <= 512),
    detected_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    acknowledgement_event_id TEXT REFERENCES audit_events(id),
    UNIQUE (source_event_id, rule_id),
    CHECK (
        (acknowledged_at IS NULL AND acknowledged_by IS NULL AND acknowledgement_event_id IS NULL AND status = 'unacknowledged')
        OR
        (acknowledged_at IS NOT NULL AND acknowledged_by IS NOT NULL AND acknowledgement_event_id IS NOT NULL AND status = 'acknowledged')
    )
);

CREATE INDEX IF NOT EXISTS idx_session_alerts_status_detected
    ON session_alerts (status, detected_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_session_alerts_severity_status_detected
    ON session_alerts (severity, status, detected_at DESC);
