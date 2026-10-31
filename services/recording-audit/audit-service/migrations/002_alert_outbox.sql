-- ADR-0057: the alerts waiting to be pushed, so that a restart of the Audit Service does not
-- lose them. One row per audit event (its id is the key: an alert is kept once). The body is
-- what the chain already holds, without any secret; the signature is made at each attempt.
CREATE TABLE IF NOT EXISTS alert_outbox (
    event_id   TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    body       BYTEA NOT NULL,
    attempt    INTEGER NOT NULL,
    due_at     TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alert_outbox_due ON alert_outbox (due_at);
