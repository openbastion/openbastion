-- ADR-0138: durable, at-least-once dispatch from a pending session to Workflow Service.
CREATE TABLE IF NOT EXISTS session_workflow_outbox (
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE RESTRICT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    due_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until TIMESTAMPTZ,
    lease_token TEXT,
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((lease_until IS NULL) = (lease_token IS NULL))
);
CREATE INDEX IF NOT EXISTS session_workflow_outbox_due_idx
    ON session_workflow_outbox (due_at, session_id);
