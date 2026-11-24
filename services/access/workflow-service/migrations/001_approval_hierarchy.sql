-- ADR-0138: OpenBastion-owned N+1 hierarchy and durable post-commit audit events.
CREATE TABLE IF NOT EXISTS approval_hierarchy_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO approval_hierarchy_state (singleton, revision)
VALUES (TRUE, 0) ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS approver_hierarchy (
    subordinate_user_id TEXT PRIMARY KEY,
    manager_user_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (subordinate_user_id <> manager_user_id)
);
CREATE INDEX IF NOT EXISTS approver_hierarchy_manager_idx
    ON approver_hierarchy (manager_user_id, subordinate_user_id);

CREATE TABLE IF NOT EXISTS workflow_audit_outbox (
    event_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    success BOOLEAN NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    due_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until TIMESTAMPTZ,
    lease_token TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((lease_until IS NULL) = (lease_token IS NULL))
);
CREATE INDEX IF NOT EXISTS workflow_audit_outbox_due_idx
    ON workflow_audit_outbox (due_at, event_id);
