-- ADR-0138: one-step approval requests, idempotent by the durable Session Broker session ID.
-- No cross-service foreign keys: Session Broker and Authentication own their respective records.
CREATE TABLE IF NOT EXISTS workflow_requests (
    id TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK (resource_type = 'session'),
    resource_id TEXT NOT NULL,
    requester_user_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    ticket_reference TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired','cancelled')),
    hierarchy_revision BIGINT NOT NULL CHECK (hierarchy_revision > 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    decision_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    decided_by TEXT,
    decision_reason TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (resource_type, resource_id),
    CHECK ((status IN ('approved','rejected') AND decided_at IS NOT NULL AND decided_by IS NOT NULL) OR (status NOT IN ('approved','rejected') AND decided_at IS NULL AND decided_by IS NULL))
);
CREATE INDEX IF NOT EXISTS workflow_requests_pending_expiry_idx
    ON workflow_requests (decision_expires_at, id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS workflow_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_request_id TEXT NOT NULL UNIQUE REFERENCES workflow_requests(id) ON DELETE RESTRICT,
    step_number SMALLINT NOT NULL DEFAULT 1 CHECK (step_number = 1),
    approver_user_id TEXT NOT NULL,
    hierarchy_revision BIGINT NOT NULL CHECK (hierarchy_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired','cancelled')),
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    decision_reason TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((status IN ('approved','rejected') AND decided_at IS NOT NULL AND decided_by IS NOT NULL) OR (status NOT IN ('approved','rejected') AND decided_at IS NULL AND decided_by IS NULL))
);
CREATE INDEX IF NOT EXISTS workflow_approvals_approver_pending_idx
    ON workflow_approvals (approver_user_id, created_at, id) WHERE status = 'pending';
