-- ADR-0068: bounded event details are stored with the event and covered by hash v4.
-- Existing events have no details; the empty object preserves that fact.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;
