-- ADR-0114 hardening: policy creation must never inherit an implicit wildcard.
-- Explicit action_pattern='*' remains possible for intentionally broad policies.
ALTER TABLE policies
    ALTER COLUMN action_pattern DROP DEFAULT;
