-- ADR-0114: separate resource scope from the action a role may perform.
-- Existing policies retain their historical behavior through the explicit wildcard.
ALTER TABLE policies
    ADD COLUMN action_pattern TEXT NOT NULL DEFAULT '*';

ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_role_resource_pattern_effect_key;

ALTER TABLE policies
    ADD CONSTRAINT policies_role_resource_action_effect_key
    UNIQUE (role, resource_pattern, action_pattern, effect);
