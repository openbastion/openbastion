-- ADR-0114: separate resource scope from the action a role may perform.
-- Development-era default; migration 003 removes it so future policies must name an action.
ALTER TABLE policies
    ADD COLUMN action_pattern TEXT NOT NULL DEFAULT '*';

ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_role_resource_pattern_effect_key;

ALTER TABLE policies
    ADD CONSTRAINT policies_role_resource_action_effect_key
    UNIQUE (role, resource_pattern, action_pattern, effect);
