-- ADR-0037 : la rotation atteint la cible. Un compte nomme son compte de réconciliation
-- (même cible, peut changer les mots de passe) ; vide : pas de rotation possible. Le nouveau
-- secret est d'abord une version en attente, à côté de la courante, jamais injectée, puis
-- devient courante en une transaction une fois posé et vérifié sur la cible.
ALTER TABLE privileged_accounts ADD COLUMN IF NOT EXISTS reconciliation_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE vault_secrets ADD COLUMN IF NOT EXISTS pending BOOLEAN NOT NULL DEFAULT FALSE;

-- Une seule rotation en attente par compte.
CREATE UNIQUE INDEX IF NOT EXISTS vault_secrets_one_pending_idx ON vault_secrets (privileged_account_id) WHERE pending;
