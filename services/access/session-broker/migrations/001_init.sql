-- Session Broker — schéma PostgreSQL initial. Suit
-- OpenBastion_06_Modele_Donnees.md §3 (table sessions), avec les écarts
-- assumés suivants, pour la même raison que partout ailleurs dans ce
-- sandbox (voir NOTES_SANDBOX.md) :
--
--   1. Identifiants TEXT fournis par l'appelant (application.randomID),
--      pas de UUID généré côté serveur.
--   2. Pas de clé étrangère vers `users`/`privileged_accounts` — dans ce
--      système en microservices, ces entités vivent dans les bases
--      d'Authentication et de Password Vault respectivement, pas dans
--      celle du Session Broker (le doc 06 modélise un schéma partagé
--      unique à titre de référence ; une vraie base par service, comme
--      ici, ne PEUT physiquement pas poser de FK inter-services).
--   3. Pas de `connection_ticket_hash` — ce MVP ne persiste pas encore
--      le hash du dernier ticket émis ; Connect (session_broker_service.go)
--      renvoie le ticket au Gateway sans le faire transiter par ce
--      dépôt. Raffinement v1.0 direct, sans changement de forme à cette
--      table.
--
-- `Save` (domain.SessionRepository) sert à la fois de création ET de
-- mise à jour (TerminateSession relit puis réenregistre la même ligne,
-- CreateSession enregistre même une tentative refusée) — d'où l'UPSERT
-- ci-dessous plutôt qu'un simple INSERT, à l'inverse des autres stores
-- de ce projet qui n'ont que des Create à usage unique par ligne.

CREATE TABLE IF NOT EXISTS sessions (
    id                     TEXT PRIMARY KEY,
    status                 TEXT NOT NULL,
    protocol               TEXT NOT NULL,
    requested_by           TEXT NOT NULL,
    privileged_account_id  TEXT NOT NULL,
    justification          TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL,
    expires_at             TIMESTAMPTZ NOT NULL,
    terminated_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_requested_by ON sessions (requested_by);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions (status);
