-- Command Recorder — schéma PostgreSQL initial. Suit
-- OpenBastion_06_Modele_Donnees.md §3 (table session_command_entries), avec
-- les mêmes écarts assumés que le Session Broker (voir son 001_init.sql) :
--
--   1. `session_id` est un TEXT fourni par l'appelant, pas un UUID.
--   2. Pas de clé étrangère vers `sessions(id)` ni de `ON DELETE CASCADE` :
--      `sessions` appartient à la base du Session Broker, et une base par
--      service ne PEUT physiquement pas poser de FK inter-services. La
--      conséquence voulue : supprimer une session ne détruirait jamais son
--      enregistrement — et ce service n'expose de toute façon ni UPDATE ni
--      DELETE (domain.CommandRepository est en ajout seul).
--
-- L'index couvre exactement la requête de replay : les entrées d'une
-- session, dans l'ordre (ts, id).

CREATE TABLE IF NOT EXISTS session_command_entries (
    id          BIGSERIAL PRIMARY KEY,
    session_id  TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    command     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_command_entries_session ON session_command_entries (session_id, ts, id);
