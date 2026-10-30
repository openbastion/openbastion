-- Audit Service — schéma PostgreSQL initial. Suit
-- OpenBastion_06_Modele_Donnees.md §3 (table audit_events), avec trois
-- écarts assumés par rapport au DDL documenté, pour la même raison que
-- partout ailleurs dans ce sandbox (voir NOTES_SANDBOX.md) :
--
--   1. Identifiants TEXT fournis par l'appelant (internal/application
--      génère déjà event.ID via nextID()), pas de UUID généré côté
--      serveur.
--   2. Pas de partitionnement par plage sur `ts` (doc 06 §3 :
--      `PARTITION BY RANGE (ts)`) — un simple index composé est
--      suffisant pour ce MVP ; le partitionnement mensuel est une
--      optimisation opérationnelle de volumétrie, pas une exigence de
--      correction, et reste un raffinement v1.0 direct une fois un
--      Scheduler réel en place pour créer les partitions à l'avance.
--   3. Pas de colonne `signature` séparée (doc 06 : "signature de
--      l'événement par le service émetteur") — domain.Event n'a pas
--      encore ce champ ; `hash` seul porte aujourd'hui la garantie
--      d'intégrité (chaînage, voir audit_service.go). Ajouter une
--      signature asymétrique par le service émetteur est un
--      durcissement v1.0 distinct du chaînage lui-même.
--
-- `seq` est la clé de tri fiable pour Last()/All() : `ts` seul ne
-- suffit pas à départager deux événements horodatés dans la même
-- microseconde, ce que BIGSERIAL (auto-incrémenté par Postgres,
-- monotone à l'insertion) garantit sans ambiguïté — c'est exactement
-- l'ordre d'insertion réel que le chaînage de hash doit respecter.

CREATE TABLE IF NOT EXISTS audit_events (
    seq            BIGSERIAL PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    ts             TIMESTAMPTZ NOT NULL,
    actor_id       TEXT,
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    success        BOOLEAN NOT NULL,
    prev_hash      BYTEA,
    hash           BYTEA NOT NULL
);

-- ADR-0026 : le format du hash de chaque événement. Les lignes écrites avant
-- (champs concaténés tels quels) reçoivent 1 à la mise à niveau ; toute
-- ligne écrite depuis porte 2 (chaque champ précédé de sa longueur).
-- Additif et idempotent.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1;

-- ADR-0027 : qui a écrit l'événement (le service que nomme son certificat mTLS)
-- et quelle clé de chaîne en signe le HMAC (format 3). Vides pour les lignes
-- antérieures, qui ne couvrent ni l'un ni l'autre. Additif et idempotent.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS emitter TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS chain_key_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events (resource_type, resource_id, ts DESC);
