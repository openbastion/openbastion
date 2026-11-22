-- ADR-0116 §3 : la tête indépendante des métadonnées de session. Pour chaque session, la dernière
-- révision que le Session Broker a attestée : son digest (SHA-256 de la forme canonique), la clé HMAC
-- du Broker qui l'a signée (son identifiant seulement), et de quoi recalculer l'événement
-- session.metadata_attested de la chaîne qui la porte, même une fois cet événement archivé
-- (ADR-0032). Écrite dans la même transaction que l'événement ; jamais par un autre chemin. Le rôle
-- PostgreSQL du Broker n'a aucun droit sur cette base.
CREATE TABLE IF NOT EXISTS session_metadata_heads (
    session_id      TEXT PRIMARY KEY,
    revision        BIGINT NOT NULL CHECK (revision >= 1),
    metadata_sha256 BYTEA NOT NULL CHECK (length(metadata_sha256) = 32),
    key_id          TEXT NOT NULL,
    event_id        TEXT NOT NULL,
    event_ts        TIMESTAMPTZ NOT NULL,
    prev_hash       BYTEA,
    event_hash      BYTEA NOT NULL,
    chain_key_id    TEXT NOT NULL,
    hash_version    INT NOT NULL,
    emitter         TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
