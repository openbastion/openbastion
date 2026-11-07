-- ADR-0078 : l'émetteur que chaque fournisseur OIDC a eu à son premier démarrage. Un autre émetteur
-- sous le même identifiant fait refuser le démarrage, sauf s'il est déclaré (previous_issuer ou
-- OIDC_PREVIOUS_ISSUER) et écrit à l'audit. Le fournisseur des variables OIDC_* est la ligne ''.
CREATE TABLE IF NOT EXISTS identity_provider_bindings (
    provider  TEXT PRIMARY KEY,
    issuer    TEXT NOT NULL,
    bound_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
