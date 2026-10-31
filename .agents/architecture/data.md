# Données

Stockage, migrations et secrets de démarrage. Les règles d'écriture SQL sont dans `rules/postgresql.md`.

- PostgreSQL 15+ pour les services à état. Chaque magasin a une variante mémoire (développement/tests) et une variante PostgreSQL ; `DATABASE_URL` choisit. Le schéma est porté par des **migrations numérotées** (`migrations/NNN_nom.sql`, embarquées dans `migrations.Files`), appliquées au démarrage par `pkg/migrate` (ADR-0030) : une fois chacune, en transaction, sous un verrou consultatif propre au service, enregistrées dans `schema_migrations (component, version, name, checksum, applied_at)`. **Une migration appliquée n'est jamais modifiée** (checksum vérifié : sinon le service refuse de démarrer) ; un changement de schéma est un nouveau fichier. `001_init.sql` est figé tel qu'il était à ADR-0030 (idempotent : c'est lui qui met à niveau les bases d'avant). Les migrations restent **additives par défaut** : une base plus récente que le binaire est acceptée (ligne `WARNING` au journal).
- Modèle de données de référence : `docs/architecture/data-architecture.md`.
- Secrets de bootstrap par variable d'environnement (`KMS_KEY_HEX`, `TOKEN_SIGNING_KEY_HEX`) : un service avec `DATABASE_URL` refuse de démarrer sans sa clé.
