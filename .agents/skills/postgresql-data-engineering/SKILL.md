---
name: postgresql-data-engineering
description: Schéma, migrations et requêtes PostgreSQL d'OpenBastion (pkg/migrate, magasins database/sql, concurrence entre réplicas, tests sur vraie base) — à utiliser pour toute migration, tout magasin ou toute requête.
---

# PostgreSQL

Règles : `rules/postgresql.md`. Workflow : `tasks/database/schema-change.md`. Réglages : `settings/postgresql.yaml`.

## Gestes

- Migration : `services/<…>/migrations/NNN_nom.sql`, numéro suivant ; `ALTER TABLE … ADD COLUMN IF NOT EXISTS … NOT NULL DEFAULT …` pour rester additif.
- Base de test : conteneur `obpg` (`docker start obpg`), `TEST_DATABASE_URL` ; purge avant une suite complète.
- Test : `testDB(t)` (se skippe sans base), identifiants uniques (`uniqueID`), aller-retour et mise à niveau ; une contrainte d'unicité sur `(target_host, name)` casse un test qui fixe ces valeurs au deuxième passage.

## Concurrence

- Changer un état : `UPDATE … WHERE id = $1 AND status = $2` et vérifier `RowsAffected` (comparer-échanger).
- Balayer : `SELECT … FOR UPDATE SKIP LOCKED` dans une CTE triée, par lots (ADR-0034).
- Une seule ligne d'un état : index unique partiel (`vault_secrets_one_pending_idx`, ADR-0037).
- Un plafond global : verrou consultatif dans la transaction (ADR-0013).

## À ne pas faire

ORM, concaténation SQL, `CREATE INDEX CONCURRENTLY` dans une migration, modifier une migration appliquée, `TRUNCATE` hors de la base de test.
