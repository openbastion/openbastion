# Modifier le schéma PostgreSQL

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. **Nouvelle migration numérotée** `migrations/NNN_nom.sql` (numéro suivant, sans trou) — **jamais** la modification d'un fichier existant (ADR-0030). Additive par défaut ; en transaction, donc pas de `CREATE INDEX CONCURRENTLY`.
2. Les deux magasins (mémoire et PostgreSQL) et le port du domaine.
3. Test PostgreSQL d'aller-retour de la colonne ou table **et** de mise à niveau d'une ligne créée avant, avec des identifiants uniques.
4. Table ajoutée : les `TRUNCATE` du `Makefile` et de `settings/postgresql.yaml`, le `docs/architecture/data-architecture.md`.
5. Lance la suite PostgreSQL sur une vraie base, purgée avant (`settings/environments/local.yaml`).
