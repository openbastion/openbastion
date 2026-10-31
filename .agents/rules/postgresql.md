# PostgreSQL

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. Le schéma est porté par des **migrations numérotées** `migrations/NNN_nom.sql` (embarquées dans `migrations.Files`), appliquées au démarrage par `pkg/migrate` (ADR-0030) : une fois chacune, en transaction, sous verrou consultatif, checksum enregistré.
2. **Une migration appliquée n'est jamais modifiée** : un changement de schéma est un nouveau fichier, numéro suivant, sans trou. Pas de `CREATE INDEX CONCURRENTLY` (transaction).
3. Additif par défaut : un ancien binaire tourne sur la nouvelle base (`ADD COLUMN IF NOT EXISTS … NOT NULL DEFAULT …`). Une migration qui ne l'est pas le dit dans son ADR.
4. SQL écrit à la main dans `database/sql`, derrière les ports de domaine ; **pas d'ORM** ni de constructeur de requêtes (ADR-0029). Paramètres `$1`, jamais de concaténation.
5. Concurrence entre réplicas : comparer-échanger (`UPDATE … WHERE status = …`), `FOR UPDATE SKIP LOCKED` pour un balayage, verrou consultatif pour un plafond ; un index unique partiel quand une seule ligne d'un état est permise.
6. Un test PostgreSQL d'aller-retour pour chaque colonne ou table nouvelle, et un test de mise à niveau d'une ligne créée avant ; il se **skippe** sans `TEST_DATABASE_URL` et choisit des identifiants uniques (une base de test garde ses lignes).
7. Une table nouvelle s'ajoute aux `TRUNCATE` du `Makefile` et de `settings/postgresql.yaml`, et dans `docs/architecture/data-architecture.md`.
