# ADR-0029 — L'accès aux données reste en `database/sql` et SQL écrit à la main ; pas d'ORM


**Contexte**
Bony Kiss a demandé une analyse de l'intégration d'un ORM dans le modèle de données (`docs/architecture/data-access-orm-analysis.md`). Mesuré : 1 077 lignes de magasins PostgreSQL, 54 appels SQL, 10 tables, 2 clés étrangères, 0 jointure, une base par service. Les garanties de concurrence et d'usage unique tiennent au SQL lui-même (verrou consultatif d'ADR-0013, comparer-échanger d'ADR-0011, `RETURNING` d'ADR-0003). Quatre options ont été présentées (A : rester en `database/sql` ; B : pilote sqlc ; C : sqlx ; D : ORM complet). **Bony Kiss a choisi l'option A.**

**Décision**
1. Les magasins restent écrits en `database/sql` avec du SQL explicite, derrière les ports de domaine existants.
2. Aucun ORM ni constructeur de requêtes n'est ajouté ; aucune dépendance n'est ajoutée.
3. Le manque réel relevé par l'analyse, les migrations versionnées, est traité à part (ADR-0030).

**Conséquences**
- (+) Les verrous, comparer-échanger et `RETURNING` restent lisibles dans le diff, là où porte la revue de sécurité.
- (+) Aucun arbre de dépendances supplémentaire dans six modules.
- (−) Le code de lecture des lignes (19 `Scan`) reste écrit à la main.
- (−) Décision renversable : sqlc (option B) reste possible plus tard derrière les mêmes ports, sans toucher domaine ni application.

**Alternatives envisagées**
Options B, C et D de l'analyse, écartées par le choix du propriétaire ; leurs motifs sont dans `docs/architecture/data-access-orm-analysis.md` §4 à §6.
