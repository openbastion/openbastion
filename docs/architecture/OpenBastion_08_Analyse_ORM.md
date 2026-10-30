# OpenBastion — Analyse : intégrer un ORM dans le modèle de données ?

**Version** 0.1 · **Statut** Analyse — décision à prendre par Bony Kiss
**Documents liés** `OpenBastion_06_Modele_Donnees.md` (tables), `OpenBastion_03_ADR.md` (ADR-0002, ADR-0003, ADR-0008, ADR-0013, ADR-0018, ADR-0026 à ADR-0028), `.agents/policies.md` §4 (dépendances)

---

## 1. Réponse courte

**Je recommande de ne pas intégrer d'ORM complet (GORM, ent, bun) dans les services.** Le modèle de données d'OpenBastion est petit et sans relations entre services. Ses garanties de sécurité sont écrites **dans le SQL lui-même**, et un ORM les cacherait ou obligerait à les réécrire en SQL brut à côté de lui.

Si l'objectif est de réduire le code répétitif et d'avoir des requêtes typées, l'option au moindre regret est **sqlc** : il génère du code Go typé à partir de fichiers `.sql`, sans aucune dépendance à l'exécution. Le SQL reste la source de vérité, lisible et relu, et le code généré utilise `database/sql`, comme aujourd'hui. Une étape plus légère encore serait **sqlx**, pour la lecture des lignes (5 modules, aucun `golang.org/x`).

Ajouter une dépendance demande ton accord (`policies.md` §4.2). Rien n'a été ajouté au dépôt pour cette analyse.

## 2. Ce qui existe, mesuré dans le code

| Service | Magasin PostgreSQL | Schéma | Appels SQL | Particularités qui portent une garantie |
|---|---|---|---|---|
| Authentication | 102 lignes | 24 lignes | 4 | — |
| Authorization | 101 lignes | 22 lignes | 4 | Amorçage de `platform-admin` seulement sur un magasin vide |
| Session Broker | 216 lignes | 69 lignes | 10 | `pg_advisory_xact_lock` (plafond d'urgences par demandeur, ADR-0013) ; `UPDATE … WHERE status = $` comme comparer-échanger (une seule décision gagne, ADR-0011) ; index partiel `WHERE status = 'pending_approval'` (ADR-0012) ; `ON CONFLICT … DO UPDATE` |
| Password Vault | 195 lignes | 44 lignes | 12 | Index partiel `WHERE superseded_at IS NULL` (version courante d'un secret) ; consommation à usage unique d'un octroi avec `RETURNING` (ADR-0003) ; les deux seules clés étrangères du projet |
| Audit Service | 112 lignes | 55 lignes | 4 | Ordre d'insertion `seq` dont dépend la chaîne ; colonnes de format de hash et de clé (ADR-0026, ADR-0027) |
| Command Recorder | 351 lignes | 37 lignes | 20 | Lot tout ou rien en transaction ; `LOCK TABLE … IN ACCESS EXCLUSIVE MODE` (scellement des lignes antérieures au chiffrement) ; `ON CONFLICT DO NOTHING` (clé de données par session) ; colonnes `BYTEA` chiffrées (AES-256-GCM, enveloppe) |
| **Total** | **1 077 lignes** | **251 lignes** | **54** | 10 tables, **2 clés étrangères**, **0 jointure** dans le code, 19 lectures de ligne (`Scan`) |

Trois faits structurent la réponse :

1. **Une base par service** (doc 06, ADR-0002) : aucune requête ne traverse deux services, il n'y a donc pas de graphe d'objets à charger. Or c'est là qu'un ORM apporte le plus (relations, chargement anticipé, jointures).
2. **Les garanties sont dans le SQL.** Le plafond d'urgences tient à un verrou consultatif, la décision unique à un `UPDATE … WHERE status = …` qui compte les lignes touchées, l'usage unique d'un octroi à un `RETURNING`. Ce sont des invariants (`architecture.md` §2), protégés par des tests de concurrence sur deux réplicas et par des mutations. Un ORM ne sait pas les exprimer : on les réécrirait en SQL brut. On aurait alors deux styles dans le même magasin, dont le plus dangereux serait le moins visible.
3. **Des valeurs liées octet par octet.** Six endroits tronquent le temps à la microseconde, parce que la chaîne d'audit et le scellement du Recorder hachent ou chiffrent la valeur exacte que PostgreSQL rend. Ce défaut a été trouvé en vrai (`NOTES_SANDBOX.md`). Un ORM qui convertit les dates, les fuseaux ou les tableaux d'octets à sa façon rouvrirait exactement cette classe de défauts.

L'architecture rend un changement **possible**, mais **pas nécessaire**. Chaque service accède à sa base par un port de domaine (`SessionRepository`, `CommandRepository`, `Store`…), avec un magasin en mémoire et un magasin PostgreSQL soumis aux **mêmes tests de contrat**. Changer de technique d'accès ne toucherait que `internal/infrastructure`, et les tests de contrat diraient si rien n'a bougé.

## 3. Les candidats, mesurés

Arbres de dépendances mesurés le 30 octobre 2026 avec `go get` dans un module jetable, hors du dépôt (`go list -m all`). Le sandbox de build d'origine ne résout pas `golang.org/x/*` sans `replace` vers les miroirs GitHub ; seuls `x/crypto` et `x/sys` en ont un (`NOTES_SANDBOX.md`).

| Candidat | Nature | Modules tirés | Dont `golang.org/x/*` | Licence | Exprime verrous, CAS, `RETURNING`, index partiels ? |
|---|---|---|---|---|---|
| GORM + pilote PostgreSQL | ORM complet (réflexion) | 23 | 8 | MIT | En SQL brut (`Raw`, `Clauses`) — donc deux styles |
| ent | ORM à génération de code (graphe) | 35 | 5 | Apache-2.0 | Partiellement, par extensions ; le schéma devient du code Go |
| bun | ORM léger, proche du SQL | 23 | 1 | BSD-2 | Oui, en grande partie, par le constructeur de requêtes |
| pgx (pilote seul) | Pilote PostgreSQL natif | 19 | 8 | MIT | Oui : c'est du SQL |
| sqlx | Extension de `database/sql` (lecture vers des structures) | 5 | 0 | MIT | Oui : c'est du SQL |
| sqlc | **Outil** de génération (pas une bibliothèque) | 0 à l'exécution | 0 à l'exécution | MIT | Oui : on écrit le SQL, il génère le Go |

*sqlc n'a pas été mesuré ici, parce que c'est un binaire de développement et pas une dépendance d'un module : le code généré n'importe que `database/sql` et le pilote déjà présent (`lib/pq`). À vérifier avant de s'engager.*

## 4. Ce qu'un ORM complet apporterait, et ce qu'il coûterait

**Apports réels**
- Moins de code de lecture des lignes. Avec 19 `Scan`, le gain se compte en dizaines de lignes, pas en milliers.
- Une API uniforme d'un service à l'autre, plus familière à une partie des développeurs.
- Des migrations automatiques (`AutoMigrate`), un apport en trompe-l'œil ici (voir les risques).

**Risques propres à OpenBastion**
- **Invariants déplacés hors de la vue.** Un `Save` qui réécrit toute la ligne, à la place du comparer-échanger `UPDATE … WHERE status = 'pending_approval'`, rouvrirait la course qu'ADR-0011 et ADR-0013 ont fermée (deux approbations, un plafond dépassé). Les tests de concurrence le verraient peut-être. Le relecteur ne le verrait pas.
- **Valeurs nulles implicites.** GORM, par exemple, ignore les champs à leur valeur zéro dans `Updates` avec une structure : un `consumed = false` ou un `break_glass = false` ne s'écrit pas. Pour un PAM, un booléen de sécurité qui ne s'écrit pas en silence est le pire défaut possible.
- **Migrations automatiques contre le schéma additif et idempotent** que la policy impose (`policies.md` §3, `tasks.md` §4). `AutoMigrate` peut créer des colonnes sous d'autres noms ou d'autres types, et ne supprime ni ne renomme rien : le schéma réel dériverait du schéma documenté (doc 06).
- **Conversion des types** (temps, `BYTEA`, tableaux) : la classe de défauts du §2, point 3.
- **Dépendances** : 23 à 35 modules par service. Chaque service est un module Go distinct (ADR-0002), donc **six fois** l'arbre à tenir à jour et à auditer. Dans le sandbox d'origine, 5 à 8 `golang.org/x/*` non résolubles sans miroir.
- **Requêtes moins lisibles en revue de sécurité.** Une requête générée à l'exécution ne se lit pas dans le diff, et la revue de sécurité (`tasks.md` §6) porte justement sur ces lignes-là.

## 5. Recommandation

1. **Ne pas intégrer GORM, ent ni bun** dans les services.
2. **Si l'objectif est de réduire le code répétitif ou d'avoir des requêtes typées : sqlc**, en pilote sur **un** service au magasin simple (Authorization : 4 appels, 101 lignes), derrière le même port, avec ses tests de contrat inchangés et une série de mutations. On l'étend service par service seulement si le pilote est probant. Le SQL reste écrit à la main, relu, et les verrous et comparer-échanger restent visibles dans les fichiers `.sql`.
3. **Alternative plus légère : sqlx**, pour la lecture des lignes seulement (5 modules, aucun `golang.org/x`).
4. **Ce qui manque vraiment au modèle de données n'est pas un ORM, ce sont des migrations versionnées.** Aujourd'hui chaque service applique au démarrage un `001_init.sql` idempotent (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). Cela tient tant que tout changement est additif. Mais rien ne dit quelle version du schéma une base a atteinte, et une migration qui n'est pas purement additive (un index à reconstruire, un `NOT NULL` à poser après un remplissage) n'a pas de place. Une table de version et des fichiers numérotés, écrits à la main ou avec un outil comme golang-migrate (licence MIT, à mesurer), régleraient cela sans toucher à la façon d'écrire les requêtes.

## 6. La décision qui te revient

| Option | Ce que je ferais ensuite |
|---|---|
| **A. Rester en `database/sql`** (recommandé à court terme) | Rien sur l'accès aux données ; proposer à part les migrations versionnées (§5, point 4) |
| **B. Pilote sqlc sur Authorization** | Mesurer l'outil dans le sandbox, écrire un ADR « Proposé », faire le pilote avec ses tests de contrat et ses mutations, puis décider de l'extension |
| **C. sqlx sur tous les magasins** | Demander l'ajout de la dépendance pour les six modules, ADR, migration magasin par magasin |
| **D. Un ORM complet malgré tout** | Je le déconseille ; si tu le veux, ADR avec les risques du §4, pilote sur un service sans garantie de concurrence (Authentication), jamais d'`AutoMigrate`, revue des requêtes générées |

Dans tous les cas, aucun changement d'accès aux données ne toucherait au domaine ni à l'application des services, seulement à `internal/infrastructure`.
