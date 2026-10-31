# ADR-0030 — Des migrations de schéma versionnées, appliquées une fois, sous verrou, et dont le texte appliqué ne change plus


**Contexte**
Chacun des six services applique à **chaque démarrage** la totalité de son `migrations/001_init.sql`, idempotent (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`), et les évolutions passées ont été ajoutées **dans ce même fichier** (`tasks.md` §4). Ce qui a été **mesuré** ou constaté :

- **Deux réplicas qui démarrent en même temps sur une base neuve** : le schéma du Session Broker appliqué par deux processus simultanés sur une vraie PostgreSQL 16 → **dans 14 essais sur 20, l'un des deux échoue** (`duplicate key value violates unique constraint "pg_type_typname_nsp_index"`, 13 fois ; `pg_class_relname_nsp_index`, 1 fois). `IF NOT EXISTS` ne protège pas d'une création concurrente.
- **Rien ne dit quelle version du schéma une base a atteinte** : ni l'exploitant, ni le service, ni une procédure de reprise (PRA).
- **Une évolution qui n'est pas purement additive n'a pas de place** : un `NOT NULL` posé après un remplissage, un index reconstruit, une donnée transformée une seule fois — rejoués à chaque démarrage, ils seraient faux ou coûteux.
- **Le texte d'un schéma déjà appliqué peut être modifié** sans que rien ne le voie : la base d'une installation existante diverge alors en silence d'une installation neuve.

**Décision** *(acceptée par Bony Kiss le 30 octobre 2026 ; règles 2 et 3 précisées avant l'implémentation, voir la note)*
1. **Une migration** = un fichier `migrations/NNN_nom.sql` embarqué (`embed.FS`), `NNN` sur trois chiffres, continu à partir de `001`. Les fichiers sont lus dans l'ordre ; un trou ou un doublon de numéro refuse le démarrage (et un test unitaire de chaque service le dit avant).
2. **Une table `schema_migrations`** : `component TEXT, version INTEGER, name TEXT, checksum BYTEA` (SHA-256 du texte), `applied_at TIMESTAMPTZ`, **clé `(component, version)`** — chaque service s'y nomme (`authentication`, `authorization`, `session-broker`, `password-vault`, `audit-service`, `command-recorder`).
3. **Sous verrou** : tout le passage se fait sous `pg_advisory_lock` d'une **clé propre au service** (les 8 premiers octets de SHA-256(`openbastion.migrate.lock` 0x00 ‖ service)), sur une connexion dédiée, relâché au retour ; un second réplica attend, puis trouve tout appliqué. La création de `schema_migrations` elle-même prend un verrou de transaction commun à tous les services. Ferme la course mesurée ci-dessus.

   *Note d'implémentation* : le texte proposé disait « `version` clé primaire » et « une clé propre à OpenBastion ». En écrivant le code, j'ai constaté qu'en développement et en test **les six services partagent une seule base** (`TEST_DATABASE_URL`) : six « version 1 » différentes s'y seraient heurtées, et un verrou unique aurait fait attendre chaque service derrière les autres. D'où la clé `(component, version)` et un verrou par service.
4. **Une fois, en transaction** : chaque migration manquante est appliquée dans sa propre transaction, avec sa ligne dans `schema_migrations` ; un échec annule la migration et refuse le démarrage, en nommant la version.
5. **Le texte appliqué ne change plus** : si le checksum d'une version déjà appliquée diffère du fichier embarqué, le service **refuse de démarrer** en nommant la version. Corriger une migration publiée, c'est en écrire une nouvelle.
6. **Une base plus récente que le binaire** (une version appliquée que le binaire ne connaît pas) : le service démarre et le journal le dit, parce que les migrations restent additives par défaut et qu'un retour arrière du binaire (PRA) doit rester possible. Une migration qui casse les anciens binaires doit le dire dans son ADR.
7. **Bases existantes** : `001_init.sql` est figé tel qu'il est aujourd'hui. Sur une base qui le porte déjà sans `schema_migrations`, il est rejoué une fois (il est idempotent, c'est déjà ce qui se passe à chaque démarrage) et enregistré comme version 1. Aucune autre reprise manuelle.
8. **Un seul code** : `pkg/migrate`, bibliothèque standard et `database/sql` seulement (comme `pkg/refusalbudget`), utilisé par les six magasins PostgreSQL. Aucune dépendance ajoutée.
9. **Le workflow change** : `tasks.md` §4 dit « une nouvelle migration numérotée », plus « dans le même `InitSQL` » ; le `docs/architecture/data-architecture.md`, le `docs/administration/` et le PRA disent comment lire la version d'une base.

**Conséquences**
- (+) Deux réplicas qui démarrent ensemble ne se gênent plus (test : N démarrages concurrents sur une base neuve, 0 échec ; contre-épreuve : sans le verrou, le test échoue).
- (+) La version d'une base se lit dans une table ; une migration modifiée après publication est refusée.
- (+) Une migration non additive a sa place, appliquée une seule fois.
- (−) Une migration longue bloque le démarrage de tous les réplicas sous le verrou.
- (−) Pas de migration descendante (`down`) : revenir en arrière, c'est restaurer une sauvegarde ou écrire une migration montante.
- (−) ~~Le verrou consultatif est par base : deux services sur la même base partageraient la clé~~ — sans objet : le verrou est par service (note de la règle 3).
- (−) Une migration s'exécute en transaction : `CREATE INDEX CONCURRENTLY` et les instructions qui refusent une transaction n'y ont pas leur place.
- (−) Un démarrage sur une base qui n'a jamais connu ADR-0030 rejoue `001_init.sql` une dernière fois, comme avant ; ce n'est qu'ensuite qu'il ne l'est plus.
- (−) **Un schéma abîmé à la main n'est plus réparé au démarrage** : avant, `001_init.sql` rejoué recréait une table, une colonne ou un index supprimés ; maintenant la version 1 est enregistrée et n'est plus rejouée — le service démarre, puis échoue à la première requête qui en a besoin. Constaté par les tests du Session Broker qui fabriquaient une « ancienne base » en retirant une colonne sans retirer sa ligne de `schema_migrations` (une vraie base d'avant n'en a pas : ils ont été corrigés pour le dire). Réparer, c'est restaurer, ou supprimer la ligne du service dans `schema_migrations` pour que `001_init.sql` soit rejoué.
- (+) **Mesuré** : avant, sur processus réels, quatre Session Brokers démarrés ensemble sur une base neuve, cinq tours → **15 réplicas sur 20 ne démarrent pas** ; après, **20 sur 20**, et 8 applicateurs × 20 tours sans un échec. Une migration modifiée après application refuse le démarrage en la nommant ; une base plus récente que le binaire démarre avec `WARNING` ; une base d'avant ADR-0030 garde ses données et devient version 1. **19 mutations : 18 tuées, 1 équivalente** (la migration exécutée sur la connexion plutôt que la transaction : `BEGIN` était déjà envoyé sur cette connexion) **remplacée par la vraie** (aucune transaction), tuée par un test ajouté (une migration et sa ligne sont une seule chose). 664 unitaires (617 sans base), 57 PostgreSQL, 61 d'intégration (44 sans base), `-race` propre.

**Alternatives envisagées**
- **golang-migrate, goose** : éprouvés, mais une dépendance par service, et rien qu'ils apportent ici ne manque à une centaine de lignes de bibliothèque standard (`policies.md` §4.1).
- **Garder `001_init.sql` rejoué à chaque démarrage** : laisse la course mesurée et l'absence de version.
- **Appliquer les migrations par un outil séparé, avant le déploiement** : plus de contrôle pour l'exploitant, mais un service qui démarrerait sur un schéma en retard ; possible plus tard en ajoutant un mode « vérifier seulement » au même code.
