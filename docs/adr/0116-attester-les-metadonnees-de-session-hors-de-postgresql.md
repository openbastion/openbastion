# ADR-0116 — Attester les métadonnées de session hors de PostgreSQL

**Statut** `Accepté` · 2026-11-16 · accepté par le propriétaire du projet pour l'incrément SI-08.

**Contexte** — Les identifiants PostgreSQL distincts limitent le rayon d'impact entre services, mais ne protègent pas une ligne `sessions` contre un rôle autorisé à l'altérer. Un rôle Session Broker compromis peut tenter de modifier le demandeur, le compte privilégié, le protocole, la justification, les droits, les dates, le statut ou les décisions d'approbation. Une signature stockée dans la même ligne ne suffit pas : sans tête de version indépendante, un attaquant peut restaurer une ancienne ligne valide (rejeu/rollback).

L'intégrité doit donc être vérifiée indépendamment de la base du Session Broker, y compris après redémarrage et après archivage de la chaîne d'audit. La protection couvre les décisions d'accès et de routage ; elle ne prétend pas rendre PostgreSQL disponible ni empêcher la suppression de données.

**Décision**

1. Le Session Broker calcule un HMAC-SHA-256 sur une représentation canonique, versionnée et à champs préfixés par leur longueur. Le domaine est `openbastion/session-metadata/v1\0`. La représentation couvre tous les champs persistés qui peuvent influencer l'identité, l'autorisation, la cible, le protocole, le cycle de vie, les approbations, les droits et les échéances. Le MAC couvre aussi explicitement la version de format, `metadata_revision` et `metadata_key_id` ; `metadata_sha256` est le SHA-256 du snapshot canonique. Le JSON n'est pas utilisé comme format cryptographique.
2. La clé HMAC est un secret de 32 octets lu depuis `SESSION_METADATA_HMAC_KEY_FILE` (fichier propriétaire du service, mode `0600`), jamais stocké dans PostgreSQL ni transmis à l'Audit Service. Chaque ligne porte `metadata_revision`, `metadata_key_id` et `metadata_mac`. Toute mutation incrémente la révision sous verrou/compare-and-swap et recalcule le MAC.
3. L'Audit Service est l'ancre indépendante de monotonie. Pour chaque révision, le Broker lui transmet `session_id`, `revision`, `metadata_sha256` et `key_id`. L'Audit Service écrit `session.metadata_attested` dans sa chaîne HMAC et maintient dans sa propre base un projection/head par session (`revision`, `digest`, `event_id`), transactionnellement avec l'événement. Son rôle PostgreSQL est distinct et le rôle du Broker ne peut ni lire ni modifier directement cette projection.
4. L'API interne de l'Audit Service expose au seul certificat mTLS `session-broker` l'ajout idempotent d'une attestation et la lecture de la tête courante. La projection est vérifiée contre l'événement signé qu'elle référence ; aucune donnée secrète de credential n'est incluse, uniquement l'identifiant de session, une révision et un digest.
5. Ordre d'écriture : le Broker écrit la nouvelle ligne avec sa révision et son MAC, puis demande l'attestation Audit. Il ne confirme pas l'opération tant que l'attestation n'est pas confirmée. Si le Broker tombe ou si Audit est momentanément indisponible après le commit SQL, une lecture peut réparer idempotemment une ligne exactement une révision en avance, seulement après vérification du HMAC. Un écart supérieur à un est refusé.
6. Toute lecture de session destinée à une décision de sécurité vérifie d'abord le HMAC puis compare la ligne à la tête Audit : même révision et même digest = valide ; révision de ligne inférieure = rollback ; même révision avec digest différent = altération ; ligne exactement une révision au-dessus avec HMAC valide = tentative de réconciliation idempotente ; toute autre divergence ou indisponibilité Audit = refus fail-closed. Aucun cache de tête n'est autorisé dans la première version.
7. La rotation de clé est versionnée par `metadata_key_id` : le Broker sait vérifier la clé courante et la précédente pendant une période bornée, puis ré-atteste toutes les lignes avant retrait de l'ancienne clé. La clé ne quitte jamais le processus Broker.
8. Migration sûre : le déploiement exige une fenêtre de maintenance et zéro session `pending` ou `active`. La migration refuse de continuer si une telle session existe. Les lignes historiques terminées/expirées/refusées sans attestation restent `legacy_unverified`, visibles en lecture seule avec un avertissement ; elles ne sont jamais signées automatiquement à partir d'une ligne potentiellement altérée et ne peuvent être reconnectées ni utilisées pour une action privilégiée. Les nouvelles sessions sont attestées dès leur création.
9. L'implémentation couvre tous les chemins d'écriture (création, approbation, refus, terminaison, expiration et mise à jour des indicateurs de rotation/audit) et tous les chemins de lecture utilisés par `connect`, `approve`, `terminate`, `secret-injection`, recherche et administration. Un chemin oublié est un défaut de sécurité P1.

**Conséquences**

- (+) Une altération de champ, un MAC falsifié ou la restauration d'une ancienne ligne est détecté indépendamment de PostgreSQL Session Broker.
- (+) La tête de révision persiste dans la base propre à l'Audit Service et reste disponible après archivage des événements ; les ancres et la chaîne signée conservent la preuve.
- (+) Un rôle PostgreSQL du Broker ne possède ni la clé HMAC ni les droits sur la tête Audit.
- (−) Les opérations de lecture de session dépendent de la disponibilité de l'Audit Service ; sans réponse, elles échouent fermées. La latence et le débit doivent être mesurés avant production.
- (−) La migration impose une fenêtre de maintenance et la terminaison préalable des sessions actives/en attente ; l'historique préexistant reste explicitement non attesté.
- (−) La suppression de la ligne peut toujours provoquer un déni de service ; la restauration d'une sauvegarde cohérente de la base Broker sans la tête Audit est refusée et doit passer par une procédure de réconciliation opérateur.

**Alternatives envisagées**

- **HMAC uniquement dans la ligne PostgreSQL** : rejeté, car une ancienne ligne avec un MAC valide peut être rejouée.
- **Hash simple ou signature avec clé dans PostgreSQL** : rejeté, car l'attaquant peut recalculer le hash ou récupérer la clé dans le même domaine de compromission.
- **Redis comme compteur monotone** : rejeté, car le cache n'est pas une ancre durable et son redémarrage/réplication ne constitue pas une preuve.
- **Conserver un compteur dans le processus Broker** : rejeté, car il disparaît au redémarrage et ne fonctionne pas en multi-réplicas.
- **Signer automatiquement toutes les lignes historiques à la migration** : rejeté, car cela pourrait légitimer des métadonnées déjà altérées avant le déploiement.

**Critères de validation**

- Mutation directe SQL de chaque champ protégé : HMAC invalide et aucune session exploitable.
- Restauration d'une ancienne ligne après terminaison : révision inférieure à la tête Audit, refusée.
- MAC, digest ou `metadata_key_id` falsifiés : refus fail-closed.
- Audit indisponible, tête manquante, projection incohérente ou chaîne/ancres invalides : aucune opération privilégiée ne continue.
- Crash entre commit PostgreSQL et attestation : réparation idempotente d'une seule révision valide ; écart supérieur à un refusé.
- Courses de mise à jour entre deux réplicas : révisions strictement monotones, aucune attestation perdue ni réutilisée.
- Migration : refus si une session active/en attente subsiste ; historique non attesté explicitement read-only.
- Tests d'intégration avec un rôle PostgreSQL Broker incapable de lire/écrire la tête Audit, plus test de restauration/restart.

## Mise en œuvre

Quatre incréments, dans cet ordre (découpage décidé le 22 novembre 2026, renversable) :

1. **Le HMAC par ligne, côté Broker** : forme canonique, clé, migration, signature à chaque écriture et vérification à chaque lecture, refus des lignes altérées ou legacy.
2. **La tête dans l'Audit Service** : `session.metadata_attested` dans la chaîne, la projection par session, l'API interne réservée au Broker (§3, §4).
3. **La comparaison à chaque lecture** et la réparation idempotente d'une révision d'avance (§5, §6).
4. **La ré-attestation d'une rotation** avant le retrait de l'ancienne clé (§7), et les tests avec des rôles PostgreSQL distincts.

### Incrément 1 — le HMAC par ligne (22 novembre 2026)

- **Fait** :
  - `domain/metadata.go` : la forme canonique v1 (un octet de version, puis chaque champ dans un ordre fixe, préfixé par sa longueur), le MAC sur le domaine, la révision, l'identifiant de clé et la forme canonique, `metadata_sha256` prêt pour l'incrément 2.
    - Champs couverts : l'identité, la cible, la justification et le ticket, le cycle de vie, l'approbation, les droits (break-glass, presse-papiers) et la dette de fin de session envers le Vault (ADR-0044), dont la perte sauterait une rotation.
    - Non couverts : `expiry_audited`, la tenue de la livraison de l'audit d'une expiration, qui n'accorde rien ; `expired_at`, qui ne sert qu'à dater la fin envoyée au Vault.
    - Les temps sont ceux de PostgreSQL (microsecondes, UTC).
  - `SESSION_METADATA_HMAC_KEY_FILE` (fichier `0600`, 32 octets), obligatoire avec `DATABASE_URL` ; `SESSION_METADATA_HMAC_KEY_ID` ; une clé précédente pendant une rotation, qui vérifie encore ce qu'elle a signé, chaque changement étant re-signé sous la courante. En Compose, le job `pki` la tire une seule fois.
  - Migration `007_metadata_attestation.sql`, idempotente : elle refuse de s'appliquer tant qu'une session est en attente ou active, qu'une expiration reste à auditer ou qu'une fin reste à dire au Vault ; elle marque l'historique `legacy_unverified`.
  - Le stockage PostgreSQL : toute écriture (création, `Save`, compare-and-swap, quota, balayage des expirations, effacement de la dette) verrouille la ligne, la vérifie, applique le changement, signe la révision suivante et l'écrit sous condition de la révision lue. Les deux mises à jour en masse deviennent des écritures ligne à ligne. Toute lecture vérifie le MAC : `Get` et les listes qu'un opérateur suit échouent fermées ; les balayages en arrière-plan passent la ligne altérée sans s'arrêter (elle n'est utilisée par personne). Une ligne legacy n'est jamais modifiée, ni comptée, ni listée parmi les demandes à décider, ni expirée, ni réclamée au Vault.
  - Le service refuse la connexion, la terminaison, la décision et toute saisie de secret (Vault ou opérateur) sur une ligne non attestée ; la lecture d'une session legacy reste permise. HTTP : `409` pour une ligne legacy, `500` sans détail pour une ligne altérée, que le journal du Broker nomme.
- **Prouvé** :
  - le domaine : chacun des 19 champs protégés, changé seul, casse le MAC ; une autre révision, une autre clé, un MAC tronqué ou un bit changé sont refusés ; les frontières des champs sont non ambiguës ;
  - sur PostgreSQL réel : une écriture SQL de chacune des 20 colonnes protégées (les 17 champs, la révision, l'identifiant de clé, le MAC) rend la ligne inutilisable par `Get`, le compare-and-swap, `Save` et la liste des demandes ; une clé non détenue est refusée, la précédente d'une rotation vérifie, et le changement suivant est re-signé ; deux réplicas qui changent la même ligne donnent deux révisions de plus, aucune perdue ; le balayage signe ce qu'il expire et passe une ligne altérée ; une dette forgée n'atteint pas le Vault ; une ligne legacy est en lecture seule ; la migration refuse une base avec une session vivante, puis passe une fois la session terminée ;
  - le service : une session legacy se lit mais ne se connecte pas, ne se termine pas, ne se décide pas et ne reçoit aucun secret ; une session altérée ne se lit même pas ;
  - contre-épreuves : sans la vérification, avec un champ retiré de la forme canonique, avec une ligne legacy dans la liste, sans la garde de la migration, sans le refus à la connexion : les tests échouent.
- **Reste** (incrément 2 d'abord) : **le rejeu d'une ancienne ligne entière n'est pas encore détecté** — une ligne restaurée à une révision antérieure porte un MAC valide ; c'est la tête de l'Audit Service qui l'arrêtera. L'Admin UI ne signale pas encore une session legacy.

### Incrément 2 — la tête dans l'Audit Service (22 novembre 2026)

- **Fait** :
  - Audit Service : la table `session_metadata_heads` (migration 004), l'événement `session.metadata_attested` écrit avec la tête dans **une** transaction, et les deux routes internes réservées au Broker (`docs/api/internal/audit-service.md`).
    - Attester : une révision qui suit la tête l'avance ; la même révision avec le même digest ne change rien ; une révision plus ancienne, la même avec un autre digest ou une autre clé, ou plus d'une d'avance sont refusées (`409`) sans rien écrire.
    - Lire : la tête n'est rendue qu'une fois recalculée en l'événement signé qu'elle nomme ; elle le reste après l'archivage de cet événement.
    - Une session sans tête accepte sa première attestation à toute révision : ce sont les lignes signées avant cet incrément, ou celles dont la première attestation s'est perdue. Choix renversable, sans lequel ces sessions seraient refusées pour toujours ; l'incrément 3 dira ce qu'une lecture fait d'une session sans tête.
  - Broker : chaque changement validé en base est attesté (création, `Save`, compare-and-swap, quota, effacement de la dette) ; il n'est confirmé à l'appelant qu'une fois la tête avancée. Une attestation qui échoue donne `ErrUnavailable` (la ligne est écrite, une révision en avance) ; une tête qui refuse donne `ErrMetadataIntegrity`. Le balayage des expirations attestera ce qu'il expire, et ne s'arrête pas si l'Audit Service ne répond pas. La terminaison prévient le proxy avant d'écrire : une attestation qui échoue ne laisse jamais une session vivante au proxy.
- **Prouvé** :
  - Audit, en mémoire et sur PostgreSQL réel (schéma isolé) : la suite des révisions, l'idempotence sans nouvel événement, les trois refus sans rien écrire, l'émetteur (le Broker seul), les champs mal formés ; une tête modifiée (révision, digest, clé, événement, émetteur, ou en SQL) ne se recalcule plus ; une tête reste vérifiable une fois ses événements sortis de la base ; la chaîne se vérifie avec ses attestations ; une tête qui a bougé n'écrit ni l'événement ni la tête ; les règles d'appel (le Broker seul).
  - Broker, sur PostgreSQL réel : les révisions 1, 2, 3 d'une session sont attestées dans l'ordre ; une attestation échouée n'est pas confirmée, une tête qui refuse est une erreur d'intégrité ; le balayage expire malgré l'Audit Service absent.
  - **Entre deux vrais processus** : un Broker qui expire une session fait avancer sa tête dans un vrai Audit Service à la révision 2, avec l'empreinte que le signataire indépendant de `test/integration` calcule pour la ligne expirée.
  - Contre-épreuves : un retour en arrière accepté, une tête non recalculée, un `Save` non attesté, et les tests échouent. La garde « tête déplacée » de l'Audit Service est doublée par la condition de l'upsert : retirer l'une seule ne suffit pas à écrire.
- **Reste** : **la lecture ne compare pas encore la ligne à la tête** (incrément 3) : tant qu'elle ne le fait pas, une ancienne ligne restaurée n'est toujours pas refusée. Puis la ré-attestation d'une rotation et les rôles PostgreSQL distincts (incrément 4).

### Incrément 3 — chaque lecture compare la ligne à sa tête (22 novembre 2026)

- **Fait** : `Get`, la lecture dont dépendent la connexion, la terminaison, la décision, toute saisie de secret et la lecture d'une session, vérifie le MAC, puis lit la tête de la session dans l'Audit Service, sans cache (§6) :
  - même révision et même digest : la ligne est valide ;
  - une révision plus ancienne que la tête : **retour en arrière, refusé** (`500`, le journal du Broker le nomme) ;
  - la révision de la tête avec un autre digest : altération, refusée ;
  - exactement une révision d'avance (un changement dont l'attestation s'est perdue, §5), ou une session sans tête : la ligne est attestée à cet instant, puis utilisée ;
  - plus d'une révision d'avance, une tête que l'Audit Service trouve altérée, ou un Audit Service qui ne répond pas : refusée (`503` pour l'indisponibilité, l'erreur d'intégrité sinon).
  - Une ligne legacy ne demande rien : elle est en lecture seule de toute façon.
  - Les listes d'affichage (recherche, demandes à décider) et les balayages en arrière-plan gardent la vérification du MAC seule ; chaque action passe ensuite par `Get`. Choix renversable : comparer chaque ligne d'une liste coûterait une requête à l'Audit Service par ligne.
- **Prouvé** :
  - sur PostgreSQL réel, avec un registre qui applique les règles de l'Audit Service : la tête valide ; une sauvegarde restaurée par-dessus une révision plus récente, dont le MAC est valide, est refusée ; une révision d'avance est attestée puis utilisée ; deux d'avance sont refusées sans même être proposées à l'Audit Service ; une session sans tête est attestée ; une tête altérée et un Audit Service absent sont refusés ; une ligne legacy ne demande rien ;
  - **entre deux vrais processus** : une ligne signée, lue (la tête naît à 1), terminée en révision 2 (signée par le signataire indépendant, attestée par la lecture suivante), puis la sauvegarde de la révision 1 remise en place : le vrai Broker la refuse (`500`) et dit « rolled back » ;
  - contre-épreuves : sans la comparaison, en réparant toute révision d'avance, en se fiant à un Audit Service absent : les tests échouent.
- **Conséquence** (§ Conséquences, déjà dite) : toute lecture de session dépend désormais de l'Audit Service ; sans lui, elle échoue fermée.
- **Fait** (incrément 4, 22 novembre 2026) : la ré-attestation de toutes les lignes avant le retrait d'une ancienne clé (§7), les tests de rôles PostgreSQL distincts et la mesure initiale du coût de lecture.

### Incrément 4 — rotation, séparation des rôles et coût de lecture (22 novembre 2026)

- **Fait** :
  - Au démarrage, le Broker recense les lignes par `metadata_key_id` et avertit explicitement pour chaque clé qu'il ne détient pas ; ces lignes restent refusées.
  - Si une clé précédente est configurée, le Broker ré-atteste en arrière-plan des lots de 200 lignes par minute. Chaque ligne est vérifiée sous sa clé d'origine puis comparée à sa tête Audit avant d'être réécrite sous la clé courante à une nouvelle révision et attestée. Une ligne altérée, revenue en arrière ou signée sous une clé inconnue n'est jamais légitimée par la rotation. Le journal annonce le nombre restant et le retrait possible de l'ancienne clé seulement lorsque le compteur atteint zéro.
  - L'API `probe` de l'Audit Service permet au healthcheck Compose de sonder le service sans shell dans son image distroless ; le Gateway peut donc attendre son état sain. Le test Compose a aussi révélé que `pg_isready` sur socket Unix déclarait PostgreSQL sain pendant son serveur temporaire d'initialisation : les services dépendants redémarraient avant le serveur TCP définitif. Le healthcheck force désormais `127.0.0.1` en TCP.
  - Le test Compose vérifie que le rôle `session_broker` ouvre sa propre base, mais ne peut pas ouvrir celle de `audit_service` (ni celles des autres services) : il ne peut donc ni lire ni modifier `session_metadata_heads`. La chaîne attendue inclut désormais `session.metadata_attested` entre `session.create` et `session.connect`.
  - La mesure séquentielle initiale (22 novembre) lançait un Broker, un Audit Service et PostgreSQL ; elle faisait 20 lectures d'échauffement puis 500 lectures séquentielles. Le test à la demande a depuis été étendu : deux Brokers, un Audit Service, PostgreSQL, mTLS, connexions persistantes et niveaux de concurrence 1/8/32/64 ; il fournit sa clé de chaîne Audit éphémère et un fichier d'ancres temporaire.
- **Prouvé** :
  - PostgreSQL réel : une ligne honnête est ré-attestée sous la nouvelle clé à la révision suivante ; une ligne altérée et une ligne restaurée à une révision antérieure restent refusées, même après retrait de l'ancienne clé ; un second passage ne les rend pas valides.
  - Entre deux vrais processus : la création/expiration fait avancer la tête Audit ; la restauration d'une ligne signée antérieure est refusée par le Broker.
  - Les tests du stockage PostgreSQL du Broker et les tests d'intégration ciblés passent sur PostgreSQL 16 réel.
  - `COMPOSE_TEST=1 go test -run '^TestCompose_TheMVPJourneyOnARealDockerComposeStack$' -count=1 -v` passe : démarrage complet, healthchecks, séparation des rôles, parcours SSH, chaîne d'audit, absence de secrets dans les logs et persistance après redémarrage. Le job « Docker Compose / full MVP journey » est requis dans la CI et a passé dans le run `45023573283` (PR #277).
- **Mesure locale séquentielle de référence** (LT209227, PostgreSQL 16 en conteneur, 22 novembre 2026, 500 échantillons après 20 échauffements, HTTP local, `INTERNAL_TLS=disabled`) :

  | Opération | p50 | p95 | p99 |
  | --- | ---: | ---: | ---: |
  | Lecture via Broker (HMAC + comparaison de tête) | 3,39 ms | 4,96 ms | 6,13 ms |
  | Lecture de la tête seule (requête Audit) | 1,62 ms | 2,99 ms | 3,86 ms |

  Cette première référence n'incluait ni mTLS ni concurrence. Les percentiles de deux séries distinctes ne se soustraient pas pour produire un coût marginal exact.
- **Mesure concurrente mTLS** (LT209227 sous WSL2, noyau 6.18.40.1, 6 vCPU visibles, 5,8 Gio RAM ; PostgreSQL 16.15 ; deux processus Broker et un Audit Service, tous sur le même hôte ; TLS 1.3, HTTP/1.1 persistant, loopback ; trois passages, 2 000 requêtes par endpoint et niveau, 20 échauffements par worker ; valeurs ci-dessous = médiane des trois passages) :

  | Endpoint | Concurrence | p50 | p95 | p99 | Débit médian |
  | --- | ---: | ---: | ---: | ---: | ---: |
  | Broker (HMAC + tête Audit) | 1 | 3,49 ms | 5,67 ms | 6,85 ms | 265 req/s |
  | Broker (HMAC + tête Audit) | 8 | 8,79 ms | 13,09 ms | 23,27 ms | 850 req/s |
  | Broker (HMAC + tête Audit) | 32 | 37,01 ms | 77,77 ms | 97,21 ms | 773 req/s |
  | Broker (HMAC + tête Audit) | 64 | 59,19 ms | 134,69 ms | 194,76 ms | 925 req/s |
  | Audit (lecture de tête seule) | 1 | 1,57 ms | 2,59 ms | 3,23 ms | 580 req/s |
  | Audit (lecture de tête seule) | 8 | 4,05 ms | 5,64 ms | 7,34 ms | 1 891 req/s |
  | Audit (lecture de tête seule) | 32 | 9,93 ms | 25,54 ms | 38,91 ms | 2 544 req/s |
  | Audit (lecture de tête seule) | 64 | 18,50 ms | 65,34 ms | 101,39 ms | 2 341 req/s |

  Les clients réutilisent les connexions TLS : le handshake est payé à l'ouverture de la connexion, pas à chaque requête. Le client du Broker présente le certificat `api-gateway` (appel direct pour isoler le chemin Broker) ; le client de comparaison Audit présente `session-broker`. Les deux Brokers partagent PostgreSQL, la clé HMAC et l'unique Audit Service. Ces chiffres sont des observations locales, pas des SLO.
- **Diagnostic de contention** (même hôte et même charge, instrumentation temporaire locale non conservée dans le code) :
  - Le block profile Go à 32 lecteurs attribue 24,06 s cumulées à `database/sql.(*DB).conn` dans l'Audit Service, sur 109,45 s de blocage cumulées dans le profil. Le chemin `AuditService.SessionMetadataHead` / `PostgresStore.MetadataHead` est le point d'attente ; côté Broker, `GetSession` passe une part importante de son attente dans `AuditHTTPClient.MetadataHead` / `http.Transport.RoundTrip`. Le profil mutex ne révèle pas de verrou applicatif dominant.
  - `DB.Stats()` confirme la saturation du pool Audit limité à 10 : sur une passe profilée, `WaitCount=7 669` et `WaitDuration=1 min 41 s` cumulées. Les deux pools Broker atteignent aussi 10 connexions, avec environ 700 et 500 attentes respectives, mais une attente cumulée plus faible. Ces compteurs sont cumulatifs entre goroutines, pas une durée murale.
  - Le plan de la lecture de tête utilise la clé primaire (`Index Scan`) ; l'essai isolé sur une clé absente s'exécute en environ 0,10 ms. Cela ne remplace pas une mesure de toutes les requêtes, mais ne suggère pas un scan de table.
- **Expérience contrôlée de dimensionnement** (trois passages par configuration, médiane des p95 et débits ; 2 000 requêtes par endpoint et niveau ; aucune modification conservée dans le code) :

  | Pool Broker / Audit | Concurrence | p95 Broker | Débit Broker | p95 Audit | Débit Audit |
  | --- | ---: | ---: | ---: | ---: | ---: |
  | 10 / 10 | 32 | 83,09 ms | 725 req/s | 28,14 ms | 2 296 req/s |
  | 10 / 20 | 32 | 46,63 ms | 1 262 req/s | 10,92 ms | 4 723 req/s |
  | 20 / 20 | 32 | 47,13 ms | 1 264 req/s | 10,83 ms | 4 870 req/s |
  | 10 / 10 | 64 | 156,65 ms | 790 req/s | 70,15 ms | 2 098 req/s |
  | 10 / 20 | 64 | 108,13 ms | 1 075 req/s | 40,67 ms | 3 399 req/s |
  | 20 / 20 | 64 | 97,87 ms | 1 258 req/s | 25,98 ms | 4 871 req/s |

  Augmenter le pool Audit de 10 à 20 réduit nettement la latence et augmente le débit. Porter aussi les pools Broker à 20 apporte un gain supplémentaire à 64 lecteurs, mais l'Audit atteint encore 20 connexions et cumule plusieurs milliers d'attentes. **Ce test ne justifie pas de remplacer le défaut global par 20** : sept services à 20 connexions dépasseraient les 100 connexions PostgreSQL par défaut, avant même les réplicas et les outils.
- **Décision provisoire** : garder le défaut 10 en production. Le prochain incrément doit concevoir des limites de pool configurables par service et un budget de connexions tenant compte du nombre de réplicas (`somme(instances × max_open) + marge <= max_connections`), puis mesurer ce budget. PgBouncer reste une option d'architecture à évaluer ; aucune mise en cache de la tête Audit ni aucun contournement de sa vérification n'est acceptable.
- **Limites de la mesure** : les deux Brokers et l'Audit Service tournent sur le même hôte WSL2 ; aucun RTT inter-hôtes, équilibrage réseau réel, Kubernetes/Envoy, seconde réplique Audit, handshake TLS par requête ni profil de charge de production n'est mesuré. Le benchmark ne suffit donc pas à qualifier un déploiement représentatif ni à fixer un SLO. La reproduction sur des hôtes distincts est différée à la demande de l'utilisateur.
- **Reste** : concevoir et valider le budget/configuration des pools sans modifier les invariants d'intégrité ; aucune valeur par défaut n'est changée par cette investigation. ~~Intégrer `test-compose` à la CI~~ — fait : le job « Docker Compose / full MVP journey » est requis et a passé dans le run CI `45023573283` (PR #277).

