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

