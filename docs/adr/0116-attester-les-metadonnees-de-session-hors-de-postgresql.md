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
