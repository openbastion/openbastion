# ADR-0122 — La file d’alertes de session sépare détection, visibilité et acquittement

**Statut** `Accepté` · 2026-11-23 · complément Zero Trust et intégration Gateway de l’ADR-0117.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — L'écran Alertes suggère des détections géographiques, horaires, de commandes et de transferts qui ne sont pas toutes émises par les producteurs. ADR-0117 propose déjà une file durable détenue par Audit Service.

**Décision**
1. ADR-0117 reste le contrat de base : occurrence issue d'un événement source authentifié, règle versionnée, sévérité décidée côté serveur, outbox durable et acquittement audité.
2. Les signaux absents restent désactivés. Pas d'alerte synthétique, pas de règle modifiable depuis le navigateur, pas de sévérité client.
3. Les routes publiques `GET /session-alerts`, `/summary`, `/{id}` et `/{id}/acknowledge` sont uniquement des routes Gateway. Permissions distinctes `session-alerts:read` et `session-alerts:acknowledge`; l'accès à la session liée reste soumis à `session.read`.
4. Les appels Gateway→Audit sont mTLS avec identité `api-gateway`, payload minimal et réponses bornées. Le port Audit ne doit pas être accessible depuis les réseaux clients.
5. Les alertes comportementales (pays, horaire, commande inhabituelle, volume) ne sont activées qu'après ADR de source, minimisation, seuils, tests anti-faux positifs et procédure de désactivation.

**Validation** — tests de provenance mTLS, absence de fuite, idempotence, concurrence d'acquittement, reprise outbox, filtrage par principal et fail-closed.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.


**État d’implémentation — 24 novembre 2026** — Les lectures Audit Service (mTLS) et la façade publique Gateway de liste, résumé et détail sont livrées. La Gateway vérifie `session-alerts:read` avec l'identité utilisateur issue du bearer token ; la ressource est `session-alerts:all` pour la collection/le résumé et `session-alerts:{id}` pour le détail. La Gateway est explicitement autorisée par la CallerRules mTLS d'Authorization à demander `check-access`. L’incrément `feat/session-alert-acknowledgement` ajoute l’acquittement signé et transactionnel sous `session-alerts:acknowledge`, avec `expected_revision`, idempotence et conflit sur révision obsolète. L’intégration Admin UI est livrée : `Sessions > Alertes` consomme exclusivement les routes publiques Gateway, affiche le résumé cohérent et la file paginée (filtres statut/sévérité), et propose l’acquittement après confirmation avec `expected_revision`. Après succès, la file et le résumé sont rechargés ; un `409` ferme la confirmation obsolète et rafraîchit les données, tandis que `403` et `503` restent explicitement visibles sans annoncer d’acquittement. L’interface ne déduit aucun droit depuis les rôles du navigateur et ne donne pas accès aux sessions associées ; les signaux comportementaux, géographiques et horaires restent désactivés.
