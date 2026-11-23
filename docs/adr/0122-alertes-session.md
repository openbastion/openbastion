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
