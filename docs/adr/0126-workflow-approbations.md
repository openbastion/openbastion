# ADR-0126 — Les workflows d’accès imposent une approbation explicite et vérifiable

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — v0.0.1 inclut Workflow Service et Approval Engine. L'UI doit montrer demande, ticket, validateurs, échéance et décision sans permettre à un demandeur de s'approuver lui-même.

**Décision**
1. Les écrans Workflow/Approvals consomment exclusivement des routes Gateway ; appels internes Broker/Workflow/Authorization restent mTLS et non routables publiquement.
2. Les règles N+1, double validation, séparation demandeur/approbateur, durée maximale, fenêtre, expiration et ticket obligatoire sont évaluées côté serveur. L'UI ne décide jamais de l'éligibilité.
3. Ticket ServiceNow/Jira : v0.0.1 valide uniquement le format/présence selon ADR-0067, sans prétendre vérifier le ticket auprès de l'ITSM.
4. Chaque transition est idempotente, optimiste (revision), attribuée au principal vérifié et auditée. Le client ne fournit jamais actor, role, timestamp ou statut final.
5. Notifications Slack/Teams sont des canaux de notification, jamais des autorités d'approbation. Une approbation externe n'est acceptée que par un callback signé, anti-rejeu et lié à une demande.
6. Les refus, expirations et indisponibilités sont fail-closed. Aucun accès cible n'est ouvert avant décision positive et capacité de session à durée limitée.

**Validation** — tests SoD, approbation concurrente, auto-approbation, replay callback, expiration, ticket mal formé, panne Workflow/Authorization et journalisation.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
