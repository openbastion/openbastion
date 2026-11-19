# ADR-0123 — Les journaux et preuves d’audit restent cloisonnés derrière la Gateway

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — L'écran Audit & conformité affiche actuellement des volumes et pourcentages non issus de contrats disponibles. `verify-chain` doit rester réservé à `admin-cli` par mTLS ; ADR-0113 n'autorise que la projection bornée des métadonnées d'injection.

**Décision**
1. Ne pas créer de proxy générique vers les routes internes Audit. Chaque projection UI exige un contrat distinct, une permission explicite et une liste de champs autorisés.
2. `GET /audit/secret-injections` demeure la seule projection d'injection exposée à l'Admin UI sous ADR-0113/0114. Aucun accès aux événements bruts, archives, checkpoints, clés, preuves cryptographiques ou verify-chain.
3. `GET /audit/v1/verify-chain` reste exclusivement mTLS `admin-cli`. Ni Gateway ni UI ne reçoivent cette capacité.
4. Les vues de conformité ne calculent pas ISO/SOC2/NIS2 sans catalogue de contrôles, preuves, couverture, période et propriétaire de contrôle. Les contrôles non évalués restent `not_evaluated`.
5. Tout nouveau flux audit public est une projection allowlistée, paginée, bornée, `Cache-Control: no-store`, expurgée et soumise à permission ressource+action.

**Validation** — tests négatifs pour api-gateway sur verify-chain, absence de route publique, absence d'accès brut, tests de schéma allowlist, pagination, fuite de secret et autorisation.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
