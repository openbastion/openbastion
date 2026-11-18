# ADR-0121 — Les écrans de supervision ne présentent que des métriques issues de contrats vérifiés

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — Le Dashboard SVG comporte des valeurs fixes (sessions actives, couverture MFA, conformité, score Zero Trust, séries temporelles) alors que `Overview.tsx` ne lit que les comptes Vault et les demandes en attente.

**Décision**
1. Chaque métrique affichée doit référencer un endpoint Gateway public, un schéma versionné, un producteur propriétaire, une permission et des tests contractuels.
2. Les métriques sont calculées côté serveur sur un instantané cohérent ; le client ne reconstitue pas des totaux globaux à partir d'échantillons paginés.
3. États obligatoires : loading, empty, partial, unavailable, error et as-of. Une absence de données n'est jamais zéro ni healthy.
4. Aucun score de conformité, MFA, risque ou disponibilité sans population, dénominateur, couverture et méthode vérifiables.
5. Le Dashboard MVP/v0.0.1 ne présente que comptes, rotations, demandes d'accès et signaux dont les contrats sont livrés. Les métriques v0.0.2 restent masquées jusqu'à activation explicite.

**Validation** — tests API/UI pour pagination tronquée, panne, permissions, données périmées, incohérence d'instantané et absence de source. Aucune donnée synthétique en production.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
