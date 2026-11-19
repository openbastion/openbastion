# ADR-0124 — La santé des composants est agrégée sans exposer les routes internes

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — L'écran Infrastructure représente des nœuds, connecteurs, métriques et disponibilité sans producteur livré. ADR-0120 propose une santé agrégée.

**Décision**
1. ADR-0120 définit le seul modèle de santé UI initial : `healthy|degraded|unavailable|unknown`, distinction liveness/readiness, horodatage, fraîcheur et raison non sensible.
2. Le navigateur n'effectue aucun appel direct aux composants et ne reçoit jamais hostname interne, IP, port, namespace, topologie, certificat, endpoint ou détail de déploiement.
3. Un collecteur côté serveur utilise une allowlist statique de dépendances et des clients mTLS dédiés ; aucun URL, DNS ou endpoint fourni par l'utilisateur. Défense SSRF : résolution contrôlée, interdiction loopback/link-local/metadata, egress policy, timeout et taille bornés.
4. Les routes internes de health restent privées. Une projection Gateway expose uniquement un résumé agrégé autorisé, sans fan-out arbitraire demandé par le client.
5. La page affiche « non configuré » ou « inconnu » plutôt que des nœuds fictifs.

**Validation** — tests SSRF, DNS rebinding, timeout, dépendance compromise, divulgation topologie, mTLS et autorisation.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
