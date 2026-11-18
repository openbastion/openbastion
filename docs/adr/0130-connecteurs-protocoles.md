# ADR-0130 — Les connecteurs et protocoles ne sont visibles qu’après preuve de disponibilité

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — Les écrans Infrastructure et Accès montrent des fournisseurs et protocoles dont certains sont planifiés en v0.0.1/v0.0.2.

**Décision**
1. Le catalogue de connecteurs et de protocoles est une projection de capacités déclarées côté serveur, versionnée et autorisée. Le client ne peut pas inscrire une cible ni choisir un endpoint réseau arbitraire.
2. Chaque connecteur expose uniquement `configured`, `connected`, `degraded`, `unavailable`, `not_configured` et un horodatage ; aucune URL interne, secret, certificat ou topologie n'est rendu.
3. Les cibles sont identifiées par références opaques et résolues côté service propriétaire après validation d'une allowlist d'adresses/plages, DNS contrôlé et règles egress. Protection SSRF obligatoire.
4. La présence d'un protocole dans la roadmap ne l'active pas. Une capacité est visible comme disponible seulement après tests d'interopérabilité, audit, isolation réseau et politique d'autorisation.
5. Les proxys sont le seul chemin d'accès. Les ports cibles sont refusés depuis les zones opérateur ; les règles réseau sont testées en CI/environnement de déploiement.

**Validation** — tests d'egress, DNS rebinding, accès direct interdit, cible non allowlistée, mTLS, autorisation et refus d'une capacité non installée.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
