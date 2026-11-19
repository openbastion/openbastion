# ADR-0129 — Les écrans roadmap distinguent les capacités livrées des capacités planifiées

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — Les maquettes constituent une référence visuelle mais certaines vues dépassent les fonctionnalités livrées. Il faut synchroniser les écrans avec MVP, v0.0.1 et v0.0.2 sans masquer les fonctions futures.

**Décision**
1. Chaque élément SVG est tracé vers un contrat public Gateway, service propriétaire, ADR, composant UI et tests. Un endpoint interne n'est jamais une source UI.
2. Statuts : `implemented`, `partial`, `planned`, `proposed`, `unavailable`. Chaque écran distingue données réelles, exemples fictifs de maquette et fonctions futures.
3. MVP : SSH/SFTP/SCP, Vault, demandes immédiates, audit/replay texte et OIDC. v0.0.1 : RDP/VNC, DB/Kubernetes, workflows, MFA, secrets dynamiques, vidéo, recherche, fédération et clients. v0.0.2 : protocoles étendus, risque, reporting et forensics.
4. Les écrans planifiés sont des propositions UX ; ils ne créent ni contrat ni permission implicite. Les éléments non livrés sont étiquetés « prévu » et n'ont pas de contrôles actifs.
5. La CI valide XML, liens ADR/contrats et manifeste de traçabilité. Une revue humaine compare les rendus PNG aux références avant acceptation.

**Validation** — aucun compteur fictif dans les écrans livrés ; aucun contrôle actif sans endpoint Gateway testé ; aucun lien vers une route interne ; couverture complète du manifeste.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
