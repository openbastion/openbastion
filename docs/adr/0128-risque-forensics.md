# ADR-0128 — La détection de risque utilise des signaux minimisés et des règles explicables

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — v0.0.2 prévoit Anomaly Detection / Risk Engine et forensics. Les maquettes actuelles anticipent déjà scores et signaux non livrés.

**Décision**
1. Première version : règles déterministes versionnées, explicables, reproductibles et désactivables. ML optionnel et détachable, jamais requis pour autoriser une session.
2. Le moteur reçoit des événements minimisés via bus privé authentifié ; pas de collecte arbitraire des commandes complètes, clipboard ou contenu de session. Les signaux sensibles sont transformés en attributs dérivés lorsque possible.
3. Un score n'est affiché qu'avec version du modèle/règles, facteurs explicatifs, fraîcheur, couverture, seuils et incertitude. Score absent ou données insuffisantes = `unknown`, pas zéro.
4. Le moteur ne délivre aucune capacité réseau ni secret. Une décision d'accès reste prise par Authorization/Workflow sur une politique explicite ; le score peut uniquement déclencher une exigence additionnelle configurée.
5. Les signaux géographiques nécessitent une base de localisation documentée, minimisation et politique de rétention. Pas de profilage caché.
6. Le ML ne peut pas auto-approuver, révoquer ou ouvrir un accès ; il peut proposer un signal soumis à règles et validation humaine.

**Validation** — jeux de tests versionnés, faux positifs/négatifs, drift, résistance aux événements forgés, provenance mTLS, explicabilité, suppression/rétention et absence d'influence directe du modèle sur les privilèges.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
