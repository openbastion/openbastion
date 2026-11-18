# ADR-0125 — Les sessions et relectures exposent uniquement les capacités réellement acquittées

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — Les SVG Sessions et Enregistrements promettent sessions actives globales, HTTP, export et intégrité globale, alors que les capacités varient selon protocole et incrément.

**Décision**
1. Les listes de sessions actives ne sont affichées que si un endpoint Gateway global et filtré par autorisation existe ; pas de déduction depuis `pending_approval`.
2. Chaque enregistrement porte protocole, type (terminal/vidéo/marqueurs), état, couverture, pertes et limites. Les marqueurs ADR-0111 ne sont pas des images ni une preuve d'intégrité.
3. Replay vidéo VNC/RDP et replay texte SSH restent distincts. Le client ne concatène jamais des segments non autorisés ou hors fenêtre.
4. Recherche plein texte suit ADR-0080 : déchiffrement à la volée, fenêtre bornée, aucune indexation de secrets/clipboard.
5. Toute capture clipboard, transfert, impression ou export est désactivée tant que protocole, consentement/politique, filtrage secret, audit et tests ne sont pas livrés.
6. Vérification de chaîne reste admin-cli only (ADR-0119) ; un écran ne peut afficher « intégrité vérifiée » sur la seule base d'un replay disponible.

**Validation** — tests de droits session/recording distincts, bornes temporelles, pagination, pertes, absence de données inter-session et refus des fonctions non prises en charge.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
