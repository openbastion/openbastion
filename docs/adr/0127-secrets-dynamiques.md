# ADR-0127 — Les secrets dynamiques restent confinés au Vault et au proxy autorisé

**Statut** `Proposé` · 2026-11-18 · décision soumise au propriétaire ; cet ADR n'autorise aucune implémentation à lui seul.

**Invariant Zero Trust** — Aucun écran, navigateur, SDK ou client ne communique directement avec un microservice interne. Toute requête opérateur passe par l'API Gateway publique, avec authentification, autorisation Authorization sur ressource ET action (ADR-0114), limitation de débit, validation de schéma et journalisation. Les appels interservices restent privés, TLS mutuel, identités de workload dédiées, audiences et permissions minimales. Aucun certificat mTLS interne n'est distribué à l'Admin UI, au User Portal, au Desktop Client ou aux SDK. Refus par défaut ; panne d'identité, d'autorisation, de preuve ou de dépendance requise = échec fermé. Les routes internes ne sont jamais documentées comme API utilisateur et ne sont jamais exposées par ingress, NodePort, LoadBalancer ou reverse proxy public.

**Contexte** — v0.0.1 ajoute Secrets Manager et rotation planifiée/post-usage. L'écran ne doit jamais devenir un navigateur de secrets.

**Décision**
1. Secrets Manager et Password Vault restent propriétaires des valeurs ; API Gateway, Workflow, UI, notifications, logs, traces et événements ne transportent que des références opaques et métadonnées minimales.
2. Une injection est réalisée par le proxy autorisé dans le flux cible. Aucun secret n'est retourné au navigateur, SDK, Desktop Client, clipboard, variable de formulaire ou URL.
3. Les routes de lecture/rotation sont Gateway-only, permissionnées par ressource/action, et ne renvoient jamais le secret. Les opérations internes Vault restent mTLS, identités workload dédiées.
4. Les secrets dynamiques ont TTL, portée, audience, cible, session, révocation et rotation bornés. Pas de secret statique « exportable » pour faciliter l'UI.
5. Rotation après usage est confirmée uniquement après résultat source vérifié ; état inconnu reste inconnu et déclenche procédure de réconciliation, jamais un succès optimiste.
6. Les écrans affichent alias, propriétaire, politique, expiration et statut de rotation, jamais valeur, empreinte réversible ou URI d'accès contenant un secret.

**Validation** — tests canary pour fuite dans API/logs/traces/crash dumps, SSRF, privilèges croisés, révocation, TTL, rotation concurrente et injection sans exposition.

**Conséquences**

- (+) Les écrans deviennent vérifiables et cohérents avec les frontières Zero Trust.
- (+) Les routes internes et les identités mTLS restent confinées aux workloads autorisés.
- (−) Les fonctionnalités non livrées restent explicitement indisponibles jusqu’à implémentation et validation.

**Alternatives rejetées** — Appels directs depuis le navigateur, proxy générique de routes internes, données synthétiques présentées comme réelles, autorisation uniquement côté frontend, confiance implicite dans le réseau ou dans un rôle global.
