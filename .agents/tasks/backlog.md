# Backlog

Ce qui reste à faire, du plus prioritaire au moins prioritaire. La source détaillée et datée des limites est `NOTES_SANDBOX.md` (« Ce que cela ne fait PAS ») et `docs/security/known-limitations.md` ; une ligne refermée se barre ici et là-bas, avec ce qui l'a refermée.

| # | Sujet | Pourquoi | Où c'est écrit |
|---|---|---|---|
| 1 | ~~**Exécuter les rotations `scheduled`**~~ — **fait** (ADR-0040) | ~~acceptées à l'enregistrement, lancées par rien~~ | ADR-0040 |
| 1 bis | ~~Fenêtres horaires et alerte après plusieurs échecs d'une rotation planifiée~~ — **fait** (ADR-0041) | ~~un compte peut tourner en pleine journée ; un échec est retenté chaque heure sans alerte~~ | ADR-0041 |
| 1 ter | ~~Notification poussée des alertes (`vault.rotation_overdue`, …)~~ — **fait** (ADR-0045 ; ~~file durable~~ ADR-0057) | ~~l'alerte n'est visible que dans l'audit~~ | ADR-0045, ADR-0057 |
| 2 | ~~Réessayer une rotation après usage échouée~~ — **fait** (ADR-0044) | ~~un échec laisse l'ancien secret en place jusqu'à la prochaine fin de session~~ | ADR-0044 |
| 3 | ~~Relayer le motif d'un `409` du Vault à l'opérateur~~ — **fait** (ADR-0042) | ~~`connect` dit « authorize-scope: status 409 » sans dire pourquoi~~ | ADR-0042 |
| 3 bis | ~~Revoir les autres routes publiques ; refuser dès `POST /sessions` un compte non épinglé~~ — **fait** (ADR-0043) | ~~les routes d'administration relaient encore le texte des refus d'écriture du Vault~~ | ADR-0043 |
| 4 | ~~Proxy SSH en plusieurs instances~~ — **fait** (ADR-0046) | ~~la révocation n'atteint qu'une instance~~ ; reste : une instance injoignable empêche toute terminaison | ADR-0046 |
| 5 | ~~Pipeline de CI~~ — **fait** (ADR-0047) | ~~aucune porte automatique aujourd'hui~~ ; reste : ~~exiger ses jobs dans la protection de `main`~~ (règle posée, non appliquée sur l'offre gratuite), ~~`govulncheck`/`npm audit`~~ (ADR-0052) | ADR-0047, ADR-0052 |
| 6 | ~~Certificats d'hôte SSH (autorité) à côté de l'épinglage~~ — **fait** (ADR-0048) | ~~une seule clé par compte~~ ; reste : ~~pas de liste de révocation~~ (ADR-0054, par clé), une autorité par compte | ADR-0048, ADR-0054 |
| 7 | ~~Vrai KMS/HSM à la place de `LocalKMS`~~ — **fait** (ADR-0049, Transit d'OpenBao) | ~~la KEK est locale~~ ; reste : ~~renouvellement du jeton~~ (ADR-0053), ~~AppRole~~ (ADR-0058), ~~ré-enveloppement en masse~~ (ADR-0055) | ADR-0049, ADR-0053, ADR-0055, ADR-0058 |
| 8 | ~~gRPC à la place de HTTP/JSON~~ — **écarté** (ADR-0050) : HTTP/JSON sous mTLS décidé, test de contrat ; à rouvrir avec un flux réel, des clients non Go ou une mesure | — | ADR-0050 |
| 9 | ~~Images de base épinglées par empreinte~~ — **fait** (ADR-0051) | ~~reproductible pour le code, pas pour les images~~ ; reste : ~~mise à jour manuelle des empreintes~~ (proposée par Dependabot, ADR-0059, sauf l'image OpenBao des tests) ; images de construction sur Go 1.27.1 depuis le même jour | ADR-0051 |
| 10 | Feuille de route v0.0.1 (RDP, Workflow/Approval Engine, MFA natif…) — **en cours** : ~~LDAP/AD~~ (ADR-0061), ~~MFA TOTP par rôle~~ (ADR-0062), ~~audit des connexions~~ (ADR-0064), ~~WebAuthn~~ (ADR-0065), ~~clé de secours~~ (ADR-0066), ~~Video Recorder et API de replay~~ (ADR-0070) faits ; **ADR-0071 en cours** : contrat écran, pinning TLS, cycle de vie partagé `proxycore.ServeScreen` et client VNC RFB 3.8 (fondation protocolaire, non reliée au service) livrés ; raccordement du Vault aux métadonnées d’écran et au Video Recorder, serveur proxy, moteur RDP, entrée opérateur, Gateway WebSocket et lecteur UI restent | hors MVP | `roadmap.md`, ADR-0061, ADR-0062, ADR-0064, ADR-0065, ADR-0066, ADR-0070 |
