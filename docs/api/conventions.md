# Conventions de l'API publique

| Aspect | Convention |
|---|---|
| Préfixe de version | `/api/v1` — toute rupture de compatibilité incrémente le préfixe, jamais de rupture silencieuse sur v1 |
| Authentification | Bearer JWT (émis par `POST /auth/login`, ADR-0007 — Keycloak en émetteur sous-jacent) |
| Pagination | `page` / `pageSize` en requête, enveloppe `{ items, page, pageSize, totalItems }` en réponse |
| Erreurs | Enveloppe unique `Error { code, message, traceId }`, `traceId` corrélé à OpenTelemetry |
| Horodatage | ISO 8601 / RFC 3339, UTC |
| Idempotence | Les endpoints de mutation sensibles (`POST /sessions`, `POST .../rotate`) acceptent un header `Idempotency-Key` |
| Limitation de débit | Le Gateway répond `429` avec un `Retry-After` vrai (secondes, arrondies au-dessus). Trois limites : **par adresse de client** pour `/auth/login` (rafale 5 puis 1 par minute) et pour toute requête authentifiée (rafale 60 puis 60 par minute), **par utilisateur** pour `POST /sessions` (rafale 10 puis 6 par minute) et, dans un seau à part, pour `…/approve`, `…/reject` et `…/connect` (rafale 10 puis 6 par minute) — réglables, jamais « illimitées » (ADR-0014, ADR-0015, ADR-0016). Derrière un reverse proxy, l'adresse du client n'est celle de `X-Forwarded-For` que si l'opérateur a déclaré le proxy (`TRUSTED_PROXY_CIDRS`) ; sinon c'est celle du pair |

Ce que cette API REST **n'expose jamais** : un secret cible en clair. `POST /sessions/{id}/connect` renvoie un ticket de connexion court terme vers le proxy protocolaire, jamais un mot de passe (ADR-0003) — cohérent avec l'invariant posé dès le `docs/architecture/system-overview.md`.
