# ADR-0042 — Un refus dit son motif à l'opérateur par un code stable, et une panne ne dit jamais sa cause


**Contexte**
Depuis ADR-0039, un compte sans clé d'hôte épinglée n'ouvre aucune session : le Vault répond `409` à `authorize-scope`. Mais le Broker transformait toute réponse non `200` en « authorize-scope: status 409 », et `connect` renvoyait à l'opérateur le texte de **toute** erreur en `409`. L'opérateur ne savait donc pas quoi faire. Et une panne du proxy, du Vault ou du réseau lui arrivait avec son texte interne, adresse comprise (« establishing session on proxy: Post http://…: dial tcp … »). `POST /sessions` avait le même défaut : une panne de l'Authorization Service, de l'audit ou du magasin sortait en `403`, avec son texte, alors que le contrat (`docs/api/rest/openapi.yaml`) promet `503` sans la cause.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « Go pour la prochaine étape » : relayer le motif d'un 409 du Vault ; le reste est renversable)*
1. **Le Vault dit ses refus d'`authorize-scope` par un code stable**, en JSON : `{"code": "no_pinned_host_key", "error": "…"}` (`409`) ; tout autre refus : `{"code": "refused", …}` (`403`). Le code est le contrat ; le texte ne l'est pas.
2. **Le Broker traduit les codes qu'il connaît** en erreurs de domaine (`ErrAccountNotPinned`) ; un code inconnu reste une erreur sans texte du Vault.
3. **`connect` répond** :
   - `409` pour un état de la session, ou pour un compte qui n'est pas épinglé, avec une phrase qui dit quoi faire ;
   - `404` pour une session inconnue ;
   - `503` pour une dépendance qui ne répond pas, avec une phrase générique : la cause va au journal du Broker, jamais au client.
4. **`POST /sessions` répond `503`**, sans la cause, quand l'Authorization Service, l'audit ou le magasin ne répondent pas, comme le `docs/api/rest/openapi.yaml` le promettait ; un refus d'accès reste un `403`.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `9cd7be3`, processus réels et vraie base, à travers la Gateway) :
  - l'opérateur lisait « authorizing vault scope: authorize-scope: status 409 » pour un compte non épinglé ;
  - le Vault arrêté, il lisait `409` « resolving account: Get "http://127.0.0.1:18481/vault/v1/accounts/…": dial tcp 127.0.0.1:18481: connect: connection refused » : l'adresse et l'URL interne du Vault.
- (+) **Mesuré, après** : `409` « the privileged account has no pinned host key: an administrator must pin it (PUT /vault/accounts/{id}/host-key) before any session » ; le Vault arrêté, `503` sans adresse, sans port, sans « dial tcp ».
- (+) **Mesuré en unitaire** :
  - le client du Broker ne reconnaît le code que sur un `409`, ignore le texte, et ne laisse passer aucune adresse ;
  - `connect` : `404` pour une session inconnue, `409` pour une session terminée, `503` sans la cause pour un proxy injoignable ;
  - `POST /sessions` : `503` sans la cause quand l'Authorization Service ou l'audit ne répondent pas, `403` motivé pour un refus.
  - **11 mutations, 11 tuées.**
- (+) Jumeaux trouvés et refermés : `connect` et `POST /sessions` laissaient sortir des causes internes ; terminer, décider, lire une session ne le faisaient déjà plus.
- (−) Le test qui fixait `409` pour une panne du proxy (`TestConnect_OtherProxyFailuresStayAConflict`) est remplacé : ce `409` n'était pas un état de la session, et `docs/api/rest/openapi.yaml` réserve `409` à l'état.
- (−) ~~Une session peut encore être **créée** sur un compte non épinglé ; c'est `connect` qui la refuse.~~ Refermé par ADR-0043 : `POST /sessions` la refuse.
- (−) ~~Les autres routes publiques n'ont pas été passées en revue de la même façon : celles de la Gateway vers le Vault relaient encore le texte des erreurs d'administration (`403`, `409` des écritures), destinées à un administrateur.~~ Refermé par ADR-0043.

**Alternatives envisagées**
- **Relayer le texte du Vault** : il n'est pas un contrat, et il peut porter un détail interne.
- **Vérifier la clé dès `POST /sessions`** : une session ouverte sur un compte non épinglé ne pourrait jamais servir, mais refuser plus tôt demande un appel au Vault de plus à chaque demande ; c'est possible plus tard.
