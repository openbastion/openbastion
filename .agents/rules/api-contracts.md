# Contrats d'API (publique et interne)

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. Les champs JSON d'une route interne **reprennent ceux du `proto`** (`snake_case`, ex. `fetch-credential`) ; les routes d'administration relayées par la Gateway gardent la forme de l'OpenAPI du doc 05 (`camelCase`). La traduction public → interne se fait dans la Gateway, nulle part ailleurs.
2. Contrats **additifs** : ne renomme ni ne supprime un champ ; un numéro Protobuf supprimé est `reserved` ; une rupture exige un `v2`.
3. Codes honnêtes : `400` entrée invalide, `401` non authentifié, `403` interdit, `404` introuvable, `409` conflit d'état, `429` budget, `503` dépendance indisponible. Un `403` qui masque une panne est un défaut ; exception voulue : même `403` que la ressource existe ou non.
4. Toute route interne a une entrée dans `CallerRules()` **et** un cas dans `callers_test.go` (appelants autorisés ; au moins un refusé ; route inconnue refusée).
5. Une route publique que la Gateway relaie ne prend du client que ce qui lui revient : l'identité (`actorId`, `actorRoles`, `callerId`…) est celle du jeton vérifié, ajoutée par la Gateway.
6. Une route qui écrit à chaque appel a un budget par identité (ADR-0016) : l'ajouter au budget, avec son test.
7. Le contrat change dans le **même commit** que le code : OpenAPI (doc 05), messages (doc 07 et `proto/`, identiques), tables (doc 06).
