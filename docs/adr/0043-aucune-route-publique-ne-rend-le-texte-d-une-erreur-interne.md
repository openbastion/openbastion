# ADR-0043 — Aucune route publique ne rend le texte d'une erreur interne ; une session ne se crée que sur un compte qui existe et dont la clé est épinglée


**Contexte**
ADR-0042 a refermé deux routes (`connect`, `POST /sessions` pour ses pannes). La revue des autres routes que relaie la Gateway — elle recopie le corps des réponses de ses services — trouve le même défaut ailleurs :
- les routes d'administration du Vault (enregistrer, lister, lire, supprimer, renouveler, épingler) rendent le texte de toute erreur, y compris une Authorization injoignable, un audit coupé (avec son adresse) ou une erreur PostgreSQL (nom de contrainte) ;
- `GET /vault/accounts/{id}` répond `404` à une panne de la base ;
- `POST /policies` répond `403` avec le texte de toute erreur du magasin ;
- la demande de break-glass laisse sortir l'adresse d'une Authorization injoignable ;
- la Gateway rend en `500` le texte de ses propres erreurs internes (une URL, au besoin).
En chemin : le magasin mémoire du Vault **écrasait** un compte enregistré deux fois sous le même identifiant (le magasin PostgreSQL, lui, refusait avec le nom de la contrainte). Enfin, une session se créait sur un compte qui n'existe pas, ou dont la clé d'hôte n'est pas épinglée : elle ne pouvait servir à rien, et ce n'est qu'à `connect` qu'on l'apprenait.

**Décision** *(acceptée par Bony Kiss le 31 octobre 2026 — « Okay pour la prochaine étape » ; la forme est renversable)*
1. **Règle** : une réponse qu'un client peut lire ne porte jamais le texte d'une erreur d'une dépendance (réseau, base, autre service). Un refus porte son propre motif (erreur sentinelle et son message) ; une panne est un `503` à la phrase générique, sa cause au journal du service.
2. **Vault, routes d'administration** : classement par erreurs sentinelles — `ErrAccessDenied` (`403`), `ErrAlreadyExists` (`409`, les deux magasins, le magasin mémoire n'écrase plus), `ErrNotFound` (`404`), `ErrNoReconciliation` / `ErrNoHostKey` / rotation en cours (`409`), clé ou intervalle illisibles (`400`), cible qui refuse ou non vérifiée (`502`, avec ce que la cible a répondu : c'est l'administrateur qui l'a configurée), rotation non configurée (`501`), audit indisponible (`503`) ; tout le reste : `503` générique.
3. **Authorization, `POST /policies`** : un refus reste `403` motivé ; une panne du magasin est un `503` générique.
4. **Broker** : une Authorization injoignable pendant une demande de break-glass est un `503` générique.
5. **Gateway** : ses propres erreurs internes sont un `500` générique.
6. **`POST /sessions` lit le compte au Vault** après l'autorisation, et avant de créer quoi que ce soit : un compte inconnu, `404` ; un compte sans clé d'hôte épinglée, `409` (`ErrAccountNotPinned`, le même motif qu'à `connect`). L'un et l'autre sont des demandes refusées, enregistrées et auditées (`session.create` en échec). Un Vault injoignable : `503`, rien n'est créé.

**Conséquences**
- (+) **Mesuré, avant** (rouge, sur `3fe3d4c`, processus réels et vraie base, à travers la Gateway) :
  - une session était créée (`201`) sur un compte non épinglé, et sur un compte que le Vault n'a pas ;
  - l'Authorization Service arrêté, un enregistrement de compte répondait `403` « checking access (fail-closed): Post "http://127.0.0.1:18483/authz/v1/check-access": dial tcp 127.0.0.1:18483: … » ;
  - un chemin `GET /vault/accounts/acc%0a1`, envoyé par n'importe quel utilisateur authentifié, recevait `500` « parse "http://127.0.0.1:…/vault/v1/accounts/acc\n1": net/url: invalid control character in URL » : l'URL interne du Vault.
- (+) **Mesuré, après** : `409` « no pinned host key », `404` « privileged account not found », `503` sans adresse ni « dial tcp », `500` « internal error ».
- (+) **Mesuré en unitaire** :
  - routes d'administration du Vault : Authorization coupée (enregistrer, lister) et audit coupé (épingler) donnent `503` sans la cause, l'audit nommé quand c'est lui ; même identifiant deux fois `409` ; compte inconnu `404` « account not found » ; refus `403` avec son motif ;
  - les deux magasins refusent un doublon (même identifiant, ou même nom sur la même cible), et le magasin mémoire **n'écrase plus** ;
  - `POST /policies` : magasin en panne `503` sans « pq: » ni adresse, doublon `409`, refus `403` ;
  - Broker : compte inconnu ou non épinglé refusé et audité ; Vault injoignable `ErrUnavailable` (rien n'est créé, rien n'est pris pour un refus) ; la décision d'accès précède la lecture du compte, un appelant refusé n'apprend rien de son existence ; break-glass, Authorization coupée `503` ;
  - le client du Broker ne prend pour « inconnu » qu'un `404`, et pour « non épinglé » qu'une empreinte vide.
  - **18 mutations, 18 tuées.** Une survivait d'abord (« le magasin mémoire laisse deux comptes du même nom sur une cible ») : un test la couvre maintenant ; deux étaient mal écrites, réécrites.
- (+) Un test existant était faux, et un test d'attaque change de lieu :
  - `TestListAccounts_ClampsPageAndPageSize` enregistrait trois comptes du même nom sur la même cible, ce que la base refuse depuis toujours : il passait parce que le magasin mémoire était plus lâche ;
  - l'attaque du Vault imposteur (`TestMTLS…`) a lieu maintenant à la création de la session, premier appel au Vault ; la garantie (l'imposteur ne reçoit rien) est intacte.
- (−) Le Vault devient une dépendance de `POST /sessions` : Vault indisponible, aucune session ne se crée. C'était déjà le cas pour s'y connecter.
- (−) Les scénarios qui ne testent que le Broker y jouent la lecture de compte du Vault (`playVaultAccounts`), au lieu d'un Vault réel.
- (−) Le magasin mémoire d'Authorization accepte encore une politique en double (sans effet) ; la base la refuse (`409`).
- (−) Une cible qui refuse une rotation voit encore sa réponse relayée à l'administrateur (`502`) : c'est la cible qu'il a configurée, et il en a besoin pour agir.

**Alternatives envisagées**
- **Filtrer à la Gateway** les corps des réponses `5xx` : une défense en plus, mais qui ne voit pas les `403` et `404` porteurs de texte ; la règle se tient là où l'erreur naît.
- **Ne vérifier le compte qu'à `connect`** (ADR-0042) : une demande de session — break-glass compris — pourrait être approuvée pour un compte qui ne peut pas servir.
