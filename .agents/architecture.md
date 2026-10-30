# architecture — la structure technique d'OpenBastion

Lis ce fichier avant de toucher au code. Il te dit où se trouve quoi, comment un service est construit, et quelles propriétés du système tu ne dois jamais casser. Quand ce fichier et le code divergent, **le code fait foi** : corrige ce fichier dans le même commit.

---

## 1. Le produit en quelques lignes

OpenBastion est un PAM (Privileged Access Management) open source, cloud-native, en Go, sous licence Apache 2.0, entièrement original. Il centralise les accès privilégiés : l'opérateur n'a **jamais** le mot de passe de la cible, toutes les connexions passent par un proxy, toutes les sessions sont enregistrées, tout est audité.

Ce qui est implémenté aujourd'hui (MVP, un seul protocole : SSH) : Authentication, Authorization (RBAC), Session Broker, Password Vault, SSH Proxy, Audit Service (chaînage de hash), Command Recorder (replay texte chiffré au repos), API Gateway, mTLS interne. Le reste du périmètre (RDP, Workflow/Approval, UI, SDK…) est décrit dans `docs/architecture/OpenBastion_04_Roadmap.md` et **n'existe pas encore** : ne fais pas comme si.

## 2. Invariants — ne les affaiblis jamais

Chacun est tenu par du code et par des tests. Si une tâche semble exiger d'en affaiblir un, **arrête-toi et demande** (voir `policies.md` §2).

| ID | Invariant | Où il est tenu |
|---|---|---|
| ADR-0003 | Un secret ne traverse jamais le control plane (Gateway, Broker). Seul le proxy échange un scope à usage unique contre un credential, directement auprès du Vault. | Le port `VaultAuthorizer` du Broker n'a **aucune méthode** pour lire un credential ; `pkg/proxycore` purge le secret octet par octet. |
| ADR-0008 | Une session qui ne peut pas être enregistrée n'a pas lieu ; une commande non acquittée par le recorder n'est jamais exécutée. | `RECORDING_POLICY=required` par défaut (`pkg/proxycore`, ssh-proxy). |
| ADR-0009 | Le break-glass ne retire que l'enregistrement acquitté, sous six verrous cumulés, et jamais en silence. | Broker + `proxycore.Admission` (preuve à champs non exportés). |
| ADR-0011 | Une demande break-glass n'ouvre rien tant qu'une **autre** personne ne l'a pas approuvée : pas d'auto-approbation (par identifiant d'utilisateur), décideur et rôles tirés du jeton vérifié par la Gateway, décision auditée avant d'agir puis compare-and-swap, `connect` réservé au demandeur. | Session Broker (`decide`, `SaveIfStatus`) + liste blanche des routes `/sessions/...` du Gateway. |
| ADR-0012 | La liste des demandes break-glass en attente ne montre que ce que l'appelant peut décider (vide, jamais 403, sans autorité ; 503 plutôt qu'une liste partielle) ; la notification est au mieux et **n'est jamais un contrôle** (port sans valeur de retour, asynchrone, après coup) ; l'URL du webhook est un secret (jamais journalisée) ; ce que le demandeur écrit (`targetAccountId`) n'atteint jamais tel quel un message lu par des tiers. | Session Broker (`ListPendingApprovals`, `ApprovalNotifier`, `infrastructure/webhook_notifier.go`, `wellFormedAccountID`) + Gateway (`handleListPending` reconstruit la requête). |
| ADR-0013 | Un demandeur ne peut pas avoir plus de `BREAKGLASS_MAX_PENDING_PER_REQUESTER` demandes en attente (3 par défaut ; **par demandeur**, jamais global ni par compte : un plafond partagé serait une arme) ; le plafond est tenu **atomiquement**, entre réplicas aussi ; un décompte impossible est un 503, jamais une acceptation ; il n'est demandé qu'après l'autorité ; le webhook, si `BREAKGLASS_NOTIFY_SECRET` est fixé, est signé (`v1=` HMAC-SHA256 de `horodatage.corps`) et le secret n'apparaît jamais dans un journal ni une erreur. | Session Broker (`checkPendingQuota`, `SaveIfUnderPendingLimit` dans les deux magasins — verrou consultatif PostgreSQL —, `WebhookNotifier.WithSecret`) + relais du `429` par le Gateway. |
| ADR-0014 | Le budget de `POST /sessions` est celui de l'**utilisateur vérifié** (`id.UserID` issu du jeton), jamais de l'adresse ni du corps ; chaque tentative le coûte **avant** la lecture du corps, et une demande refusée par lui n'atteint pas le Broker (ni ligne, ni événement d'audit) ; défauts stricts (rafale 10, 6 par minute), pas d'« illimité » ; `429` avec un `Retry-After` vrai, message distinct du plafond du Broker ; un refus laisse une ligne de journal par utilisateur et par épisode — pas d'audit (le Gateway n'est pas émetteur autorisé, ADR-0010) ; l'éviction des seaux inactifs ne change jamais une décision. | API Gateway (`admitSessionRequest`, `application.RateLimiter.Take`/`Decision`, `NewSessionRequestLimiter`, `sweep`). |
| ADR-0015 | L'adresse du client des limites par adresse n'est **jamais** choisie par le client : `X-Forwarded-For` n'est lu que si le pair TCP immédiat est dans `TRUSTED_PROXY_CIDRS` (défaut : personne), **de droite à gauche**, jusqu'à la première adresse qui n'est pas un proxy ; au moindre doute la clé est l'adresse du **pair** ; clés normalisées (IPv4 écrite en IPv6 → IPv4, IPv6 → /64) ; une confiance plus large que prévue (réseau de longueur 0 sous toutes ses écritures, bits d'hôte, entrée vide) empêche de démarrer ; les limites par adresse sont réglables (`CLIENT_LOGIN_*`, `CLIENT_REQUEST_*`), défauts = ce que le code faisait, jamais « illimité ». | API Gateway (`application.ProxyTrust.ClientKey` — fonction pure —, `ParseTrustedProxies`, `addressKey`, `GatewayServer.clientKey`, `WithProxyTrust`). |
| ADR-0016 | Les routes qui **écrivent à chaque appel** — `approve`, `reject`, `connect`, et `terminate` depuis ADR-0017 — ont un budget par **utilisateur vérifié** (`id.UserID`, jamais l'adresse ni le corps), **un seul seau pour les quatre**, distinct de celui de `POST /sessions` ; le jeton est pris **avant** que le Broker soit appelé (une action refusée n'atteint ni le Broker, ni le Vault, ni le proxy, et n'écrit aucun événement) et après la vérification de la méthode (`405` gratuit) ; les lectures ne sont **pas** comptées (pas d'écriture à chaque appel) ; `SESSION_ACTION_BURST` (défaut 10, 1 à 1000) et `SESSION_ACTION_RATE_PER_MINUTE` (défaut 6, 1 à 600), jamais « illimité ». Ajouter une route qui écrit à chaque appel = l'ajouter ici, avec son cas de test. | API Gateway (`GatewayServer.admitSessionAction`, `admitFromBudget`, `WithSessionActionLimiter`, `application.NewSessionActionLimiter`). |
| ADR-0017 | Mettre fin à une session : **son demandeur** (sans politique) **ou** une politique sur `session-terminate:account:{id}` (refusée par défaut, préfixe distinct de `vault:`, `breakglass:` et `breakglass-approve:`) ; l'appelant et ses rôles viennent du **jeton vérifié** (le Gateway construit `{callerId, actorRoles}`, le corps du client est écarté, sans `callerId` : `403`) ; ordre **session (404) → appelant (403, quel que soit l'état) → état (409)**, Authorization injoignable : `503` et rien n'est terminé ; l'audit nomme **l'appelant** (refus : `session.terminate` en échec sous son nom ; succès après l'action, au mieux ; `404`/`409` sans événement) ; terminaison par comparaison-échange (`SaveIfStatus` depuis `active`) ; la route est dans le budget d'actions d'ADR-0016, avant le Broker. **Ne coupe pas une connexion déjà ouverte** (le proxy n'a pas de route de révocation). | Session Broker (`TerminateSession`, `SessionTerminateResourcePrefix`, `handleTerminate`) + Gateway (`handleSessionItem`, cas `DELETE`). |
| ADR-0018 | **Terminer, c'est couper** : `TerminateSession` fait révoquer la session au proxy (`POST /internal/v1/revoke-session`, **Broker seul**, ADR-0010) **avant** de changer l'enregistrement (`SaveIfStatus`) ; `200` seulement quand plus rien n'est ouvert, sinon `503` : **rien n'est terminé**, la session reste `active`, `session.terminate` en échec sous le nom de l'appelant, le même appel rejoué aboutit ; jamais d'appel au proxy pour une terminaison refusée / session inconnue / non active / expirée / Authorization muette. Le proxy tient `proxycore.LiveSessions` (connexions + mémoire des révocations, **un seul verrou**) partagé avec `Listener.Serve` (qui enregistre **avant** l'admission, l'audit et le credential ; `relayCtx` dérive de `liveCtx`) ; il jette les tickets non utilisés, refuse `establish-session` (`409`) pour une session révoquée avant d'interroger l'enregistreur, ferme la connexion cible à l'annulation (`context.AfterFunc`, y compris pendant la poignée de main). Mémoire = temps restant + 1 min, plafond 7 jours, comparée **en secondes** avant conversion. Audit proxy : `session.revoked` + `session.terminate` ; un arrêt du proxy n'est pas une révocation ; l'opérateur lit « session ended because it was terminated. » sans savoir qui. Un `Listener`/serveur sans registre refuse toute session (`ErrNotRevocable`). `conn.RelayEnded()` juste après le relais, avant l'audit. |
| ADR-0019 | Lire une session : **son demandeur** (sans politique), **celui qui l'a décidée** (`DecidedBy` = appelant, cette session seulement) **ou** une politique sur `session-read:account:{id}` (action `session:read`, refusée par défaut, préfixe distinct de `vault:`, `breakglass:`, `breakglass-approve:`, `session-terminate:`) ; le Gateway construit `?callerId=&actorRoles=` d'après le **jeton vérifié** (`forwardRead` : la requête et le corps du client sont écartés, rôles encodés) ; ordre appelant vide `403` → session `404` → appelant `403` → Authorization `503` (échec fermé, tiers seulement) ; le refus est **générique** (jamais la raison de l'Authorization Service) ; une erreur du store qui n'est pas `ErrNotFound` est un `503`, jamais un `404` ; **une lecture n'écrit jamais dans le store** et reste hors du budget d'actions ; à l'audit, seul le refus de politique (ADR-0020) et la lecture servie à un titulaire de politique (ADR-0021) écrivent — le demandeur et le décideur n'écrivent rien. | Session Broker (`GetSession`, `handleGetSession`) + Gateway (`forwardRead`) + règle mTLS `/sessions/`. |
| ADR-0020 | **Un refus de politique d'une lecture** (`403` d'un appelant nommé, session existante) écrit `session.read`, `resource_type=session`, `success=false`, **sous le nom de l'appelant que le Gateway a vérifié** (jamais `sess.RequestedBy`, jamais une valeur de la requête), **dans la limite d'un budget par identité** (`RefusalBudget`, seau à jetons du Broker, par identité et pas par session) : `SESSION_READ_AUDIT_BURST` (10, de 1 à 1000) puis `SESSION_READ_AUDIT_RATE_PER_MINUTE` (6, de 1 à 600), invalide ⇒ le Broker s'arrête, ni « illimité » ni « désactivé » ; **la réponse ne dépend jamais du budget** (refus identique, écrit ou non ; audit en panne ⇒ même refus, cause dans le journal ; ce n'est pas « enregistrer ou refuser ») ; une ligne de journal **par épisode** quand le budget est épuisé ; `404`, `503`, appelant vide et lecture servie n'écrivent rien ; mémoire bornée (seau revenu plein oublié), horloge qui recule sans effet ; par processus (N répliques ⇒ N×). | Session Broker (`auditRefusedRead`, `refusal_budget.go`, `main.go`) ; le Gateway ne change pas. |
| ADR-0021 | **Une lecture servie à un titulaire de politique** (le chemin `allowed` de `GetSession`, ni le demandeur ni le décideur) écrit `session.read`, `resource_type=session`, **`success=true`**, sous le nom de l'appelant que le Gateway a vérifié, **avant** de servir ; **si l'événement ne s'écrit pas, rien n'est servi** : `ErrUnavailable` (`503`), ni `ErrForbidden` ni `ErrNotFound`, la cause dans l'erreur pour le journal du gestionnaire, jamais au client ; **pas de budget** (celui d'ADR-0020 borne les refus ; une lecture servie n'en dépense aucun jeton et n'est pas réduite au silence par lui) ; asymétrie voulue : ce qui réduit un accès (terminer, refus de lecture) est au mieux, ce qui accorde — session, approbation, **connaissance** — est fermé ; le demandeur et le décideur n'écrivent rien et ne dépendent pas de l'audit ; l'ordre est appelant vide `403` → session `404` → appelant `403` → Authorization `503` → **audit `503`** → servi. | Session Broker (`GetSession`) ; le Gateway ne change pas. |
| ADR-0022 | **Chaque page d'un enregistrement du Command Recorder servie** (`GET /sessions/{id}/recording`) écrit `recording.read`, `resource_type=session`, `resource_id`=la session, **`success=true`**, sous le nom de l'appelant que le Gateway a vérifié (`?callerId=` construit d'après le jeton, celui du client écarté), **avant** d'être servie ; **sans l'événement, rien n'est servi** : `ErrUnavailable` (`503`, corps générique, cause au journal du Recorder) ; pas d'exception demandeur (toute lecture d'un enregistrement passe par une politique), **pas de budget** ; ordre appelant vide `403` → Authorization `403` / `503` (plus `403` quand elle est muette) → store `500` (corps générique) → **audit `503`** → servi ; un refus n'écrit rien. `AUDIT_URL` du Recorder sans réglage pour le désactiver. | Command Recorder (`GetRecording`, `handleSession`, `AuditHTTPClient`) + Gateway (`handleSessionRecording`) + règle mTLS `emit-event` de l'Audit Service ouverte à `command-recorder`. |
| ADR-0023 | **Chaque demande de la page servie par la liste des demandes en attente** (`ListPendingApprovals`, `GET /sessions?status=pending_approval`) écrit `session.listed`, `resource_type=session`, `resource_id`=la demande, **`success=true`**, sous le nom de l'appelant que le Gateway a vérifié, **avant** de servir la page ; **un seul qui ne s'écrit pas, et rien n'est servi** (`ErrUnavailable`, `503` générique) ; seulement les demandes **de la page servie** (pas celles comptées dans `totalItems`, pas celles écartées par le filtre) ; **une page vide n'écrit rien** et ne dépend pas de l'audit ; pas de budget ; écriture séquentielle, au plus `pageSize` (100) appels. | Session Broker (`ListPendingApprovals`) ; le Gateway ne change pas. |
| ADR-0010 | L'identité de l'appelant vient du certificat, jamais du corps de la requête ; chaque route a sa liste d'appelants, refus par défaut. | `pkg/mtls`, un `internal/interfaces/callers.go` par service. |
| — | L'audit est fail-closed : un événement qui ne peut pas être écrit empêche l'action. | Broker, proxy. |
| — | Les défauts sont les plus stricts ; le comportement faible se demande **par son nom**, et une valeur inconnue est fatale. | `RECORDING_POLICY`, `INTERNAL_TLS`, `BREAKGLASS_*` (dont `BREAKGLASS_APPROVAL`) ; `BREAKGLASS_NOTIFY_URL` absente = pas de notification, annoncé au démarrage, et une valeur inutilisable est fatale ; `BREAKGLASS_MAX_PENDING_PER_REQUESTER` (1 à 100, pas d'« illimité ») et `BREAKGLASS_NOTIFY_SECRET` (32 octets au moins, sans URL = fatal) : hors bornes, fatal ; `SESSION_REQUEST_BURST` (1 à 1000) et `SESSION_REQUEST_RATE_PER_MINUTE` (1 à 600) du Gateway : pas d'« illimité », hors bornes fatal, annoncés au démarrage ; `SESSION_ACTION_BURST` (1 à 1000) et `SESSION_ACTION_RATE_PER_MINUTE` (1 à 600) : idem, pour `approve`, `reject`, `connect` ; `CLIENT_LOGIN_BURST` (1 à 100), `CLIENT_LOGIN_RATE_PER_MINUTE` (1 à 60), `CLIENT_REQUEST_BURST` (1 à 10000), `CLIENT_REQUEST_RATE_PER_MINUTE` (1 à 6000) : idem ; `TRUSTED_PROXY_CIDRS` absente = personne n'est de confiance (annoncé), une valeur douteuse est fatale. |

## 3. Arborescence réelle

```
go.work                          workspace Go : un module par composant (ADR-0002)
Makefile                         build, vet, test, test-integration, test-postgres, pki, run-*
NOTES_SANDBOX.md                 journal des écarts, découvertes, limites, état des tests — à tenir à jour
README.md
.agents/  AGENTS.md              ce dossier
pkg/
  proxycore/                     pipeline proxy commun (listener, credential fetcher, tap, terminator) — ADR-0006
  mtls/                          identité par certificat, Guard, rechargement, PKI de dev — ADR-0010
    pki/  mtlstest/  cmd/openbastion-pki/
services/
  access/
    api-gateway/                 seul point d'entrée public ; écrase l'identité revendiquée par le client
    authentication/              Argon2id, JWT
    authorization/               RBAC deny-by-default, un deny explicite l'emporte
    session-broker/              orchestrateur ; ne voit jamais un secret
  proxy/ssh-proxy/               premier proxy réel (golang.org/x/crypto/ssh) ; sshcodec/
  vault/password-vault/          comptes, secrets (chiffrés), scopes à usage unique
  recording-audit/
    audit-service/               journal chaîné par hash, signé
    command-recorder/            replay texte, chiffrement enveloppe AES-256-GCM
proto/                           contrats Protobuf (doc 07) — la forme des messages
test/integration/                scénarios sur processus réels (binaires compilés, ports 18xxx)
docs/
  architecture/                  docs 00–07 numérotés ; les ADR sont consolidés dans le doc 03
  api/                           OpenAPI (doc 05)
  guides/                        administrateur, développeur, sécurité, HA, PRA/PCA, utilisateur
deploy/                          docker-compose, helm, k8s (squelettes)
```

`docs/adr/` est vide : tant que les ADR ne sont pas éclatés en fichiers, **ils vivent dans `docs/architecture/OpenBastion_03_ADR.md`**.

## 4. Le patron d'un service (Clean Architecture)

Chaque service a la même forme. Respecte-la ; ne mélange pas les couches.

```
services/<domaine>/<service>/
  go.mod                         module propre (+ replace locaux vers pkg/…, voir rules.md §8)
  cmd/<service>/main.go          composition : lit l'environnement, construit les adaptateurs, démarre
  internal/
    domain/                      entités + PORTS (interfaces de dépôt/clients). Aucune dépendance externe.
    application/                 cas d'usage. Dépend du domaine seulement. Toute la logique métier est ici.
    infrastructure/              adaptateurs : magasin mémoire, magasin PostgreSQL (InitSQL idempotent),
                                 clients HTTP vers les autres services (champ Client *http.Client + orDefault)
    interfaces/
      http.go                    handlers HTTP/JSON (remplaçant de gRPC, voir §6) ; aucune règle métier
      callers.go                 CallerRules() : qui peut appeler quelle route (mTLS)
```

Règles de dépendance : `interfaces → application → domain` ; `infrastructure → domain` (elle implémente ses ports). `domain` n'importe rien du projet. `main.go` est le seul endroit qui connaît tout le monde. Une règle métier dans un handler HTTP ou dans un adaptateur est un défaut.

## 5. Qui appelle qui (identités mTLS)

Les noms de service sont ceux des SAN URI `spiffe://<domaine>/<service>` : `api-gateway`, `authentication`, `authorization`, `session-broker`, `ssh-proxy`, `password-vault`, `audit-service`, `command-recorder`, plus `admin-cli` (outillage opérateur).

```
utilisateur ──HTTP──► api-gateway ──► authentication   (login, verify)
                          │──────► session-broker      (/sessions… : création, `GET /sessions?status=pending_approval` (seul statut servi), connect, approve, reject — liste blanche ; l'identité de l'appelant est celle du jeton, la requête de liste est reconstruite)
                          │──────► password-vault      (administration des comptes, rotation)
                          │──────► authorization       (création de politiques)
                          └──────► command-recorder    (lecture d'un replay)
session-broker ──► authorization (check-access) · password-vault (authorize-scope, métadonnées de compte)
               ──► audit-service (emit-event)   · ssh-proxy (establish-session)
               ──► webhook de notification (BREAKGLASS_NOTIFY_URL, HORS maillage mTLS, au mieux, jamais un contrôle — ADR-0012 ; signé si BREAKGLASS_NOTIFY_SECRET — ADR-0013)
ssh-proxy ──► password-vault (fetch-credential) · audit-service · command-recorder (écriture des commandes)
password-vault, command-recorder ──► authorization (check-access)
command-recorder ──► audit-service (recording.read, avant de servir une page — ADR-0022)
admin-cli ──► authentication (POST /auth/v1/users) · audit-service (GET /audit/v1/verify-chain)
```

Ports par défaut : gateway 8080, vault 8081, audit 8082, authorization 8083, broker 8084, ssh-proxy 8085 (API) + 2222 (SSH), authentication 8086, recorder 8087. La source de vérité des appelants autorisés est le `callers.go` de chaque service, pas ce schéma.

## 6. Transport, contrats, identité

- Le transport interne documenté est gRPC (doc 07). **Dans ce dépôt, c'est du HTTP/JSON** avec exactement les noms de champs des messages Protobuf, uniquement dans `internal/interfaces/`. Raison : réseau restreint du sandbox de build (`NOTES_SANDBOX.md`). Ne « répare » pas cet écart de ton propre chef.
- TLS 1.3 mutuel entre services, `INTERNAL_TLS=required` par défaut. Le listener public du Gateway reste en HTTP (le TLS se termine à l'arête).
- Un client HTTP interne n'est construit que pour des pairs déclarés (`mtls.Peer{URL, Service}`) : l'identité du pair est épinglée.
- Les contrats évoluent **de façon additive** uniquement (doc 07 §1) ; une rupture exige un package `v2`. Un numéro de champ Protobuf supprimé est `reserved`, jamais réutilisé.

## 7. Données

- PostgreSQL 15+ pour les services à état. Chaque magasin a une variante mémoire (développement/tests) et une variante PostgreSQL ; `DATABASE_URL` choisit. Le schéma est créé par un `InitSQL` **idempotent** (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF NOT EXISTS`) : une base créée avant un incrément doit se mettre à niveau sur place.
- Modèle de données de référence : `docs/architecture/OpenBastion_06_Modele_Donnees.md`.
- Secrets de bootstrap par variable d'environnement (`KMS_KEY_HEX`, `TOKEN_SIGNING_KEY_HEX`) : un service avec `DATABASE_URL` refuse de démarrer sans sa clé.

## 8. Où est la vérité

| Question | Fichier |
|---|---|
| Pourquoi cette décision ? | `docs/architecture/OpenBastion_03_ADR.md` |
| Quelle API publique ? | `docs/api/OpenBastion_05_OpenAPI.md` |
| Quel message entre services ? | `docs/architecture/OpenBastion_07_Interfaces_Inter_Services.md` + `proto/` |
| Quelle table ? | `docs/architecture/OpenBastion_06_Modele_Donnees.md` |
| Qu'est-ce qui est fait, quelles limites, quels écarts ? | `NOTES_SANDBOX.md` (le plus à jour) |
| Quelle feuille de route ? | `docs/architecture/OpenBastion_04_Roadmap.md` |
| Comment exploiter / sécuriser ? | `docs/guides/` |

## 9. Écarts connus entre la cible et l'implémenté

À ne pas « corriger » sans demande : transport HTTP/JSON au lieu de gRPC ; pas de Workflow/Approval Engine (seulement l'approbation à un décideur du break-glass, ADR-0011, dans le Broker) ni de MFA natif ; notification du break-glass sans nouvelle tentative, non signée, un seul canal ; `GET /sessions` ne sert que `pending_approval` ; un seul protocole (SSH) ; KEK locale (`LocalKMS`) au lieu d'un vrai KMS/HSM ; Vault chiffre en un seul niveau (pas d'enveloppe) ; lignes du recorder non chaînées ; événements d'audit non attribués par l'identité du certificat ; listes d'appelants dans le code ; la limite par adresse du Gateway ne vaut que si `TRUSTED_PROXY_CIDRS` est réglé (ADR-0015 ; Traefik n'a pas été essayé) et ne borne pas une force brute distribuée ; seuls `POST /sessions`, `approve`, `reject`, `connect` et `terminate` ont un budget par identité (les lectures n'en ont pas) ; `terminate` a un contrôle (ADR-0017) et coupe (ADR-0018) **mais le proxy SSH est en instance unique** (la révocation atteint une instance ; ne pas déployer de réplicas), les octrois de portée du Vault ne sont pas révoqués, le mode est strict (proxy injoignable ⇒ on ne peut pas terminer), et un refus de lecture d'une session (`GET /sessions/{id}`) est audité **dans une limite par identité** (ADR-0020), le nombre exact de refus supprimés n'est pas enregistré, la lecture servie à un titulaire de politique est un événement avant d'être servie (ADR-0021) — **ne pas la passer par `RefusalBudget`, ni l'écrire après ou en arrière-plan** —, une panne de l'audit rend donc la lecture d'un auditeur indisponible (voulu), le demandeur et le décideur ne sont pas tracés, chaque page d'un enregistrement du Command Recorder servie est un événement `recording.read` écrit avant d'être servie (ADR-0022) — **même règle : pas de budget, pas d'écriture après ou en arrière-plan** — mais un refus de lecture d'un enregistrement n'est pas audité ; chaque demande servie par la liste des demandes en attente est un événement `session.listed` écrit avant d'être servie (ADR-0023, même règle) ; et chaque refus interroge toujours l'Authorization Service ; budgets par processus ; refus par adresse ni audités ni journalisés. La liste à jour est dans `NOTES_SANDBOX.md` et dans le Guide Sécurité §12.
