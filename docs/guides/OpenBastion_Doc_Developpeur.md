# OpenBastion — Documentation Développeur

**Version** 0.1 · **Statut** Draft de travail
**Public visé** Contributeurs souhaitant construire, étendre ou corriger OpenBastion
**Portée** Guide pratique de mise en route et de contribution. Pour le *pourquoi* des choix, voir la séquence architecture (`OpenBastion_00` à `OpenBastion_07`) — ce document ne la répète pas, il y renvoie.

---

## 1. Prérequis

| Outil | Usage |
|---|---|
| Go ≥ 1.23 | Langage unique des microservices (ADR-0004) |
| Docker + Docker Compose | Environnement de développement local (doc 02 §6) |
| `buf` | Génération de code depuis `proto/`, détection de rupture de contrat (doc 07 §1) |
| `make` | Commandes de build/test agrégées (doc 02 §2) |
| `golangci-lint` | Lint Go, exécuté aussi en CI |

## 2. Démarrer l'environnement local

```sh
git clone https://github.com/openbastion/openbastion.git
cd openbastion
make dev-up          # docker-compose : PostgreSQL, Redis, MinIO, NATS, Kafka, Keycloak
make proto-gen        # génère le code Go depuis proto/ via buf
make dev-seed         # charge un jeu de données de test (un utilisateur, un compte SSH cible)
make run SERVICE=ssh-proxy
```

`make dev-up` suffit à obtenir toute l'infrastructure du périmètre MVP (doc 04 §2). Les microservices eux-mêmes se lancent individuellement avec `make run SERVICE=<nom>`, pas via Compose — cela reproduit la façon dont ils tournent en production (un binaire par conteneur).

**Le SSH Proxy refuse de démarrer sans Command Recorder** : `RECORDING_POLICY` vaut `required` par défaut (ADR-0008), donc lance d'abord le recorder (`make run-recorder`) et fournis `RECORDER_URL`. Pour travailler sur autre chose que l'enregistrement, `RECORDING_POLICY=best-effort` le laisse démarrer sans — développement uniquement, le proxy s'en plaint au démarrage, et les sessions ne sont alors pas rejouables.

**Le transport interne est en mTLS par défaut** (ADR-0010) : un service sans certificat refuse de démarrer. Deux façons de travailler :

- **Comme en production** : `make pki` crée une autorité et l'identité de chaque service dans `.pki/` (ignoré par git — ce sont des clés privées), puis chaque `make run-<service>` s'en sert. Les certificats durent 7 jours ; relancer `make pki` les renouvelle et les services en cours les reprennent sans redémarrage.
- **Sans certificats** : `make run-<service> INTERNAL_TLS=disabled` (ou `INTERNAL_TLS=disabled` dans l'environnement) lance en HTTP clair, sans aucune authentification entre services ; chaque service s'en plaint au démarrage. Pratique pour un `curl` direct sur un endpoint interne ; ne jamais le laisser dans une configuration partagée.

Pour appeler un endpoint interne sous mTLS à la main : `curl --cacert .pki/ca.pem --cert .pki/admin-cli/cert.pem --key .pki/admin-cli/key.pem https://127.0.0.1:8082/audit/v1/verify-chain` (l'identité `admin-cli` n'ouvre que la création d'utilisateurs et la vérification de la chaîne d'audit ; pour une autre route, prendre l'identité du service qui l'appelle, comme le font les tests).

**Ajouter une route interne** : l'ajouter aussi à la table `CallerRules()` du service (`internal/interfaces/callers.go`) — une route qu'aucune règle ne mentionne est refusée à tous, y compris à ses appelants légitimes. Le test `callers_test.go` du service doit dire qui peut l'appeler et qui ne le peut pas. Ne jamais lire l'identité de l'appelant dans le corps d'une requête : elle vient de `mtls.CallerFrom(ctx)`.

**Essayer le break-glass en local** (ADR-0009) : lance le Broker avec `BREAKGLASS_MAX_MINUTES=30` et le proxy avec `BREAKGLASS_ENABLED=true`, crée une politique sur `breakglass:account:<id>` (le moteur d'autorisation ne regarde que le rôle et la ressource : un motif `vault:account:…` ne suffit pas), puis arrête le recorder et demande une session avec `"breakGlass": true`. Le test `test/integration/breakglass_flow_test.go` le fait sur des processus réels, recorder tué puis relancé (avec `BREAKGLASS_APPROVAL=disabled`, pour ne juger que les verrous d'ADR-0009).

**Essayer la double validation en local** (ADR-0011) : sans rien d'autre, le Broker exige l'approbation d'une seconde personne. Crée une politique `breakglass-approve:account:<id>` pour un second rôle, un second utilisateur, puis : le demandeur crée la demande (`pending_approval`), l'autre fait `POST /sessions/<id>/approve`, le demandeur fait `connect`. Le test `test/integration/breakglass_approval_test.go` le fait sur huit processus réels, attaques comprises. Deux gestes à connaître en écrivant un test : un Broker construit à la main (`NewSessionBrokerService`) **exige l'approbation** tant qu'on n'a pas appelé `WithoutBreakGlassApproval()` (la valeur zéro est le mode strict) ; et `Connect` prend l'identité de l'appelant (`callerId` côté HTTP) — un test qui parle directement au Broker joue le rôle du Gateway et doit la fournir.

**Essayer la découverte et la notification en local** (ADR-0012) : une fois une demande en attente, `GET /sessions?status=pending_approval` avec le jeton de l'approbateur la liste ; pour voir le webhook, lance un récepteur sur la boucle locale (`nc -l 9099`, ou un petit serveur) et démarre le Broker avec `BREAKGLASS_NOTIFY_URL=http://127.0.0.1:9099/hook` (http n'est admis que vers une adresse de boucle locale). Le test `test/integration/breakglass_discovery_test.go` le fait sur cinq processus réels : liste filtrée par autorité, webhook reçu, puis webhook refusant, bloquant et disparu — la demande et la décision n'en sont pas touchées. Trois gestes à connaître : le port `ApprovalNotifier` (`internal/application`) n'a **pas de valeur de retour** — ne lui en donne pas, c'est ce qui l'empêche d'être un contrôle ; la liste interroge l'Authorization Service **une fois par compte distinct** (un test d'application le compte) ; et un test de store qui lit « toutes les lignes en attente » doit vider les siennes d'abord (`clearPending` dans `list_pending_test.go`), la base de test étant partagée. Les tests qui attendent un serveur bloqué doivent le libérer **avant** `srv.Close()` (un `defer` exécuté en premier), sinon un échec se transforme en blocage.

**Essayer le plafond et la signature en local** (ADR-0013) : démarre le Broker avec `BREAKGLASS_MAX_PENDING_PER_REQUESTER=2` et fais trois `POST /sessions` `breakGlass: true` avec le même jeton — la troisième est un `429` qui dit le plafond, avec un second jeton la demande passe ; pour la signature, ajoute `BREAKGLASS_NOTIFY_SECRET=$(openssl rand -hex 32)` à côté de `BREAKGLASS_NOTIFY_URL` et vérifie la livraison avec l'extrait du guide administrateur. Le test `test/integration/breakglass_quota_test.go` le fait sur cinq processus réels (rafale de 12 demandes d'un même demandeur : une acceptée, onze refusées et auditées, signature vérifiée par un récepteur indépendant, secret absent du journal). Trois choses à savoir en touchant à ce code : tout `SessionRepository` doit offrir `SaveIfUnderPendingLimit` **atomique** — `quotaCountContract`, `quotaSaveContract` et `quotaRaceContract` (`quota_store_test.go`) s'exécutent sur chaque store, et un store qui compte puis enregistre en deux temps échoue à la course ; le récepteur des tests de signature (`receiverVerifies`) est écrit **d'après la description** du contrat (`v1=hex(HMAC-SHA256(secret, ts "." corps))`), pas d'après le code du notifier — s'il faut changer la signature, changer d'abord la description (ADR) et ce récepteur ; et le plafond par défaut (3) s'applique à tout `SessionBrokerService` construit à la main : un test qui dépose plus de trois demandes d'un même demandeur doit appeler `WithMaxPendingPerRequester(n)`.

**Essayer la limite de débit en local** (ADR-0014) : démarre le Gateway avec `SESSION_REQUEST_BURST=3 SESSION_REQUEST_RATE_PER_MINUTE=6` et fais quatre `POST /sessions` d'affilée avec le même jeton, **même avec un corps vide ou invalide** — la quatrième est un `429` « too many session requests from this user … » avec un `Retry-After` de 10 secondes, et le Broker n'a rien écrit ; un second jeton a son propre seau. Le Gateway annonce au démarrage ce qu'il applique ; c'est la ligne à lire. Quatre choses à savoir en touchant à ce code : (1) la clé est `id.UserID`, **issue de la vérification du jeton** — jamais `clientIP(r)` (la même pour tous derrière Traefik), jamais un champ du corps ; (2) `admitSessionRequest` s'exécute **avant** la lecture du corps, et déplacer l'appel après le décodage ferait gagner un jeton aux requêtes illisibles (`http_session_rate_test.go` le garde) ; (3) `Take` rend une `Decision` (`Allowed`, `RetryAfter`, `NewEpisode`) : utiliser `Take` partout où une réponse `429` doit dire la vérité sur `Retry-After`, `Allow` n'étant que son raccourci booléen ; (4) l'éviction des seaux inactifs (`sweep`) attend qu'un seau soit **plein, plus une marge**, car l'arithmétique flottante peut rendre « capacité − ε » à l'instant où il devrait l'être — `TestEviction_NeverChangesADecision` compare le limiteur à une référence qui n'évince jamais, sur des configurations choisies pour tomber sur cette frontière ; ne pas retirer la marge sans les relire. Tout test qui envoie beaucoup de `POST /sessions` par le Gateway (comme `breakglass_quota_test.go`) doit **relever** le budget par l'environnement (`SESSION_REQUEST_BURST=100`, `SESSION_REQUEST_RATE_PER_MINUTE=600`) : les défauts sont stricts exprès. `test/integration/session_rate_test.go` prouve la limite, les unités des deux autres limiteurs et l'arrêt sur valeur invalide sur des processus réels.

**Essayer le budget d'actions en local** (ADR-0016, ADR-0017) : démarre le Gateway avec `SESSION_ACTION_BURST=3 SESSION_ACTION_RATE_PER_MINUTE=6` et, avec le jeton d'un utilisateur qui détient une demande break-glass en attente, fais huit `POST /sessions/{id}/approve` d'affilée : trois sont des `403` du Broker (chacun écrit un événement d'audit `session.breakglass_approved`, `success=false`), cinq sont des `429` « too many session actions from this user … » avec `Retry-After`, et le Broker n'a rien écrit pour eux ; `reject`, `connect` et `DELETE /sessions/{id}` sont refusés au même instant, puisque le seau est unique. Quatre choses à savoir en touchant à ce code : (1) le budget suit le **coût d'un appel répété** — `admitSessionAction` n'est appelé que pour `connect`, `approve`, `reject` et `terminate` (ADR-0017), jamais pour les lectures, et `TestSessionAction_OnlyTheActionsThatWriteOnEveryCallAreCharged` le garde ; ajouter une route qui écrit à chaque appel, c'est l'ajouter ici avec son cas de test ; (2) l'appel est placé **après** la vérification de la méthode (un `405` ne coûte rien) et **avant** `forwardJSON` — le déplacer après le Broker ferait écrire les refus ; (3) le seau est celui de `id.UserID`, un seul pour les quatre routes et distinct de `sessionLimiter` : `admitFromBudget` est partagé, ce sont le limiteur et le libellé (`"session actions"`) qui changent ; (4) les valeurs par défaut de `NewSessionActionLimiter` sont aujourd'hui celles de `NewSessionRequestLimiter` : aucun test ne peut distinguer les deux jeux de constantes (mutation `A6`, équivalente), ne pas en conclure qu'ils sont liés. Un test qui enchaîne plus de dix `approve`, `reject`, `connect` ou `DELETE` pour un même utilisateur par le Gateway doit **relever** le budget par l'environnement (`SESSION_ACTION_BURST=100`, `SESSION_ACTION_RATE_PER_MINUTE=600`). `test/integration/session_action_test.go` prouve la limite sur des processus réels, avec un témoin qui mesure ce que le Broker écrit sans budget (6 approbations et 6 rejets refusés : 12 événements d'audit).

**Essayer la terminaison en local** (ADR-0017) : avec Authorization, Authentication, Audit, le Broker et le Gateway, ouvre une session (Alice, rôle `sre`), puis `DELETE /sessions/<id>` avec le jeton d'un autre utilisateur (Bob, sans politique) : `403`, la session reste `active`, et l'audit porte `session.terminate` en échec **sous le nom de Bob**. Crée une politique `session-terminate:account:<id>` pour le rôle de Carol : son `DELETE` répond `200` et l'audit nomme **Carol**, pas Alice. Alice termine sa propre session sans aucune politique. Le test `test/integration/session_terminate_test.go` le fait sur des processus réels, attaques comprises (corps forgé avec les rôles d'un administrateur, approbateur sans politique de terminaison, session inconnue, double terminaison, refus répétés jusqu'au budget). Cinq choses à savoir en touchant à ce code : (1) `TerminateSession(ctx, id, callerID, actorRoles)` suit l'ordre **session → appelant → état** : l'inverser (`TestTerminate_TheCallerComesBeforeTheState`) dirait l'état d'une session à qui n'a aucun droit dessus ; (2) la ressource est `SessionTerminateResourcePrefix + sess.PrivilegedAccountID`, son préfixe est volontairement distinct de `vault:`, `breakglass:` et `breakglass-approve:` (`TestTerminate_TheOtherPoliciesAreNotThePolicyToTerminate`) ; (3) le Gateway construit le corps `{callerId, actorRoles}` à partir du jeton vérifié et n'en lit aucun autre — comme pour `approve` ; un test qui parle directement au Broker joue le Gateway et doit fournir les deux ; (4) l'acteur de l'audit est **l'appelant**, pas `sess.RequestedBy` ; le succès est émis **après** la comparaison-échange (`SaveIfStatus`, depuis `active`), au mieux (un audit en panne ne garde pas une session ouverte : c'est une action qui réduit un accès, choix assumé) ; (5) le service d'autorisation ignore aujourd'hui le champ `action` et décide sur la ressource seule : `TestTerminateOverHTTP_AuthorizationIsAskedWithTheRolesOfTheBody_AboutTheAccountOfTheSession` fige ce que dit le Broker, sans que cela change la décision. **Ne pas en conclure que terminer coupe la connexion** : le proxy n'a que `establish-session`, pas de route de révocation.

**Essayer l'adresse du client en local** (ADR-0015) : démarre le Gateway avec `TRUSTED_PROXY_CIDRS=127.0.0.1/32` et joue le proxy avec `curl` : `curl -X POST localhost:8080/auth/login -H 'X-Forwarded-For: 203.0.113.9' -d '{"username":"x","password":"y"}'` six fois — la sixième est un `429` — puis une fois avec `-H 'X-Forwarded-For: 198.51.100.4'` : elle passe, c'est un autre client. Sans la variable, ou depuis un pair qui n'est pas dans la liste (`curl --interface 127.0.0.2 …`), l'en-tête est **ignoré** et toutes les requêtes partagent le seau du pair. Le Gateway annonce au démarrage ce qu'il fait. Quatre choses à savoir en touchant à ce code : (1) la résolution est `ProxyTrust.ClientKey` — une fonction **pure**, sans `net/http` ; ne pas la remplacer par un `strings.Split(xff, ",")[0]` : ce serait l'adresse que le client écrit, c'est-à-dire la suppression de la limite de login (`C1` de la série de mutations) ; (2) tout retour en arrière sur un doute rend l'adresse **du pair**, jamais une valeur lue à gauche d'un élément illisible ; (3) toute nouvelle forme de configuration de confiance doit **refuser** ce qui est plus large que prévu (la longueur 0 sous toutes ses écritures, les bits d'hôte) et ajouter son cas à `TestParseTrustedProxies_EveryDoubtIsAnError` ; (4) les clés sont normalisées (`addressKey`) : IPv4 écrite en IPv6 → IPv4, IPv6 → /64 — ne pas comparer deux adresses sans passer par elle. `test/integration/client_address_test.go` prouve le comportement sur des processus réels (dont un attaquant qui se connecte depuis `127.0.0.2` en écrivant l'adresse d'un autre) ; un test qui envoie beaucoup de `POST /auth/login` ou de requêtes authentifiées depuis **une** adresse doit relever les limites par l'environnement (`CLIENT_LOGIN_BURST`, `CLIENT_REQUEST_BURST`…) : les défauts sont stricts exprès.

## 3. Repères dans le monorepo

Rappel de l'arborescence complète : `OpenBastion_02_Arborescence_Depot.md`. Table de correspondance rapide pour une tâche donnée :

| Je veux… | Je vais dans… |
|---|---|
| Ajouter un endpoint REST public | `services/access/api-gateway/`, puis mettre à jour `docs/api/openapi.yaml` |
| Modifier la logique d'octroi de session | `services/access/session-broker/internal/application/` |
| Ajouter un protocole de proxy | `services/proxy/<nouveau>/`, en réutilisant `pkg/proxycore/` (§5) |
| Modifier un contrat gRPC interne | `proto/<domaine>/v1/`, puis `make proto-gen` |
| Ajouter une table | migration dans `services/<domaine>/<service>/migrations/`, mettre à jour `OpenBastion_06_Modele_Donnees.md` |
| Toucher à l'Admin UI | `web/admin-ui/src/features/<domaine>/` |

## 4. Structure d'un microservice — rappel

Chaque service suit le gabarit posé au document 02, §3 : `cmd/`, `internal/{domain,application,infrastructure,interfaces}/`, `go.mod` propre. Le point à retenir en tant que contributeur : **`internal/` n'est jamais importable depuis un autre service**. Toute communication passe par le contrat `proto/` correspondant (doc 07) — si vous vous surprenez à vouloir importer le package interne d'un autre service, c'est le signal qu'il manque un RPC au contrat, pas une raison de contourner la règle.

## 5. Ajouter un nouveau protocole de proxy

Les 9 proxies partagent `pkg/proxycore` (doc 01 §4.2, ADR-0006). Ajouter un dixième protocole ne touche jamais au pipeline commun :

1. Créer `services/proxy/<nom>-proxy/`.
2. Implémenter l'interface `Codec` (`pkg/proxycore/codec.go`) — c'est la seule pièce spécifique au protocole.
3. Câbler `ProxyControl` (`proto/proxy/v1/proxy_control.proto`, doc 07 §4) dans `cmd/<nom>-proxy/main.go`.
4. Écrire les tests de `test/security/` vérifiant la purge mémoire du credential (voir Guide Sécurité, §8) — **obligatoire**, pas optionnel, avant toute revue de code sur un nouveau proxy.
5. Ajouter le chart Helm sous `deploy/helm/charts/<nom>-proxy/`.

## 6. Travailler avec les contrats Protobuf

- Toute modification de `proto/` doit passer `buf lint` et `buf breaking` avant merge (doc 07 §1) — la CI rejette automatiquement une rupture non justifiée.
- Le code généré n'est pas commité : `make proto-gen` le régénère localement et en CI. Ne jamais éditer un fichier `*.pb.go` à la main.
- Un champ retiré est marqué `reserved`, jamais réutilisé (doc 07 §1) — même en développement local, avant toute publication.

## 7. Tests

| Niveau | Emplacement | Commande |
|---|---|---|
| Unitaire | à côté du code, `*_test.go` dans chaque `internal/` | `make test SERVICE=<nom>` |
| Intégration | `test/integration/` (Testcontainers) | `make test-integration` |
| End-to-end | `test/e2e/` | `make test-e2e` |
| Performance | `test/performance/` (k6) | `make test-perf` |
| Sécurité | `test/security/` | `make test-security` |

Les tests d'intégration actuels du dépôt (`test/integration/*_test.go`) tournent en mode `INTERNAL_TLS=disabled`, stipulé dans `buildEnv` ; `mtls_flow_test.go` et `mtls_lifecycle_test.go` font tourner les huit services sous mTLS requis avec une PKI générée par test (`mtls_helpers_test.go`), et attaquent le réseau avec des identités de toute sorte.

Un service qui touche à la couche proxy ou au Vault (§5, Guide Sécurité §6-8) n'est pas mergeable sans passage vert de `test-security` — ce n'est pas laissé à l'appréciation du relecteur.

## 8. Observabilité en développement

La stack locale (`make dev-up`) inclut Prometheus, Grafana, Loki et Tempo (doc 00 §10). Chaque service émet ses traces via OpenTelemetry dès son démarrage — inutile d'instrumenter manuellement un nouvel endpoint, l'instrumentation est portée par `pkg/telemetry` (doc 02 §3), déjà branchée sur le middleware gRPC/HTTP commun.

## 9. Processus de contribution

1. Ouvrir une issue décrivant le changement avant toute pull request substantielle — évite un travail rejeté pour désalignement architectural.
2. Une pull request ne touche idéalement qu'un seul service (ou `pkg/`, ou `proto/`) — cohérent avec le filtrage CI par chemins modifiés (doc 02 §9).
3. CI bloquante : lint, tests unitaires du/des service(s) modifié(s), `buf breaking` si `proto/` est touché, `test-security` si la couche proxy ou le Vault est touchée.
4. Toute pull request touchant un ADR existant (`docs/adr/`) doit soit le respecter, soit proposer un nouvel ADR le remplaçant explicitement (« Remplacé par ADR-NNNN », doc 03 §1) — pas de dérive silencieuse.

## 10. Prochaine étape

La **documentation administrateur** couvre le déploiement, la configuration des connecteurs d'identité, la gestion des politiques et l'exploitation courante — public différent (opérateur de la plateforme, pas contributeur de code).

---
*Document suivant : `OpenBastion_Doc_Administrateur.md`*
