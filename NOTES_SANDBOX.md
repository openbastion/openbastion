# Notes sur les contraintes de cet environnement de build

Ce fichier documente une contrainte réelle rencontrée en démarrant l'implémentation, et les décisions prises en réponse — à lire avant de juger que le transport HTTP/JSON ci-dessous est un écart d'architecture. Ce n'en est pas un : c'est une substitution de transport documentée, réversible, qui n'a touché aucun contrat.

## Ce qui a été découvert

L'environnement de build utilisé pour amorcer ce dépôt a un accès réseau restreint à une liste explicite de domaines (dépôts Ubuntu, GitHub, PyPI, npm, crates.io). Deux familles de domaines Go semblaient absentes :

- `golang.org/x/*` (imports "vanity" — leur résolution nécessite une requête HTTP vers `golang.org` lui-même)
- `google.golang.org/*` (même mécanisme — `google.golang.org/grpc`, `google.golang.org/protobuf`)

**Mise à jour** : `golang.org/x/crypto` et `golang.org/x/sys` sont en réalité utilisables, via un contournement simple — une directive `replace` dans `go.mod` pointant vers le mirroir GitHub officiel du projet, qui est bien accessible (`codeload.github.com` est autorisé) :

```
require golang.org/x/crypto v0.24.0
replace golang.org/x/crypto => github.com/golang/crypto v0.24.0
```

Ce contournement a été vérifié avec un vrai serveur SSH (clé hôte, `ssh.ServerConfig`, listener réel) qui compile et tourne. **`services/proxy/ssh-proxy` utilise donc le vrai paquet `golang.org/x/crypto/ssh`**, pas une réimplémentation. Le contournement n'a en revanche pas été retesté pour `google.golang.org/grpc` et `google.golang.org/protobuf` (dépendances beaucoup plus lourdes, avec leur propre graphe de dépendances) — le transport HTTP/JSON documenté ci-dessous reste donc en vigueur pour l'inter-services, uniquement.

**Deux détails pratiques rencontrés en mettant en place ce contournement**, pour quiconque reproduirait la démarche :

1. **`go.sum` est committé** (`services/proxy/ssh-proxy/go.sum`), avec les empreintes de `github.com/golang/crypto` et `github.com/golang/sys`. Une fois `go.sum` présent, `GOSUMDB=off` n'est plus nécessaire — la vérification se fait localement contre `go.sum`, jamais contre `sum.golang.org` (lui aussi hors allowlist). Seul `GOPROXY=direct` reste utile dans ce sandbox précis (le `Makefile` l'exporte pour tous les contributeurs, sandbox ou non — inoffensif dans un environnement réseau normal).
2. **Un comportement du mode workspace observé empiriquement** : quand un module a *à la fois* une dépendance locale résolue par `go.work` (`pkg/proxycore`) *et* une dépendance externe avec `replace` (`golang.org/x/crypto`), la résolution de la dépendance locale échouait (`module lookup disabled by GOPROXY=off`) alors qu'elle réussit pour un module qui n'a *que* des dépendances locales (comme `test/integration` ou `session-broker`). Un `replace` explicite supplémentaire vers le chemin local (`replace .../pkg/proxycore => ../../../pkg/proxycore`) lève l'ambiguïté — voir `services/proxy/ssh-proxy/go.mod`.

## Écart de modèle de données découvert en implémentant le codec SSH

`privileged_accounts` (`docs/architecture/data-architecture.md` §3) ne porte pas de champ `username` distinct de `name`/`target_host` — or authentifier une session SSH vers la cible exige un nom d'utilisateur. `EstablishSessionRequest` (`docs/api/grpc/README.md` §4) n'a pas non plus ce champ. Contournement documenté dans le code (`ssh-proxy/internal/interfaces/http.go`, `EstablishSessionRequest.TargetUser`) : threading explicite du champ jusqu'à ce que le modèle de données et le contrat proto soient mis à jour formellement — pas une omission silencieuse.

## API Gateway et Authentication Service

**Nouveau service : `services/access/authentication`.** Mots de passe hachés en Argon2id réel (`golang.org/x/crypto/argon2`, même contournement replace que pour `x/crypto/ssh`), format PHC auto-porteur (salt + paramètres + hash dans une seule chaîne, pas de colonne salt séparée). Jetons signés HMAC-SHA256 — **volontairement pas un vrai JWT** : aucune bibliothèque JWT externe n'a été ajoutée, cohérent avec le parti pris de ce projet de préférer la bibliothèque standard pour le code sensible (AES-GCM dans le Vault, SHA-256 pour le chaînage d'audit). La forme encodée (payload base64 + signature base64, séparés par un point) est volontairement proche d'un JWT pour que la bascule vers une vraie bibliothèque JWT, une fois `google.golang.org` joignable, reste un changement contenu à `infrastructure/token.go` — `application.TokenIssuer` n'expose aucun détail d'encodage dans sa signature.

**Écart documenté plutôt que masqué** : `docs/architecture/data-architecture.md` modélise `user_roles` comme table de jointure séparée contre une table `roles` autonome. Cet incrément simplifie en portant les noms de rôles directement sur `User` — `Authorization` possède déjà ce qu'un rôle peut *faire* (les politiques) ; `Authentication` possède quels rôles un utilisateur *a*. Séparer l'assignation de rôle dans sa propre table est un raffinement v0.0.1 direct, qui ne changerait aucun appelant de ce package.

**Nouveau service : `services/access/api-gateway`.** Point d'entrée public unique (`docs/architecture/system-overview.md`) : `POST /auth/login` (public, limité en débit spécifiquement — 5/minute par IP, plus strict que le reste), puis tout le reste sous `Authorization: Bearer <token>`, vérifié à chaque requête auprès du vrai `Authentication Service`. **L'injection de contexte d'identité est la pièce la plus importante** : sur `POST /sessions`, la Gateway écrase systématiquement `requestedBy` et `actorRoles` du corps de requête avec l'identité qu'elle vient de vérifier — quoi que le client ait pu revendiquer. Testé explicitement, à deux niveaux : au niveau HTTP unitaire (`TestHandleSessionsCollection_InjectsVerifiedIdentityOverridingClientClaims`, avec un faux Session Broker qui capture ce qu'il reçoit réellement) et en inter-processus réel (`gateway_flow_test.go`, où le client revendique explicitly `attacker-controlled-id` et le rôle `admin`, et où seule l'identité vérifiée par le vrai Authentication Service traverse jusqu'au vrai Session Broker).

**Portée volontairement limitée de cet incrément** : la Gateway route `POST /auth/login` et le cycle de vie complet de `/sessions/*` — le parcours MVP central. Les surfaces d'administration (`/vault/accounts/*`, `/policies`) restent accessibles directement sur leurs services respectifs, pas encore routées à travers la Gateway — un ajout direct suivant exactement le même patron (`forwardJSON`/passthrough) une fois nécessaire. Autre écart existant, non introduit par cet incrément mais rendu visible par lui : `Password Vault` n'impose aucune vérification RBAC sur ses propres opérations d'écriture (`onboard-account`, `rotate`) — seule la création de session le fait, via `Authorization.CheckAccess`. Une gestion de compte non gatée par rôle est un choix à corriger avant tout déploiement au-delà d'un pilote.

## Routage des surfaces d'administration à travers la Gateway

**Deux vrais manques comblés en routant, pas seulement un ajout de tuyauterie.**

1. **Rotation vraiment automatique.** `application.VaultService.Rotate` exigeait jusqu'ici un `newSecret` fourni explicitement — ce qui contredit l'exigence de `docs/architecture/system-overview.md` ("Rotation automatique") : un opérateur n'a jamais à inventer ni connaître la nouvelle valeur. `Rotate` génère désormais 32 octets aléatoires (`crypto/rand`) si `newSecret` est vide, testé explicitement (`TestRotate_AutoGeneratesSecretWhenNoneProvided`, `TestRotate_AutoGeneratesDifferentSecretsEachTime`) et vérifié en inter-processus réel (`admin_routes_test.go` : rotation via la Gateway, puis récupération directe du credential pour confirmer qu'il a réellement changé).
2. **Traduction REST publique ↔ contrat interne.** `POST /vault/accounts/{id}/rotate` (`docs/api/rest/openapi.yaml`, id dans l'URL, pas de corps) ne correspond pas à `POST /vault/v1/rotate` de Password Vault (accountId dans le corps JSON, antérieur à ce travail de routage). La Gateway traduit — extrait l'id du chemin, construit le corps, ne transmet jamais de secret côté client — plutôt que de changer le contrat interne déjà testé de Password Vault pour coller à une forme REST qui n'avait jamais été exercée de bout en bout avant maintenant.

**Même principe d'injection d'identité qu'ailleurs, appliqué à `POST /policies`** : `createdBy` est systématiquement écrasé par le nom d'utilisateur que la Gateway vient de vérifier, jamais celui que le client revendique — testé au niveau HTTP unitaire (faux backend qui capture) et en inter-processus réel (la politique créée via la Gateway avec un `createdBy` falsifié est ensuite vérifiée comme *effectivement fonctionnelle* via un vrai `CheckAccess`).

**Ce que cet incrément ne fait toujours pas** : aucune de ces routes admin n'exige de rôle particulier (ex. `admin`) — un jeton valide suffit, quel que soit le rôle qu'il porte. C'est un vrai gap de sécurité pour un déploiement au-delà d'un pilote, distinct de (mais lié à) l'absence de vérification RBAC sur les écritures du Password Vault lui-même, déjà signalée. Les deux sont liés : imposer un rôle au niveau Gateway sans que Password Vault vérifie quoi que ce soit en interne resterait un contrôle en un seul point, contournable par quiconque atteint directement le port de Password Vault.

## Ce que le codec SSH couvre, et ce qu'il ne couvre pas encore

**Couvert et testé** (`services/proxy/ssh-proxy/internal/sshcodec/codec_relay_test.go`) : un vrai `ssh.Client` (l'opérateur) se connecte à travers un vrai serveur SSH (le proxy), qui authentifie la connexion via un ticket à usage unique, récupère le credential auprès du Vault, s'authentifie vers une vraie fausse cible SSH avec ce credential exact, et relaie un shell interactif dans les deux sens — avec capture de commande (`RecordingTap`) et purge mémoire du credential en fin de session.

**Câblage Session Broker ↔ ssh-proxy — fait.** `Session Broker` expose désormais le vrai `POST /sessions/{id}/connect` public (`docs/api/rest/openapi.yaml`) : il résout les métadonnées du compte via `GET /vault/v1/accounts/{id}` (nouvellement implémenté, métadonnées seules), obtient un scope Vault, puis appelle le vrai `ProxyControl.EstablishSession` de `ssh-proxy` — et ne renvoie que le `connection_ticket` du proxy, jamais le `scope_token` Vault (`session-broker/internal/application`, `Connect`, testé explicitement : `TestConnect_NeverReturnsTheScopeTokenItself`). `test/integration/broker_flow_test.go` prouve l'ensemble sur **cinq** processus réels séparés, jusqu'à une vraie connexion SSH d'opérateur simulée à travers la vraie API publique du Broker.

**Écart de modèle de données comblé en cours de route** : `PrivilegedAccount` a maintenant un champ `Username` (`services/vault/password-vault/internal/domain/account.go`) — la solution définitive à l'écart signalé dans l'incrément précédent, pas seulement un contournement supplémentaire.

**Convention introduite** : `target_host` inclut désormais le port (`10.0.4.12:22`, pas seulement `10.0.4.12`) — nécessaire pour que `ssh-proxy` puisse `net.Dial` directement. À formaliser dans `docs/architecture/data-architecture.md` lors d'une prochaine révision.

**Non couvert par cet incrément** :
- ~~Les sous-systèmes `exec` et SFTP/SCP (seul `shell` interactif est géré).~~ **Levé par ADR-0038** pour SFTP et l'ancien SCP (chaque transfert enregistré avant d'être transmis) ; tout autre `exec` reste refusé.
- Une clé hôte persistée pour `ssh-proxy` (générée à chaque démarrage de processus actuellement).
- Un registre de proxies par `proxyServiceID` — `Session Broker` n'a qu'un seul `ProxyClient` configuré (`SSH_PROXY_URL`), suffisant tant que MVP ne couvre qu'un seul protocole (`docs/roadmap.md` §2).

## Conséquences pour ce qui est implémenté ici

| Ce que dit la `docs/api/grpc/README.md` | Ce qui est réellement codé dans ce sandbox | Pourquoi c'est un remplacement sûr |
|---|---|---|
| Transport interne en gRPC/Protobuf | HTTP/JSON, avec exactement les mêmes noms de champs que les messages `.proto` (`scope_token`, `calling_proxy_id`, `credential_material`, `actor_roles`, `decision_reason`, …) | `internal/interfaces/http.go` de chaque service est la seule couche concernée ; `internal/application` et `internal/domain` n'ont aucune dépendance à un transport |
| `POST /sessions/{id}/connect` retournant un `ConnectionTicket` (`docs/api/rest/openapi.yaml`) | `Session Broker` expose `POST /internal/v1/authorize-connection`, qui retourne le `scope_token` Vault directement — volontairement sous un chemin distinct, jamais exposé publiquement | Le vrai `connection_ticket` client-facing doit être émis par le proxy lui-même (`ProxyControl.EstablishSession`, `docs/api/grpc/README.md` §4) — maintenant implémenté dans `services/proxy/ssh-proxy`, mais pas encore appelé par le Session Broker (qui appelle toujours son propre endpoint interne). Le câblage Broker → Proxy est le prochain incrément |

Rien dans `internal/domain` ou `internal/application` ne mentionne HTTP, JSON, ni aucun détail de transport — c'est exactement la séparation Clean Architecture posée dans `docs/development/repository-structure.md` §3 qui rend ce remplacement sans douleur.

## Ce qui reste vrai et testé malgré la contrainte

- La purge mémoire du credential, octet par octet (`pkg/proxycore`).
- Le chiffrement enveloppe AES-256-GCM et le versionnement des secrets (`password-vault`).
- Le scope à usage unique et son rejet strict par identité de proxy (`password-vault`, prouvé aussi en inter-processus par `test/integration`).
- Le chaînage de hash de l'audit et la détection de falsification, y compris quand l'attaquant recalcule le hash de l'événement modifié (`audit-service`). *(Précisé à ADR-0026 : seulement s'il ne recalcule pas aussi tous les événements suivants — la chaîne n'a pas de clé ; et, jusqu'à ADR-0026, un déplacement d'octets entre deux champs voisins n'était pas détecté.)*
- Le RBAC deny-by-default, avec un `deny` explicite qui l'emporte toujours sur un `allow`, quel que soit l'ordre de création des politiques (`authorization`).
- L'audit fail-closed : un échec d'émission d'événement d'audit empêche l'octroi de la session plutôt que de l'accorder silencieusement sans trace (`session-broker`, cohérent avec `docs/deployment/high-availability.md` §1).
- Le fait que `VaultAuthorizer` (le port utilisé par le Session Broker) n'a structurellement aucune méthode `FetchCredential` — l'invariant ADR-0003 est encodé au niveau du système de types Go, pas seulement documenté.
- Un vrai protocole SSH de bout en bout — vrai client, vrai proxy, vraie cible — avec injection du credential exact récupéré au Vault, ticket de connexion à usage unique rejeté au niveau du handshake SSH lui-même s'il est invalide ou réutilisé, et capture de commande (`ssh-proxy`).
- Le flux complet AuthorizeScope → FetchCredential → purge → audit, entre deux vrais binaires séparés communiquant en HTTP réel (`test/integration/ssh_flow_test.go`).
- **Le flux complet de bout en bout — control plane ET data plane** — `CreateSession` (deny-by-default) → `POST /sessions/{id}/connect` réel (résolution de compte → scope Vault → `EstablishSession` sur le vrai `ssh-proxy`, ne renvoyant que le `connection_ticket`, jamais le `scope_token`) → vraie connexion SSH d'un opérateur simulé → vraie cible recevant le credential exact → chaîne d'audit intacte → session terminée ne peut plus se connecter — entre **cinq** vrais binaires séparés (`test/integration/broker_flow_test.go`).

## RBAC réel sur les écritures du Vault, et PostgreSQL réel

**Le dernier écart RBAC est comblé — les deux moitiés ensemble.** `application.VaultService.OnboardAccount` et `Rotate` appellent désormais un vrai `Authorization.CheckAccess`, fail-closed, avant toute écriture — exactement le même principe que l'audit fail-closed du Session Broker (`docs/deployment/high-availability.md` §1). La Gateway injecte les rôles vérifiés dans les requêtes qu'elle transmet, mais ne duplique pas la décision : c'est Password Vault lui-même qui refuse, qu'on l'atteigne via la Gateway ou directement sur son port. Testé à trois niveaux : unitaire (deny-by-default, fail-closed si Authorization injoignable, un rôle avec seulement les droits de création de session ne suffit pas à administrer un compte), HTTP (la Gateway écrase l'`actorRoles` revendiqué par le client), et inter-processus réel (`admin_routes_test.go` : refus 403 explicite avant toute politique, puis succès une fois la politique créée).

**Choix de conception** : un nouvel espace de ressource `vault:account-admin:<id>`, distinct de `vault:account:<id>` (vérifié pour la création de session). Le modèle de politiques (`docs/architecture/data-architecture.md` §3) n'a pas de dimension action — avoir le droit de session sur un compte n'offre donc aucun droit d'administration dessus, et réciproquement. C'est la façon la plus simple de séparer ces deux privilèges sans étendre le modèle de politiques.

**PostgreSQL réel, vérifié avec une vraie base qui tourne.** `postgresql` et `postgresql-contrib` s'installent via `apt-get` (dépôts Ubuntu, déjà autorisés) dans ce sandbox. `github.com/lib/pq` — hébergé directement sur GitHub, aucun problème d'import vanity contrairement à `golang.org/x/*` — se résout normalement via `GOPROXY=direct`. `services/vault/password-vault/internal/infrastructure/postgres_store.go` implémente les trois mêmes interfaces de dépôt que `InMemoryStore` (`domain.AccountRepository`, `domain.SecretRepository`, `domain.ScopeRepository`) — exactement le bénéfice de la séparation Clean Architecture annoncé depuis le début : aucun changement à `internal/application` pour faire la bascule.

**Écarts assumés, documentés dans `migrations/001_init.sql`** : les identifiants sont des `TEXT` fournis par l'appelant, pas des UUID générés par PostgreSQL comme le DDL d'origine (`docs/architecture/data-architecture.md` §3) le prévoyait — changer maintenant casserait tous les identifiants déjà utilisés partout ailleurs, pour un bénéfice marginal. Et `vault_scope_grants` n'existait pas dans le DDL de `docs/architecture/data-architecture.md` — les scopes à usage unique devaient bien vivre quelque part une fois la persistance réelle posée ; ajoutée en cohérence avec `domain.ScopeGrant`, pas improvisée à la volée.

**Un avantage concret de PostgreSQL sur `InMemoryStore`, prouvé et pas seulement affirmé** : `ConsumeIfValid` (le cœur du caractère « à usage unique » des scopes, ADR-0003) utilise un `UPDATE ... RETURNING` atomique — qui tiendrait sous plusieurs répliques de Password Vault partageant une base, contrairement au mutex Go d'`InMemoryStore`, qui ne protège que l'intérieur d'un seul processus.

**Preuve de persistance réelle, pas seulement « compile contre l'interface »** : `test/integration/postgres_flow_test.go` onboarde un compte sur un premier processus `password-vault`, **tue ce processus**, démarre un second processus entièrement séparé pointé sur la même base, et vérifie que le compte — et après rotation, le nouveau secret — y est toujours. C'est exactement la propriété qu'`InMemoryStore` ne pourrait jamais avoir.

**Limite pratique de ce sandbox, pas du code** : le service `postgresql` ne persiste pas de façon fiable entre deux appels d'outil séparés dans cet environnement (contrairement au système de fichiers) — `service postgresql start` doit être relancé avant toute suite de tests qui en dépend. `make test-postgres` et `TEST_DATABASE_URL` existent justement pour que ce soit un geste explicite et isolé, jamais une dépendance silencieuse de `make test`.

## RBAC réel sur l'Authorization Service lui-même, et PostgreSQL pour ses policies

**Le dernier gap RBAC connu est comblé.** `POST /policies` (création de politique) acceptait n'importe quel appelant jusqu'ici — explicitement signalé comme tel dans le commentaire de package de l'API Gateway et dans la section précédente de ce document. `application.AuthorizationService.CreatePolicy` exige désormais un accès sur une ressource dédiée, `authz:policy-admin`, vérifié via `CheckAccess` — **en interne, sans appel réseau** : Authorization est sa propre autorité ici, contrairement à Password Vault qui appelle Authorization à travers le réseau (`AuthorizationClient`, `vault_service.go`). Une erreur du dépôt de politiques reste fail-closed (jamais traitée comme un `allow`).

**Le problème de l'œuf et la poule, et comment il est résolu.** Si la création d'une politique exige déjà une politique, qui crée la toute première ? `AuthorizationService.BootstrapAdminPolicy(ctx, role, createdBy)` contourne volontairement `requirePolicyAdmin`, mais **seulement** quand le dépôt de politiques est entièrement vide (`PolicyRepository.Count() == 0`) — jamais sinon, même pour un rôle différent, pour qu'un appelant ultérieur (y compris compromis) ne puisse jamais s'octroyer un nouveau rôle admin sur un système déjà initialisé. `cmd/authorization/main.go` l'appelle à chaque démarrage (variable `BOOTSTRAP_ADMIN_ROLE`, défaut `platform-admin`) — un no-op sur tout redémarrage d'un système déjà initialisé, exactement le même principe qu'un jeton root HashiCorp Vault ou qu'un compte admin de bootstrap Keycloak, mais exprimé ici comme une politique ordinaire plutôt qu'un type de credential à part. Testé à trois niveaux, comme pour le gap Vault précédent : unitaire (refusé sans accès, refusé si l'accès ne vient que d'un rôle sans rapport, bootstrap crée la première politique sur un dépôt vide, bootstrap est un no-op dès qu'une politique existe déjà — même pour un rôle différent —, fail-closed si le dépôt erre), HTTP (la Gateway écrase désormais `actorRoles` sur `POST /policies` exactement comme elle le fait déjà pour l'onboarding/la rotation du Vault), et inter-processus réel (`admin_routes_test.go` : refus 403 explicite avant toute politique-admin, succès une fois la politique créée par `platform-admin`).

**PostgreSQL pour les policies**, même patron que le Vault : `services/access/authorization/migrations/001_init.sql` (même écart assumé — identifiants `TEXT`, pas de table `roles` séparée puisque les rôles restent des attributs fédérés par l'IdP, pas une entité gérée localement en MVP), `postgres_store.go` implémentant `domain.PolicyRepository` (`Create`, `ForRoles` — via `pq.Array` pour couvrir tous les rôles de l'appelant en une seule requête —, `Count`, qui fonde `BootstrapAdminPolicy`), `cmd/authorization/main.go` bascule sur `DATABASE_URL` avec repli en mémoire. Preuve de persistance réelle inter-processus, même format que pour le Vault : `TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart` crée une politique sur un premier processus, le tue, démarre un second processus séparé sur la même base, et vérifie que la politique — et le fait que le bootstrap ne se relance jamais — survivent.

## Deux bugs réels trouvés en exerçant PostgreSQL pour de vrai, pas seulement « compile contre l'interface »

Les deux bugs suivants étaient invisibles avec `InMemoryStore` — rien n'y imposait les contraintes que PostgreSQL impose réellement — et seule l'exécution d'un vrai redémarrage de processus contre une vraie base les a fait apparaître. Les deux sont corrigés et chacun a désormais un test qui l'épingle indépendamment du moteur de stockage.

1. **Clé de chiffrement locale non stable entre redémarrages.** `infrastructure.NewLocalKMS()` générait une clé AES-256 aléatoire à chaque démarrage de processus, sans aucun moyen de la retrouver au redémarrage suivant — un `password-vault` redémarré ne pouvait donc **jamais** déchiffrer ce qu'un processus précédent avait scellé, ce qui défait entièrement l'intérêt de la persistance PostgreSQL pour les secrets. Corrigé par `NewLocalKMSFromHexKey(hexKey string)` : `cmd/password-vault/main.go` refuse désormais de démarrer si `DATABASE_URL` est défini sans `KMS_KEY_HEX` (fail-closed, pas un repli silencieux sur une clé aléatoire) — `openssl rand -hex 32` pour en générer une, à garder hors de la base, cohérent avec `encryption_key_id... référence la clé KMS/HSM, pas la clé elle-même` (`docs/architecture/data-architecture.md` §3). `KMS_KEY_HEX` reste optionnel quand `DATABASE_URL` n'est pas défini (mémoire, tests). Testé dans `crypto_test.go` (deux instances construites avec la même clé hex peuvent déchiffrer l'une ce que l'autre a scellé ; deux instances aléatoires ne le peuvent pas) et dans `test/integration/postgres_flow_test.go` (`TestPasswordVaultMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex`, qui n'a pas besoin d'une vraie base — le refus intervient avant toute tentative de connexion).

2. **Le numéro de version suivant était calculé après la supersession, pas avant.** `VaultService` calculait le prochain numéro de version (`storeNewVersion`, désormais `storeVersion`) en relisant `CurrentVersion` **après** que `Rotate` avait déjà appelé `SupersedeCurrent` — qui efface `superseded_at` sur toute ligne existante. Résultat : la relecture ne trouvait plus jamais rien, et le numéro de version retombait systématiquement à 1, à **chaque** rotation, pas seulement la première. `InMemoryStore.AddVersion` se contente d'ajouter à une liste sans vérifier l'unicité — le bug y était invisible. La contrainte `UNIQUE (privileged_account_id, version)` de PostgreSQL, elle, l'a fait échouer net dès la première rotation exercée contre une vraie base (`TestPostgresFlow_AccountSurvivesPasswordVaultProcessRestart`, sous-test "rotation on the restarted process persists too" : `status 403`). Corrigé en déplaçant la lecture du prochain numéro de version **avant** l'appel à `SupersedeCurrent`. `TestRotate_IncrementsVersionNumberEachTime` épingle le comportement correct (versions 1 → 2 → 3 sur deux rotations successives) indépendamment du moteur de stockage, pour que ce bug ne puisse pas revenir silencieusement même si un futur dépôt en mémoire est ajouté.

## PostgreSQL étendu aux trois derniers services à état

Même patron que Password Vault et Authorization, appliqué sans surprise aux trois services à état restants — exactement le bénéfice de la séparation Clean Architecture annoncé depuis le début : zéro changement à `internal/application` pour faire basculer le stockage de chacun.

- **`authentication`** : `postgres_store.go` implémente `domain.UserRepository` (`Create`, `GetByUsername`, `GetByID`) contre la table `users` (`migrations/001_init.sql` — mêmes écarts assumés que partout ailleurs : identifiants `TEXT`, rôles stockés comme `TEXT[]` directement sur la ligne plutôt qu'une table `roles`/`user_roles` séparée, cohérent avec le commentaire déjà présent dans `domain/user.go`). `Create` renvoie les mêmes sentinelles (`ErrUsernameTaken`, `ErrUserNotFound`) que `InMemoryStore` — même package, mêmes variables, pas de duplication.
- **`session-broker`** : `postgres_store.go` implémente `domain.SessionRepository` (`Save`, `Get`) contre la table `sessions`. Seul dépôt de ce projet où `Save` doit être un **UPSERT** (`INSERT ... ON CONFLICT (id) DO UPDATE`) plutôt qu'un `Create` à usage unique : `SessionBrokerService` réutilise réellement `Save` pour mettre à jour la même ligne (`TerminateSession` relit puis réenregistre), pas seulement pour créer. Pas de clé étrangère vers `users`/`privileged_accounts` — en microservices, ces entités vivent dans les bases d'Authentication et de Password Vault, pas dans celle du Session Broker (le schéma partagé de `docs/architecture/data-architecture.md` est une référence, pas ce qu'une vraie base par service peut physiquement respecter).
- **`audit-service`** : `postgres_store.go` implémente le port `Store` de la couche application (`Append`, `Last`, `All`) contre la table `audit_events`, avec une colonne `seq BIGSERIAL` dédiée à l'ordre d'insertion — `ts` seul ne suffit pas à départager deux événements horodatés dans la même microseconde, ce que `seq` garantit sans ambiguïté.

Les trois basculent sur `DATABASE_URL` dans leur `cmd/.../main.go`, avec repli en mémoire, exactement comme Vault et Authorization.

## Trois bugs réels de plus, trouvés en exerçant PostgreSQL pour de vrai — jamais vus avec `InMemoryStore`

Même discipline que les deux bugs déjà documentés plus haut pour le Vault : chacun des trois a son propre test qui l'épingle indépendamment du moteur de stockage.

3. **`pq.Array(nil)` sérialise un rôle `nil` en `NULL`, pas en tableau vide.** `authentication`'s `users.roles` est `NOT NULL DEFAULT '{}'` — un `domain.User` créé avec un `Roles` à `nil` (cas légitime : un compte en attente de sa première attribution de rôle) compilait et passait tous les tests contre `InMemoryStore`, qui n'impose aucune contrainte, puis échouait net au premier `Create` réel contre PostgreSQL (`null value in column "roles" violates not-null constraint`) — découvert par `TestPostgresStore_Create_RejectsDuplicateUsernameWithTheSameSentinelAsInMemoryStore` la toute première fois qu'il a tourné contre une vraie base. Corrigé en normalisant un `Roles` `nil` en tranche vide avant l'`INSERT`. `TestPostgresStore_Create_NilRolesRoundTripAsEmptyNotError` épingle le comportement correct.

4. **Le hash de chaînage de l'audit était calculé sur une précision que PostgreSQL ne peut pas conserver.** `AuditService.EmitEvent` horodatait avec `time.Now().UTC()` — précision nanoseconde — et calculait `Hash` sur cette valeur **avant** tout passage en base. Or la colonne `ts` (`TIMESTAMPTZ`) n'a qu'une précision microseconde : les trois derniers chiffres de précision nanoseconde sont silencieusement tronqués à l'écriture. `VerifyChain`, qui recalcule le hash de chaque événement à partir de ce qu'il relit, retombait donc systématiquement sur une valeur différente de celle stockée — **chaque** événement passé par une vraie base se voyait signalé comme falsifié, alors que rien n'avait été altéré. Totalement invisible avec `InMemoryStore`, qui ne tronque jamais rien. Découvert par `TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart` (`verify-chain: status 409`) la toute première fois qu'un événement a réellement fait l'aller-retour par PostgreSQL. Corrigé en tronquant l'horodatage à la précision microseconde **avant** de calculer le hash, dans `EmitEvent` lui-même — ainsi la valeur hachée est, par construction, identique à ce que n'importe quel moteur de stockage peut fidèlement restituer. `TestEmitEvent_TimestampIsTruncatedToMicrosecondPrecision` épingle le comportement, indépendamment du moteur de stockage.

**Par construction, les mêmes classes de bugs qu'avant** : un invariant qui tient dans `InMemoryStore` (aucune contrainte `NOT NULL`, aucune troncature de précision) mais pas contre un vrai moteur. Aucun des cinq bugs trouvés dans ce projet (les deux du Vault, plus ces trois-ci) n'a été vu par une relecture de code ni par les tests unitaires habituels — seule l'exécution réelle contre PostgreSQL, notamment à travers un redémarrage de processus, les a fait apparaître.

## Clé de signature des tokens, stabilisée pour la même raison que la clé KMS

`authentication` avait le même défaut de conception que `LocalKMS` avant son correctif, repéré cette fois par relecture plutôt que par un test qui échoue : `GenerateSigningKey()` tirait une clé HMAC-SHA256 aléatoire à chaque démarrage de processus, ce qui aurait invalidé silencieusement tous les tokens actifs au moindre redémarrage une fois `DATABASE_URL` défini (les utilisateurs survivant au redémarrage, mais plus leurs sessions). Corrigé *avant* que PostgreSQL ne l'expose en pratique, par analogie directe avec `NewLocalKMSFromHexKey` : `SigningKeyFromHex(hexKey string)` décode/valide une clé de 32 octets fournie en hexadécimal, et `cmd/authentication/main.go` refuse de démarrer si `DATABASE_URL` est défini sans `TOKEN_SIGNING_KEY_HEX` — même discipline fail-closed, même commande `openssl rand -hex 32` pour en générer une. Testé dans `token_test.go` (même patron que `crypto_test.go` : deux instances construites avec la même clé hex vérifient les tokens l'une de l'autre ; deux instances aléatoires ne le peuvent pas) et prouvé inter-processus dans `TestPostgresFlow_UserAndSigningKeySurviveAuthenticationProcessRestart` (un token émis par le premier processus se vérifie toujours contre le second, redémarré, avec la même clé).

## Jeton HMAC maison remplacé par un vrai JWT

`github.com/golang-jwt/jwt/v5` est hébergé directement sur GitHub (contrairement à `golang.org/x/*`, dont le domaine vanity est hors allowlist réseau — voir plus haut), donc `go get` passe sans détour sous `GOPROXY=direct` dans ce sandbox. `infrastructure/token.go` (`services/access/authentication`) a basculé de l'encodage maison (payload base64 + `.` + signature HMAC base64, documenté comme un intérimaire dès l'origine) à un vrai jeton RFC 7519 à trois segments, signé HS256.

Le point intéressant n'est pas la bibliothèque elle-même mais ce que ce changement n'a **pas** touché : `application.TokenIssuer` (le port) n'a jamais mentionné d'encodage, précisément pour que ce remplacement reste contenu à `internal/infrastructure/token.go` — confirmé en pratique, zéro ligne changée dans `internal/application` ou au-dessus. La Gateway, qui ne fait jamais que relayer le jeton à `POST /auth/v1/verify`, n'a pas eu à changer non plus.

Trois décisions de sécurité/compatibilité à noter :

- **Alg confusion (RFC 8725 §3.1/§3.2), défense en profondeur.** `Verify` épingle HS256 à deux endroits indépendants : `jwt.WithValidMethods(["HS256"])` au niveau du parseur, et une vérification du type concret de la méthode à l'intérieur du `keyfunc` lui-même. Chacun des deux rejette seul un jeton `alg: none` ou signé avec un autre algorithme HMAC (HS384/HS512) en utilisant pourtant la bonne clé — testé explicitement par `TestTokenIssuer_VerifyRejectsAlgNoneToken` et `TestTokenIssuer_VerifyRejectsTokenSignedWithDifferentAlgorithm`.
- **`jwt.WithExpirationRequired()`** : un jeton sans `exp` est rejeté d'office plutôt que traité comme « n'expire jamais ». Ce service n'émet jamais un tel jeton ; un jeton qui en manque est forcément forgé ou mal émis.
- **Précision de `exp` réduite à la seconde, par construction.** `NumericDate` (RFC 7519 §2) n'a jamais plus qu'une précision seconde dans l'écosystème JWT ; `jwt.NewNumericDate` tronque silencieusement sinon. Plutôt que de laisser cette troncature se produire sans le dire, elle est actée explicitement dans `Issue` — même discipline que la troncature microseconde du chaînage d'audit plus haut, mais appliquée un cran plus tôt puisqu'ici la frontière à perte, c'est l'encodage du jeton lui-même, pas une base de données en dessous. `TestTokenIssuer_IssueThenVerifyRoundTrips` compare désormais contre `expiresAt.Truncate(time.Second)`, pas une assertion affaiblie mais la bonne attente : aucun appelant, même avant ce changement, ne pouvait observer `exp` nulle part ailleurs qu'en test (la Gateway ne reçoit jamais que `expiresIn` en secondes).

Trois nouveaux tests dans `token_test.go` (en plus de ceux déjà là, intacts) : la forme à trois segments du jeton émis, et les deux rejets alg confusion ci-dessus. `make build`/`vet`/`test`/`test-postgres`/`test-integration` : tous verts, y compris `TestGatewayFlow_LoginThroughRealSSHConnection_AcrossSevenRealProcesses` (le jeton réel transite par une vraie connexion SSH de bout en bout) et `TestPostgresFlow_UserAndSigningKeySurviveAuthenticationProcessRestart` (le jeton survit, inchangé dans son format, à un redémarrage de processus).

## `Username` formalisé dans le modèle de données et le contrat proto — l'écart documenté plus haut est refermé

Rattrape l'« Écart de modèle de données découvert en implémentant le codec SSH » documenté en tout début de ce fichier. En relisant le code pour le combler, il s'avère que la moitié du travail était déjà faite sans que ce fichier n'ait été mis à jour en conséquence : `privileged_accounts.username` existe déjà dans la vraie migration (`services/vault/password-vault/migrations/001_init.sql`) et dans `domain.PrivilegedAccount`, avec un commentaire de doc qui le dit explicitement (« added here directly rather than worked around again »), et `target_user` circule déjà, en vrai, de bout en bout — Session Broker → `ProxyClient.EstablishSession` → `ssh-proxy`'s `EstablishSessionRequest.TargetUser` → la connexion SSH réelle vers la cible. Rien de tout ça n'était un écart de comportement : uniquement un écart entre le code qui tourne et les documents qui le décrivent.

Ce qui restait donc réellement à faire — et qui vient de l'être — c'est seulement de mettre les contrats à jour pour qu'ils cessent de mentir sur ce que le système fait déjà :

- `proto/proxy/v1/proxy_control.proto` : `EstablishSessionRequest` gagne `string target_user = 6`.
- `docs/api/grpc/README.md` : même ajout dans l'extrait proto reproduit au §4, plus le diagramme de séquence du §9 (`EstablishSession(session_id, target_host, target_user, scope_token)`).
- `docs/architecture/data-architecture.md` : `username` ajouté à la fois dans le diagramme entité-relation (§2) et dans le `CREATE TABLE privileged_accounts` (§3), pour matcher la vraie migration.

**Ce qui n'a volontairement pas été touché, et pourquoi** : la formulation d'origine de cet item de roadmap mentionnait aussi `proto/vault/v1/vault.proto`. En le relisant, `AuthorizeScopeRequest`/`FetchCredentialResponse` ne portent et ne doivent jamais porter de métadonnée de compte (ADR-0003 : ces deux RPC n'échangent qu'un jeton de scope ou un secret, jamais autre chose) — y ajouter `username` violerait l'invariant même que ce proto existe pour faire respecter. Le vrai répondant, `EstablishSessionRequest`, était dans `proxy_control.proto`, pas `vault.proto` ; la mention de `vault.proto` dans la roadmap d'origine était donc inexacte, pas seulement incomplète.

**Écart différent, pré-existant, non refermé ici** : la surface d'administration du Vault (onboard/get/rotate un compte) n'avait aucune représentation formelle dans `proto/`. Correction : l'affirmation initiale de cette même entrée, selon laquelle `docs/api/rest/openapi.yaml` n'en avait pas non plus, était fausse — une recherche trop superficielle à l'époque (`grep -i username` sans chercher les chemins REST eux-mêmes). `/vault/accounts`, `/vault/accounts/{accountId}` et `.../rotate` y sont bel et bien spécifiés en OpenAPI 3.1 depuis le début (§2), avec les schémas `PrivilegedAccountInput`/`PrivilegedAccount`. Voir la section suivante pour ce que ça change.

Aucun code Go n'a changé : ce n'était pas nécessaire, le comportement réel était déjà correct. `make build`/`vet`/`test`/`test-postgres`/`test-integration` restent verts sans modification de leur côté.

## Surface d'admin Vault : `VaultAccountAdmin` ajouté au proto, et deux vrais écarts corrigés dans l'OpenAPI existant

Corrige l'affirmation de la section précédente, découverte fausse en y retournant pour la traiter. `docs/api/rest/openapi.yaml` documentait déjà `/vault/accounts` (GET liste, POST onboard), `/vault/accounts/{accountId}` (GET, DELETE) et `.../rotate` (POST), avec des schémas `PrivilegedAccountInput`/`PrivilegedAccount` — juste pas vus la première fois faute d'avoir cherché les chemins eux-mêmes plutôt que le seul mot « username ». Deux vrais écarts s'y trouvaient néanmoins, indépendants de ceux déjà traités :

- `PrivilegedAccountInput` n'avait pas `username` — même nature que les écarts proto/`docs/architecture/data-architecture.md` refermés plus haut, juste localisé dans le troisième contrat (OpenAPI) plutôt que les deux premiers. Ajouté, et rendu `required` au même titre que `name`/`targetHost`/`protocol` (même traitement `NOT NULL` que ces trois dans la vraie migration).
- `rotationPolicy` n'énumérait que `[manual, post_use]`, alors que `domain.RotationPolicy` (et le `CHECK` de `docs/architecture/data-architecture.md` §3) en acceptent trois : `scheduled` manquait. `scheduled` est une valeur de premier rang dès aujourd'hui au niveau stockage (aucun `CHECK` ne la distingue des deux autres dans la vraie migration) même si rien ne l'exploite encore activement (le Scheduler qui le ferait est hors périmètre MVP, `docs/roadmap.md`) — son absence de l'énumération publique avait toutes les apparences d'un oubli, pas d'un choix.

Et, comme pour `target_user` plus haut, le contrat gRPC qui manquait réellement a été ajouté : `VaultAccountAdmin` (`proto/vault/v1/vault.proto`, miroir dans `docs/api/grpc/README.md` §5 et §10), avec `OnboardAccount`/`GetAccount`/`RotateSecret` — les trois seules opérations que `password-vault/internal/interfaces/http.go` implémente réellement. `PrivilegedAccount` y porte des métadonnées (`username` compris) sans violer ADR-0003 : ce service est explicitement hors du chemin critique scope-puis-secret que l'ADR protège, et aucun de ses trois RPC ne renvoie de secret.

**Ce qui n'a volontairement pas été ajouté, et pourquoi** : `docs/api/rest/openapi.yaml` documente aussi `GET /vault/accounts` (liste paginée) et `DELETE /vault/accounts/{id}`, et donne à `POST .../rotate` un `requestBody` vide — alors que l'implémentation réelle n'a ni liste, ni suppression, et que son `rotateRequest` accepte en réalité un `newSecret` optionnel non documenté. Écart réel, mais différent en nature des précédents (une opération entière à construire, pas un champ à ajouter à un contrat existant) et non introduit par cet incrément — noté ci-dessous plutôt que traité à la volée.

Aucun code Go n'a changé ici non plus. `make build`/`vet`/`test`/`test-postgres`/`test-integration` restent verts.

## `GET /vault/accounts` (liste) et `DELETE /vault/accounts/{id}` implémentés — l'écart documenté juste au-dessus est refermé

Les deux opérations que `docs/api/rest/openapi.yaml` documente depuis le tout début du projet mais que `password-vault` n'a jamais réalisées. Suppression logique (soft delete), pas un `DELETE` SQL : `domain.PrivilegedAccount.DisabledAt` et la colonne `disabled_at TIMESTAMPTZ` existaient déjà (lues par `PostgresStore.Get`) mais n'étaient écrites nulle part — `grep -rn "DisabledAt\|disabled_at"` le confirme avant cet incrément. Une suppression physique aurait `CASCADE` dans `vault_secrets` (`migrations/001_init.sql`), détruisant l'historique de versions de secrets qu'un PAM existe justement pour préserver à des fins d'audit.

Trois décisions de sécurité découlent directement de ce choix, pas ajoutées après coup :

- **`GetAccount` renvoie `domain.ErrNotFound` pour un compte désactivé**, exactement comme pour un compte inconnu. C'est ce qui ferme réellement la porte à de nouvelles sessions sans toucher au code du Session Broker : `AccountLookupHTTPClient.GetAccount` (session-broker) appelle ce même `GET /vault/v1/accounts/{id}` que la vue détail de l'admin UI — confirmé en lisant `services/access/session-broker/internal/infrastructure/account_client.go` et le port `AccountLookup` dans `session_broker_service.go`.
- **`AuthorizeScope` vérifie `DisabledAt` lui-même**, indépendamment de `GetAccount` — défense en profondeur délibérée : une requête qui atteindrait ce point en contournant la résolution de compte (contournement du Gateway/Session Broker, ou future route qui oublierait l'appel à `GetAccount`) doit quand même être rejetée. Les deux chemins sont testés séparément (`TestDisableAccount_GetAccountThenReturns404`, `TestDisableAccount_BlocksAuthorizeScope`).
- **`ListAccounts` est RBAC-gated** (`vault:account-admin:*`, action `vault:account:list`) — contrairement à `GetAccount`, qui n'a jamais été protégé par RBAC (écart préexistant, non traité ici : voir plus haut « jamais vu jusqu'ici » dans ce fichier). Un listage expose plus d'informations d'un coup qu'une consultation ciblée ; ne pas étendre la protection à `GetAccount` dans ce même incrément est un choix de périmètre, pas un oubli — noté explicitement pour ne pas être perdu.

**Transport de `actorRoles` en query string, pas en JSON body**, pour ces deux routes seulement : `GET` et `DELETE` ne portent conventionnellement pas de corps, contrairement à `onboard-account`/`rotate` (POST). Le motif est appliqué identiquement aux deux couches qui en avaient besoin — `password-vault/internal/interfaces/http.go` (`splitCommaList` sur `?actorRoles=role1,role2`) et l'API Gateway (`handleVaultAccountsCollection`'s GET branch, `handleVaultAccountItem`'s DELETE branch, toutes deux via `url.Values.Encode()` plutôt qu'une concaténation de chaîne brute, pour rester correct si un nom de rôle contenait un caractère à encoder).

`net/http`'s `ServeMux` distingue un chemin exact (`/vault/v1/accounts`) d'un sous-arbre (`/vault/v1/accounts/`, slash final) — déjà exploité côté Gateway pour `handleVaultAccountsCollection`/`handleVaultAccountItem` ; le même motif, déjà établi, est répliqué côté `password-vault` lui-même (`handleListAccounts` sur le chemin exact, `handleAccountItem` — ex-`handleGetAccount`, renommé pour refléter qu'il gère maintenant GET et DELETE — sur le sous-arbre).

`docs/api/rest/openapi.yaml` : `PrivilegedAccount` gagne `disabledAt` (absent tant que le compte est actif). **Écart de périmètre non traité ici, noté pour rester honnête** : la réponse JSON réelle de `password-vault` (`accountResponse` dans `interfaces/http.go`) n'a jamais exposé `rotationPolicy`/`lastRotatedAt`/`createdAt` alors que `PrivilegedAccount` les documente depuis le début — préexistant à cet incrément, pas élargi par lui (discipline de périmètre : cet incrément ferme l'écart liste/suppression, pas un audit complet du contrat de réponse).

Couverture : 7 tests dans `internal/application` (RBAC liste/désactivation, exclusion des comptes désactivés, pagination `page`/`pageSize` bornée à `[1,100]` par `ListAccounts` lui-même — `docs/api/rest/openapi.yaml` — pas par l'appelant, blocage d'`AuthorizeScope`), 2 tests PostgreSQL réels (`List`/`Disable`, gated `TEST_DATABASE_URL`), 2 tests HTTP côté Gateway (injection `actorRoles` en query string, relai des paramètres `page`/`pageSize`), et 4 sous-tests ajoutés au scénario d'intégration `admin_routes_test.go` qui tournent sur quatre vrais processus séparés — Authentication, Authorization, Password Vault, API Gateway — prouvant la chaîne complète : onboard → apparaît dans la liste → désactivé → disparaît de la liste → 404 sur `GET` → `AuthorizeScope` refusé → re-désactiver un compte déjà désactivé est lui-même un 404 (pas une erreur silencieuse). `make build`/`vet`/`test`/`test-postgres`/`test-integration` restent verts.

## `rotate` clarifié dans `docs/api/rest/openapi.yaml`, `rotationPolicy`/`lastRotatedAt`/`createdAt` exposés — et un troisième bug du même type que `disabled_at` trouvé en le faisant

Referme les deux points laissés ouverts juste au-dessus.

**`newSecret` : pas ajouté au `requestBody` public, et c'est délibéré.** En relisant le code avant d'écrire la doc, `handleVaultAccountItem` (API Gateway) ne relaie **jamais** un secret fourni par le client vers `/vault/v1/rotate` — commentaire déjà présent dans ce fichier : « un opérateur ne doit jamais inventer la valeur ». Documenter `newSecret` dans le `requestBody` public de `docs/api/rest/openapi.yaml` aurait donc décrit un comportement que le système ne fournit pas à cette frontière-là — un contrat inexact, pas juste incomplet. `docs/api/rest/openapi.yaml` reçoit à la place une `description` explicite sur `POST /vault/accounts/{id}/rotate` : aucun corps n'est accepté, et pourquoi (choix de sécurité de la Gateway, pas un oubli), avec un renvoi vers le vrai porteur de ce champ — le contrat interne `VaultAccountAdmin.RotateSecret` (`proto/vault/v1/vault.proto`, déjà mirroré fidèlement dans `docs/api/grpc/README.md` §5 depuis l'incrément précédent, vérifié avant d'écrire quoi que ce soit).

**`rotationPolicy`/`lastRotatedAt`/`createdAt` exposés** dans `accountResponse` (`password-vault/internal/interfaces/http.go`), via un nouveau `toAccountResponse` partagé par `handleAccountItem` (GET) et `handleListAccounts` — jusqu'ici dupliqué entre les deux, c'est exactement comme ça que `disabled_at` avait pu être oublié une fois dans l'un des deux endroits par le passé.

**Troisième occurrence du même bug que `disabled_at`, trouvée en essayant d'exposer `lastRotatedAt` honnêtement** : la colonne `last_rotated_at` existe dans la DDL depuis le début et `PostgresStore.Get`/`List` l'ont toujours lue — mais rien ne l'écrivait nulle part. `Rotate` (`application.VaultService`) créait de nouvelles versions de secret sans jamais toucher la ligne du compte lui-même. Exposer le champ tel quel aurait donc produit une réponse JSON structurellement toujours vide — pas un simple écart de doc comme les deux précédents, mais une régression silencieuse qu'ajouter `lastRotatedAt,omitempty` sans rien d'autre aurait rendue invisible (toujours absent, jamais une erreur). Corrigé par une nouvelle méthode `AccountRepository.MarkRotated` (même forme que `Disable` : idempotente, l'existence du compte est vérifiée par l'appelant), appelée par `Rotate` seulement après que la nouvelle version de secret a été stockée avec succès — pour qu'une rotation en échec ne puisse jamais prétendre avoir eu lieu.

**Observation faite en touchant `Rotate`** : `Rotate` ne vérifiait pas `DisabledAt` avant d'agir, contrairement à `GetAccount`/`AuthorizeScope` — traitée juste après, voir la section suivante.

Tests : 2 nouveaux dans `internal/application` (`LastRotatedAt` reste `nil` tant qu'aucune rotation n'a eu lieu, puis se peuple et ne recule jamais sur une deuxième rotation), 1 PostgreSQL réel (`MarkRotated`, gated `TEST_DATABASE_URL`), et les deux sous-tests existants d'`admin_routes_test.go` sur `/vault/accounts/{id}` étendus (métadonnées complètes avant rotation, `lastRotatedAt` apparaît après une vraie rotation routée par la Gateway). `make build/vet/test/test-postgres/test-integration` restent verts.

## `Rotate` refuse enfin un compte désactivé — dernier point de la série « désactivé = comme s'il n'existait pas »

Observation laissée ouverte dans la section précédente, maintenant traitée. Avant ce correctif, `Rotate` appelait `accounts.Get` et ignorait `DisabledAt` : faire tourner une rotation sur un compte désactivé était accepté (202), créait une nouvelle version de secret **et** posait `LastRotatedAt` — sur une ligne que `GetAccount`, `ListAccounts` et `AuthorizeScope` traitent tous, depuis l'incrément liste/suppression, comme supprimée. Rien ne fuyait (`AuthorizeScope` refusait de toute façon d'émettre un scope sur ce compte) mais la ligne continuait de changer *après* sa « suppression », ce qui est exactement ce qu'un journal d'audit ne devrait pas avoir à expliquer.

Même motif qu'`AuthorizeScope` : `Rotate` vérifie `DisabledAt` lui-même plutôt que de passer par `GetAccount`, pour ne pas dépendre du comportement d'une autre méthode pour rester correct. Les quatre opérations du Vault qui touchent un compte (`GetAccount`, `AuthorizeScope`, `DisableAccount`, `Rotate`) appliquent maintenant toutes la même règle.

Tests : `TestDisableAccount_BlocksRotate` (refus `ErrNotFound`, la version de secret reste à 1, `LastRotatedAt` reste `nil` — c'est l'absence de trace qui est vérifiée, pas seulement le refus) et un sous-test d'intégration sur quatre vrais processus (rotation d'un compte désactivé via la Gateway : refusée, pas 202). `make build/vet/test/test-postgres/test-integration` verts.

## `rotate` répond 404 pour un compte introuvable ou désactivé — le dernier code de statut qui mentait

Point laissé en suspens à la fin de la section précédente, tranché sur demande : `handleRotate` répondait 403 à toute erreur, y compris « compte introuvable ou désactivé », alors que `DELETE` distinguait déjà 404 de 403. Un opérateur autorisé qui se trompait d'identifiant apprenait qu'il était « interdit » plutôt que que le compte n'existait pas.

`rotate` et `DELETE` passent maintenant par un seul `adminErrorStatus` : `domain.ErrNotFound` → 404, tout le reste (refus RBAC, Authorization injoignable donc fail-closed) → 403, comme avant. `DELETE` comparait l'erreur avec `==` ; `errors.Is` le remplace, pour que l'ajout d'un enrobage d'erreur plus tard ne casse pas silencieusement le 404.

**Ce que ce changement ne doit pas permettre, et pourquoi il ne le permet pas** : distinguer 403 de 404 pourrait servir à sonder quels comptes existent. `VaultService` vérifie l'accès (RBAC) *avant* l'existence, donc un appelant non autorisé reçoit 403 que le compte existe ou non. Un sous-test d'intégration le fige explicitement (rotation refusée en 403, pas 404, avant toute politique d'admin — sur un compte qui n'existe pas encore) ; sans lui, un réordonnancement futur de ces deux vérifications ouvrirait cette fuite sans qu'aucun test ne bouge.

Un compte désactivé reste indiscernable d'un compte inconnu (404 dans les deux cas), cohérent avec `GetAccount`. `docs/api/rest/openapi.yaml` documente maintenant 403 et 404 sur `rotate` et `DELETE /vault/accounts/{id}`, avec cet ordre.

Tests : 1 sous-test ajouté (403 avant 404), 1 resserré (désactivé : 404 exact, plus un simple « pas 202 »), 1 ajouté (compte inconnu : 404), tous sur quatre vrais processus. Aucune fonction de test top-level ajoutée : les comptes restent 134 unitaires / 10 d'intégration.

## Le Recording Tap ne voyait aucune commande d'une vraie session interactive — et ne protégeait pas les mots de passe saisis

Avant de bâtir le Command Recorder (critère de sortie MVP : « le replay texte retrouve chaque commande exécutée »), j'ai vérifié que ce qui l'alimenterait capture bien les commandes. Ce n'était pas le cas.

**Le bug.** `RecordingTap` ne coupait les lignes que sur `\n`. Or un client SSH avec PTY envoie `\r` à la touche Entrée. Les tests existants (`proxycore` et le test de bout en bout du proxy) passaient parce qu'ils envoient `\n` à la main, comme un `printf` — jamais comme un terminal. Reproduit par un test qui échouait avant la correction : `whoami\r` donnait zéro entrée. En usage réel, rien n'aurait été enregistré.

**Ce que le tap fait maintenant**, comme un éditeur de ligne de terminal : `\r`, `\n` et `\r\n` terminent une ligne (un `\r\n` ne compte qu'une fois, même coupé entre deux écritures) ; retour arrière/DEL retire un caractère entier (UTF-8 compris) ; Ctrl-C et Ctrl-U abandonnent la ligne, Ctrl-W retire le dernier mot ; les séquences d'échappement (flèches, marqueurs de collage) et les autres octets de contrôle (Tab…) sont écartés, y compris quand une séquence est coupée entre deux écritures ; une ligne est tronquée à 8 Kio (un flux binaire sans terminateur ne fait plus grossir le tampon). `Record` est appelé hors du verrou : un enregistreur lent ne bloque plus l'observateur de sortie, donc l'autre moitié du relais.

**Mots de passe saisis à un prompt.** Une fois les commandes réellement capturées, un `sudo` aurait stocké le mot de passe en clair dans l'enregistrement. Le tap observe maintenant la sortie de la cible (`Codec.OutputObserver`, branché sur `RecordingTap.Output()`) : quand la ligne de sortie en cours ressemble à un prompt `password`/`passphrase`/`passcode`/`verification code`/`PIN`, la ligne saisie ensuite est enregistrée comme `[redacted: input at a secret prompt]` (`proxycore.RedactedSecretInput`) au lieu de son contenu. Un nouveau retour à la ligne en sortie, ou Ctrl-C, rend le prompt caduc : un prompt resté sans réponse n'avale pas une commande ultérieure.

**Pourquoi un marqueur plutôt que de ne rien enregistrer.** Le texte du prompt vient de la cible, que l'opérateur contrôle : un initié peut afficher un faux prompt (`printf 'Password: '`) pour faire masquer UNE commande suivante. Avec un marqueur, la tentative reste visible dans le replay, juste après la commande qui a affiché le prompt ; en n'enregistrant rien, elle serait invisible.

**Limites assumées, pas corrigées ici.**
- La capture se fait au clavier, pas dans le shell : une commande rappelée de l'historique (↑, Ctrl-R), complétée par Tab ou modifiée après un déplacement du curseur est enregistrée telle que **saisie**, pas telle qu'exécutée. Combler l'écart demande une reconstruction côté cible ou côté sortie.
- La détection de prompt est une heuristique sur du texte : un prompt dans une autre langue, ou sans mot-clé reconnu, laisse passer le secret en clair.

`SSHServer` obtient son tap de `Listener.Recording` (au départ un `Recorder` injecté ; remplacé par la politique d'enregistrement, voir « Enregistrer ou refuser » plus bas), ce qui permet de tester l'enregistrement à travers la vraie pile SSH : `TestSSHProxy_InteractiveCommandsAreRecordedAndSecretPromptInputIsRedacted` joue un vrai `sudo` (prompt sans saut de ligne, saisie non répétée) et vérifie que le mot de passe n'apparaît nulle part.

Tests : `proxycore` passe de 9 à 29 (20 nouveaux), `sshcodec` de 2 à 3 ; 155 tests unitaires à ce stade (180 après le Command Recorder, 181 après la correction de pagination du Vault, 193 après le chiffrement au repos). Stabilité vérifiée sous le détecteur de course : 40 exécutions du test de bout en bout, 20 de `proxycore`.

## Command Recorder : le replay texte d'une session existe enfin (critère de sortie MVP)

La feuille de route (`docs/roadmap.md` §2) exige que « le replay texte d'une session retrouve chaque commande exécutée, horodatée ». Il n'y avait ni service d'enregistrement ni table `session_command_entries` côté code : le proxy se contentait de journaliser les commandes sur sa sortie standard (`StdoutRecorder`). Cet incrément comble l'écart, après la correction du Recording Tap décrite juste au-dessus (sans elle, rien n'aurait été capturé en session interactive).

**Le service** — `services/recording-audit/command-recorder`, port 8087, Clean Architecture comme les autres. Contrat interne `POST /recorder/v1/command-entries` (lot d'entrées `session_id`/`ts`/`command`, réponse `entries_received` : la forme de `SessionRecording.StreamCommandEntries` et de `StreamAck`) et `GET /recorder/v1/sessions/{id}/commands`. Public : `GET /sessions/{id}/recording` (`docs/api/rest/openapi.yaml`, déjà documenté), routé par la Gateway — qui ne transmet que `page`/`pageSize` du client et y accole les rôles du jeton **vérifié**, jamais ceux que le client enverrait.

**Décisions, et pourquoi**
- **Ajout seul.** `domain.CommandRepository` n'a ni mise à jour ni suppression, et le service n'expose aucun endpoint qui en fasse : un enregistrement est une preuve.
- **Pas de FK vers `sessions`** (même raison que le Session Broker : une base par service ne peut pas poser de clé étrangère inter-services). Effet voulu : supprimer une session ne détruit plus son enregistrement, contrairement au `ON DELETE CASCADE` du DDL de référence (`docs/architecture/data-architecture.md`).
- **Lecture : RBAC d'abord**, action `recording:session:read` sur `recording:session:{id}`, fermé par défaut si Authorization est injoignable. Le refus est identique que la session existe ou non, et une session sans entrée donne un enregistrement **vide en 200**, pas un 404 : l'API ne permet pas de sonder quels identifiants de session existent. Un test d'intégration le fige.
- **Lot tout ou rien.** Une entrée invalide (session vide, horodatage absent, commande vide) refuse le lot entier en 400, et l'insertion PostgreSQL est transactionnelle — vérifié en provoquant un échec réel au milieu d'un lot.
- **Normaliser plutôt que perdre.** Octets UTF-8 invalides remplacés, octets NUL retirés, commande trop longue tronquée à 8 Kio sur une frontière de caractère. À l'origine, PostgreSQL `TEXT` refusait NUL et l'UTF-8 invalide et un refus aurait fait perdre tout le lot ; depuis le chiffrement (voir plus bas) la commande est stockée en `BYTEA`, qui accepte tout — la normalisation reste utile pour que le replay ne contienne jamais d'octet qui casse les outils en aval, mais ce n'est plus elle qui protège le lot.
- **Un seul contrat de test, deux magasins.** `runRepositoryContract` tourne sur le magasin mémoire en permanence et sur PostgreSQL quand `TEST_DATABASE_URL` est défini : le magasin de test ne peut plus dériver du vrai en silence.

**Côté proxy** — `infrastructure.AsyncRecorder` : `Record` ne fait qu'enfiler (jamais d'attente réseau, car il est appelé depuis le relais d'une session vivante) ; un unique worker envoie par lots, dans l'ordre, avec trois tentatives. Si le recorder reste indisponible et que la file (1024) se remplit, les entrées sont **perdues, comptées et journalisées** (`RECORDING GAP`) — c'était le comportement du tap, qui n'est **plus** celui par défaut : depuis ADR-0008, `AsyncRecorder` n'est utilisé que sous `RECORDING_POLICY=best-effort` (voir « Enregistrer ou refuser »). À l'arrêt (SIGTERM/SIGINT), la file est vidée avant de sortir (5 s max) pour ne pas perdre les dernières commandes des sessions en cours. En `best-effort`, sans `RECORDER_URL`, le proxy retombe sur `StdoutRecorder` et le journalise au démarrage : *rien n'est enregistré pour replay* ; en `required` (défaut), il refuse de démarrer.

**Preuves.** `recording_flow_test.go` : **huit processus réels** (Authentication, Authorization, Session Broker, Vault, Audit, ssh-proxy, Command Recorder, Gateway). Un opérateur ouvre une vraie session SSH, tape comme un vrai terminal (Entrée = `\r`, mot de passe `sudo` tapé à un vrai prompt d'une cible qui désactive l'écho) ; un auditeur relit le replay par la Gateway. Vérifié : commandes dans l'ordre pour la bonne session, mot de passe `sudo` absent de la réponse brute, pagination, 403 pour un opérateur sans le rôle (y compris avec un `actorRoles` forgé dans l'URL), 401 sans jeton, vide-pas-404. **Contre-épreuve faite** : en désactivant volontairement le masquage des secrets dans le tap, ce test échoue — il affiche alors `correct-sudo-pw` en clair dans le replay. `TestPostgresFlow_RecordingSurvivesCommandRecorderProcessRestart` prouve la survie à un redémarrage du processus.

**Contrats** — `proto/recording/v1/recording.proto` et `docs/api/grpc/README.md` §6 gagnent `SessionRecordingQuery.GetCommandRecording` (même démarche que `VaultAccountAdmin` : le contrat avant le code) ; `docs/api/rest/openapi.yaml` : `GET /sessions/{id}/recording` gagne `page`/`pageSize`, 403, et `CommandRecording` gagne `page`/`pageSize`/`totalEntries`. Le résumé disait « d'une session terminée » ; le service sert la lecture pendant la session comme après, la description est corrigée en conséquence.

**Une erreur de mon commit précédent, trouvée en revalidant.** Le bloc YAML de `docs/api/rest/openapi.yaml` était **invalide** depuis 392c5ee : deux descriptions en texte brut contenant `: ` (« … rotate : 403 avant 404 »). Je ne l'avais pas fait parser. Corrigé (descriptions entre guillemets) et le bloc complet est maintenant parsé et contrôlé (13 chemins, 15 schémas, réponses 403/404 de rotate et DELETE, 404 ajouté sur `GET /vault/accounts/{id}`, qui n'était documenté qu'en 200).

### Chiffrement au repos des enregistrements

Le cahier des charges demande des sessions « Chiffrées ». Les commandes étaient stockées en `TEXT` dans PostgreSQL : quiconque lisait la base lisait les commandes de tous les opérateurs — y compris, voir limitation 2, des secrets passés en argument.

**Le schéma** (`envelope.go`, `postgres_store.go`, `migrations/001_init.sql`). Chiffrement enveloppe à deux niveaux : une clé de données (DEK) aléatoire de 256 bits **par session**, qui scelle chaque commande en AES-256-GCM (nonce aléatoire préfixé) ; la DEK n'est stockée que chiffrée par la KEK (`session_recording_keys.wrapped_dek`, avec `kek_id` pour une rotation future). Il n'y a plus de colonne `command` : `session_command_entries.command_sealed BYTEA`.
- **Pourquoi une DEK par session** : GCM avec nonces aléatoires de 96 bits n'est sûr que pour un nombre borné de messages par clé ; une clé par session garde chaque clé très loin de cette limite quel que soit le volume cumulé. Et détruire une seule `wrapped_dek` rend un enregistrement définitivement illisible sans toucher aux lignes — la base d'une politique de rétention (non construite).
- **Ce que le chiffrement lie** (AAD GCM) : chaque commande est liée à son `session_id` et à son horodatage (µs), la DEK enveloppée à sa session et à sa KEK. Déplacer une ligne vers une autre session, éditer son `ts` ou y glisser la clé d'une autre session fait **échouer la lecture** (erreur 500 sans contenu), jamais produire un replay différent mais valide. L'AAD de la DEK préfixe la longueur du `kek_id` : mon propre test a trouvé que `("a|b","c")` et `("a","b|c")` produisaient les mêmes octets — corrigé avant tout déploiement, donc sans migration.
- **Horodatages tronqués à la microseconde** dans le service *et* le magasin mémoire : la valeur qui a servi à sceller doit être celle que PostgreSQL rend à la lecture, sinon la lecture échoue — le même piège que le hash d'audit en nanosecondes (voir plus haut).
- **Fail-closed** : avec `DATABASE_URL`, le recorder exige `KMS_KEY_HEX` (64 hex) et refuse de démarrer sinon ou si la clé est mal formée. Contrairement au Vault, **aucun repli sur une clé aléatoire par processus** : ce repli est exactement le bug qui a déjà coûté cher (ce qui est scellé sous une clé aléatoire est illisible après redémarrage).
- **Concurrence** : deux lots pour une session neuve créent la DEK par `INSERT … ON CONFLICT DO NOTHING` puis relecture ; tous scellent sous la clé *stockée*, jamais sous une clé perdante. Un lot qui échoue ne laisse ni ligne ni clé (une seule transaction).
- **Base existante** : au démarrage, `NewPostgresStore` scelle les lignes en clair d'une base antérieure (verrou exclusif, par lots de 500, puis suppression de la colonne `command`). Idempotent ; une seconde instance qui démarre ensuite ne trouve rien à faire. Le verrou exclusif bloque les lectures/écritures pendant la conversion : acceptable une fois, à planifier sur une grosse table.

**Preuves.**
- `store_test.go` (PostgreSQL) : le même contrat que le magasin mémoire, chiffrement dans le chemin ; **SQL brut** montrant qu'aucun octet de commande n'est lisible, que deux commandes identiques donnent des octets différents, qu'il n'y a plus de colonne `command` ; une clé par session ; 8 écritures concurrentes sur une session neuve → une seule clé, huit entrées lisibles ; quatre altérations (octet de chiffré inversé, `ts` modifié, ligne déplacée, clé d'une autre session) → lecture refusée sans fuite ; mauvaise KEK → ne lit ni n'ajoute ; conversion d'une base préexistante dans un schéma isolé (lignes scellées, colonne supprimée, une clé par ancienne session, idempotence).
- `postgres_flow_test.go` : deux processus recorder réels avec la même KEK (un enregistrement écrit par l'un est relu par l'autre après redémarrage) ; SQL brut sans `CorrectHorseBatteryStaple` ni `mysql` ; un recorder démarré avec **une autre clé** répond 500 (sans contenu dans le corps) à la lecture comme à l'écriture, et le bon recorder reste intact ; le refus de démarrer sans clé et avec une clé de mauvaise longueur est testé sur le binaire réel, sans base (`TestCommandRecorderMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex`).
- **Contre-épreuves** : AAD de l'horodatage neutralisé → le test d'altération de `ts` échoue ; AAD de la session neutralisé → le test unitaire de liaison échoue ; AAD de la DEK sans session ou sans préfixe de longueur → `TestDEKAAD_IsBoundToSessionAndKEK` échoue ; chiffrement neutralisé (texte clair stocké) → le contrat PostgreSQL entier échoue. Deux de mes premières mutations ne prouvaient rien (l'une ne compilait pas, le motif `sed` de l'autre ne correspondait à rien et le test « passait ») : je les ai refaites jusqu'à les voir échouer. Détecteur de course : 3 passes propres.
- Un constat que le test d'altération rend visible : « ligne déplacée » et « clé échangée » sont aussi arrêtés par la séparation des DEK, pas seulement par l'AAD — deux protections indépendantes, donc ce test seul ne prouverait pas l'AAD de session ; c'est le test unitaire de liaison qui le fait.

**Ce que ce chiffrement ne fait PAS.**
- **La KEK est locale** (`LocalKEK`, `KMS_KEY_HEX`), pas un KMS/HSM : même statut que `LocalKMS` du Vault. Quiconque a la base *et* cette variable d'environnement lit tout. `KeyWrapper` est la couture où un vrai client remplace `LocalKEK`. Avec un vrai KMS, chaque lot/lecture coûtera un appel de déchiffrement de DEK (aujourd'hui local, donc négligeable) : à mesurer à ce moment-là. Pas d'outil de rotation de KEK (`kek_id` est stocké, rien ne re-chiffre les DEK).
- **Pas d'intégrité de la suite.** Chaque ligne est authentifiée seule ; un attaquant de la base peut **supprimer** des lignes ou les **réordonner** sans qu'on le détecte. L'audit a un chaînage par hash, pas les enregistrements.
- **Pas de recherche sur le chiffré.** Le cahier des charges veut une recherche par commande / plein texte : l'indexer (OpenSearch) demandera de déchiffrer puis d'indexer avec sa propre protection, ou un index aveugle — à décider, pas à découvrir.
- **Le transport est en mTLS par défaut depuis ADR-0010** (proxy → recorder → Authorization : TLS 1.3, certificats des deux côtés ; en clair seulement avec `INTERNAL_TLS=disabled`, développement), et le magasin **mémoire** (développement) ne chiffre rien.
- **Constat au passage, hors périmètre de ce commit :** le README et `docs/security/secrets-management.md` parlent de « chiffrement enveloppe » pour le Vault, mais `LocalKMS` scelle les secrets **directement** sous la KEK (un seul niveau) ; seul le Command Recorder a aujourd'hui une vraie DEK par objet. Je n'ai pas modifié le Vault ; soit on corrige le vocabulaire, soit on lui donne le même schéma.

### Ce que ce service ne fait PAS — à décider, pas à découvrir

1. **Le chiffrement au repos existe, mais il est partiel** (voir la section précédente) : KEK locale et non un vrai KMS, lignes non chaînées entre elles (suppression/réordonnancement par un attaquant de la base non détectés), pas de recherche possible sur le chiffré, rétention par destruction de clé non construite. (Le transport proxy → recorder est protégé depuis ADR-0010, voir ci-dessous.)
2. **Un secret peut rester dans le texte d'une commande.** Le masquage ne couvre que la saisie à un prompt (`sudo`, `su`, `ssh`…). Un secret passé en argument (`mysql -pXXXX`, `curl -H 'Authorization: …'`, `export TOKEN=…`) est enregistré tel quel. Le replay est donc une donnée sensible, et `recording:session:read` une permission privilégiée à n'accorder qu'à des auditeurs.
3. **~~L'écriture n'est pas authentifiée.~~ Refermé par ADR-0010** : `POST /recorder/v1/command-entries` n'accepte plus que l'identité `ssh-proxy` (certificat), et la lecture que `api-gateway`. Prouvé sur huit processus : un Broker ou l'outillage opérateur qui poste une entrée forgée reçoit 403 à la porte, et le replay ne contient rien de forgé. Reste vrai en `INTERNAL_TLS=disabled`.
4. **Enregistrer ou refuser ? — tranché : refuser** (ADR-0008, section suivante). Le « break-glass » (accès d'urgence, borné et audité) pour le jour où le recorder est indisponible et qu'un accès est vital a été décidé ensuite : ADR-0009, section « Break-glass » plus bas. Il est désactivé par défaut ; sans lui, personne n'accède aux cibles via le bastion pendant la panne.
5. **La lecture d'un replay n'est pas elle-même auditée** (pas d'événement `recording.read` vers l'Audit Service), et n'est contrôlée que par rôle — pas par propriété de la session.
6. **Capture au clavier, pas dans le shell** (voir la section du tap) : historique, complétion et déplacement du curseur ne sont pas reconstitués.

## `GET /vault/accounts` rapportait la page demandée, pas la page servie

Défaut de ma propre liste des comptes (ab64541), repéré en écrivant la pagination du Command Recorder : `ListAccounts` borne bien `page`/`pageSize` (page < 1 → 1 ; taille < 1 → 20 ; > 100 → 100), mais le handler HTTP répondait avec les valeurs **brutes de la requête**. Une requête sans paramètre était servie en page 1 de 20 et annonçait `page: 0, pageSize: 0`. Un client qui s'appuierait sur ces champs pour paginer aurait bouclé ou calculé n'importe quoi.

Prouvé avant de corriger (sous-test d'intégration qui échouait : `reported page 0 / size 0, want 1 / 20`), puis corrigé en exposant la règle (`application.ClampPage`) pour que le handler rapporte ce qui a réellement été servi — le Command Recorder a la même fonction et le même test dès le départ. Un test unitaire couvre les bornes (0, négatifs, 100 inclus, 101, 100000) et le sous-test d'intégration quatre formes de requête. Un test qui n'aurait vérifié que les `items` ne l'aurait jamais vu.

## Enregistrer ou refuser : une session qui ne peut pas être enregistrée n'a pas lieu (ADR-0008)

Décision de Bony Kiss (« Refuser les sessions non enregistrables »), implémentée de bout en bout. Avant : si le Command Recorder tombait, le proxy laissait la session continuer et perdait les entrées (comptées, journalisées) — un administrateur pouvait exécuter des commandes non journalisées pendant une panne, ou la provoquer. Maintenant, par défaut (`RECORDING_POLICY=required`) :

- **Admission.** Le proxy sonde `GET /readyz` du recorder, d'abord à `EstablishSession` (avant d'émettre le ticket), puis de nouveau à la connexion du client, **avant** de récupérer le credential à usage unique. Non prêt ⇒ `503 recording unavailable` (le Broker le relaie en `503`, pas en `409` ; la Gateway laisse passer le statut), `session.recording_unavailable` audité, scope Vault non consommé (le Broker l'a déjà émis : il reste en suspens jusqu'à son expiration, et la nouvelle tentative a été vérifiée de bout en bout).
- **Acquittement par commande.** `RequiredRecordingTap` : une ligne n'est transmise à la cible qu'une fois le lot acquitté (`RecordBatch`, tout ou rien). En cas d'échec, `Write` renvoie `(0, ErrRecordingUnavailable)` — c'est `io.TeeReader` qui propage ce `0` à `io.Copy`, donc aucun octet de la ligne n'atteint la cible —, le tap reste définitivement en échec, la session est terminée, l'opérateur reçoit un message explicite, `session.recording_lost` puis `session.terminate` sont audités.
- **Fermé par défaut, partout.** La valeur zéro de `RecordingConfig` est `required` (une configuration oubliée refuse tout) ; une politique inconnue est une erreur (`ParseRecordingPolicy`), jamais un repli ; un proxy `required` sans `RECORDER_URL` refuse de démarrer ; `best-effort` doit être demandé et est annoncé par un avertissement au démarrage.
- **`/readyz` du recorder** ne dit pas « le processus tourne » mais « une écriture pourrait réussir » : il ouvre une transaction (lib/pq envoie `BEGIN READ WRITE`, donc il suit le chemin d'écriture) et vérifie que la base est inscriptible (`writableOrError(readOnly, inRecovery)`) — un réplica ou une base basculée en lecture seule est « non prêt », sans que la cause soit exposée au client (journalisée seulement).
- **Nouvelles tentatives** (`SyncRecorder`) : 2 tentatives, 100 ms de délai, 3 s par tentative, **uniquement** sur erreur de connexion et `500`/`503` — cas où le recorder garantit n'avoir rien stocké. Il est en ajout seul, sans déduplication : `502`, `504`, délai dépassé et connexion coupée sont ambigus (l'écriture a pu aboutir) et ne sont pas rejoués. Un échec ambigu ne peut donc que **sur-enregistrer** une commande jamais exécutée — pas l'inverse.

**Preuves, à trois niveaux** (aucun n'est une simple vérification de compilation) :
1. `pkg/proxycore` (29 → 47 tests) : commande non acquittée jamais relayée, refus avant `Fetch` (le scope n'est pas brûlé), `recording_lost` distinct de `terminate`, valeur zéro fermée, politique inconnue rejetée, verrou non tenu pendant `RecordBatch`.
2. `sshcodec` : vrai protocole SSH à trois participants avec une cible qui note chaque ligne qu'elle reçoit — avec un recorder en panne, la commande **n'apparaît jamais** côté cible ; un proxy non configuré refuse toutes les sessions.
3. **Huit processus réels** (`record_or_refuse_test.go`), le recorder étant tué puis relancé sous un déploiement vivant : (1) recorder arrêté **en cours de session**, l'opérateur tape `cat /etc/shadow` ⇒ la cible, qui rapporte chaque ligne reçue, ne la reçoit **jamais**, l'opérateur est informé, `session.recording_lost` et la fin anormale sont audités ; (2) recorder arrêté puis `connect` ⇒ `503` à travers la Gateway et le Broker, `session.recording_unavailable` observé par un « audit spy » (le service d'audit n'a pas d'endpoint de lecture) ; (3) ticket obtenu recorder sain, recorder perdu, *puis* connexion ⇒ refusée à la porte (c'est la raison de la seconde admission) ; (4) recorder rétabli ⇒ la même session se connecte, s'exécute, et sa commande est lisible aussitôt (acquittée avant d'être exécutée), chaîne d'audit intacte. Un second test lance le vrai binaire `ssh-proxy` : sans `RECORDER_URL`, ou avec une politique inconnue, il refuse de démarrer ; seul `RECORDING_POLICY=best-effort` explicite le laisse démarrer.

**Contre-épreuves** (la preuve qu'un test peut échouer) : A) `Write` qui renvoie `len(p)` malgré l'échec ; B) enregistrement lancé en asynchrone ; C) admission après `Fetch` — chacun fait échouer le test visé. Sur le test à huit processus, forcer `best-effort` dans `main.go` fait échouer le test, qui affiche alors `out:cat /etc/shadow` (la commande a atteint la cible). Deux de mes mutations étaient invalides au départ (import inutilisé qui ne compilait pas ; motif `sed` qui ne correspondait à rien et laissait le test « passer » à tort) : refaites jusqu'à ce que le test échoue pour la bonne raison. Une assertion négative (« la commande n'arrive pas ») doit attendre un temps de stabilisation (`settle()`), sinon elle passe avant que la commande ait pu arriver — mon premier essai laissait passer la mutation A.

**Défauts trouvés en l'écrivant :**
- Le test de refus d'un proxy non configuré échouait (`client pty: EOF`) : le serveur fermait le canal avant que le client ait envoyé ses requêtes `pty`/`shell`. `tell()` attend maintenant (2 s max) la requête `shell` avant d'écrire le message de refus — appliqué aussi au message « cible injoignable ».
- Ma première hypothèse sur `/readyz` était fausse : `default_transaction_read_only=on` ne bloque pas les écritures de lib/pq (`BEGIN READ WRITE` l'emporte). La readiness est donc mesurée sur le chemin d'écriture lui-même, comparée à lui dans un test PostgreSQL, et la fonction de décision est testée à part.

**Ce que cette politique ne fait PAS :**
1. **Le recorder devient une dépendance de disponibilité de tout accès privilégié** — HA obligatoire (`docs/deployment/high-availability.md` : désormais Tier 0), et `/readyz` à superviser, pas `/healthz`.
2. **Pas de « break-glass » par défaut** : une procédure d'urgence existe (ADR-0009, section suivante) mais doit être activée, deux fois, et n'accorde que ce que son audit rend visible.
3. **Ne rend pas la capture exhaustive** : historique, complétion et déplacement du curseur ne sont pas reconstitués, et un secret dans les arguments d'une commande est enregistré tel quel (limites 2 et 6).
4. **Le mode `best-effort` peut dupliquer** : `AsyncRecorder` rejoue encore sur toute erreur, ambiguë ou non. La classification de `SyncRecorder` pourrait lui être appliquée ; non fait, car ce mode n'est pas destiné à la production.
5. **Un scope Vault reste en suspens** quand l'admission refuse après son émission par le Broker (jusqu'à expiration) — inoffensif (usage unique, jamais consommé), mais pas nettoyé.

## Break-glass : une dérogation d'urgence, bornée et auditée, à « enregistrer ou refuser » (ADR-0009)

Suite directe d'ADR-0008, que j'avais laissée en « reste à décider ». Quand le recorder tombe, plus personne ne peut ouvrir de session — y compris pour réparer ce qui a causé l'incident. ADR-0009 ajoute une issue d'urgence **qui ne retire qu'une chose : l'enregistrement acquitté d'une session**. Authentification, RBAC `session:create`, Vault, audit : rien d'autre ne change. J'ai marqué l'ADR « Accepté » sans validation préalable de Bony Kiss, à partir de « Go pour la prochaine étape » ; les choix ci-dessous sont les siens à renverser.

**Six verrous, tous nécessaires** (un seul manquant ⇒ session ordinaire, c'est-à-dire refusée) :
1. La demande dit explicitement `breakGlass: true` et porte une justification d'au moins 10 caractères (après `TrimSpace`, comptés en runes).
2. Une politique RBAC existe sur la ressource **distincte** `breakglass:account:{accountId}`. Découverte en le concevant : `Authorization.CheckAccess` ne regarde que le rôle et la ressource — l'action est **ignorée**. Un « droit `session:breakglass` » aurait donc été accordé à quiconque a déjà `session:create` sur le compte. D'où le choix d'une ressource à part, refusée par défaut même pour `platform-admin`.
3. Durée de 1 à `BREAKGLASS_MAX_MINUTES` (Broker). Absente ou `0` : désactivé. Un texte ou un négatif est fatal au démarrage — une faute de frappe ne doit pas ouvrir ni fermer la porte en silence.
4. Le proxy doit avoir `BREAKGLASS_ENABLED=true`, et seulement sous `RECORDING_POLICY=required` avec un `Sink` (l'`AsyncRecorder`) : le drapeau envoyé par le Broker est une demande, pas un ordre.
5. La dérogation ne sert que si le recorder n'est **pas** prêt à l'admission. Un recorder prêt ⇒ tap acquitté strict, aucun événement de dérogation. Elle ne dégrade jamais une session qui pouvait être enregistrée.
6. Audit **avant** le credential : `session.breakglass` est émis avant la récupération du scope Vault ; s'il ne peut pas être écrit, la session est refusée (la demande côté Broker, `session.breakglass_requested`, est elle aussi fail-closed). Une dérogation que personne ne peut voir n'est pas accordée.

Côté code : `proxycore.Admission` est une preuve à champs non exportés — seul `Listener.AdmitSession` peut en produire une, et `Serve` ne l'honore que si `For(meta.SessionID)` (une admission d'une autre session est ignorée). `Probe` est la version non engageante pour le plan de contrôle HTTP (elle audite un refus, pas une dérogation qu'elle accorderait : l'événement appartient au moment où elle sert). `RecordingConfig.NewTapFor(adm)` construit le tap qui va avec : acquittant, ou non bloquant pour une session dérogée. Désactiver `BREAKGLASS_MAX_MINUTES` au Broker agit **immédiatement**, même sur une session déjà accordée mais pas encore ouverte (`waiver := sess.BreakGlass && max > 0`).

**Découverte en chemin, qui dépasse le break-glass : le proxy ne coupait aucune session à son échéance.** Seul le Broker reflétait l'expiration, paresseusement, au prochain appel. Une session break-glass « de 20 minutes » aurait donc duré tant que l'opérateur gardait sa connexion ouverte. `Listener.Serve` lance maintenant `codec.Relay` sous `context.WithDeadline(ctx, meta.ExpiresAt)` **pour toutes les sessions** (zéro = sans limite) : à l'échéance, `session.expire` puis `session.terminate` (les deux `success = true` — une fin normale), l'opérateur lit « session ended because its time limit was reached », et l'audit comme la purge du credential s'exécutent sur le contexte **parent**, encore vivant. Une annulation de l'appelant, ou sa propre échéance, n'est pas une expiration.

**Preuves, à quatre niveaux, avec contre-épreuves :**
1. `pkg/proxycore` (47 → 65 tests) : ordre exact de l'audit (dérogation avant `Fetch`), refus si l'audit échoue, recorder prêt ⇒ aucune dérogation, admission d'une autre session ignorée, expiration distinguée d'une annulation, purge sur contexte vivant. **8 mutations tuées.**
2. `sshcodec` — vrai protocole SSH à trois participants, cible qui note chaque ligne reçue (+6 tests) : une session dérogée vit recorder arrêté et ses commandes atteignent la cible ; une session ordinaire au même moment est refusée. **4 mutations tuées.**
3. Session Broker (+10 tests) : chaque verrou testé isolément, audit fail-closed, extinction immédiate. **10 mutations tuées.**
4. PostgreSQL : aller-retour de `break_glass`, et **mise à niveau en place** d'une table `sessions` créée avant cette colonne (`ALTER TABLE … ADD COLUMN IF NOT EXISTS` dans le même `InitSQL` idempotent).
5. **Huit processus réels** (`breakglass_flow_test.go`) : recorder tué sous un déploiement vivant, session dérogée admise, `session.breakglass` observé **avant** l'accès au credential par un « audit spy », session ordinaire simultanée refusée en `503`, coupure à l'échéance faite par le proxy ; plus un test que le Broker refuse de démarrer sur une limite illisible. **5 mutations + 1 tuées.**

**Une erreur de ma part, rattrapée.** En préparant une mutation, j'ai sauvegardé deux `main.go` différents (ssh-proxy puis session-broker) sous le même nom de sauvegarde : la seconde copie a écrasé la première, et la restauration a remplacé `ssh-proxy/cmd/ssh-proxy/main.go` par la mauvaise version. Détecté par la compilation, restauré depuis `git HEAD`, puis mes modifications réappliquées ; les mutations E2–E5 ont été refaites avec des sauvegardes aux noms uniques, et le test à huit processus relancé. Leçon : une sauvegarde par fichier **et** par mutation, jamais par nom de fichier seul.

**Ce que ce mécanisme ne fait PAS :**
1. **~~Pas de double validation : une seule personne suffit.~~ Refermé par défaut par ADR-0011** (section suivante) : une demande break-glass attend désormais l'accord d'une *autre* personne. Reste vrai avec `BREAKGLASS_APPROVAL=disabled`. Il n'y a toujours **pas de revue obligatoire après incident**.
2. **~~Le drapeau `break_glass` circule du Broker au proxy sur un canal interne non authentifié.~~ Refermé par ADR-0010** : `establish-session` n'accepte que l'identité du Session Broker (un Vault ou un Gateway qui l'appelle avec `break_glass: true` est refusé à la porte, testé sur processus réels). Reste vrai en `INTERNAL_TLS=disabled`, où seuls les verrous 4, 5 et 6, locaux au proxy, protègent.
3. **La convention `breakglass:account:*` est la seule frontière** entre politique ordinaire et politique d'urgence : un motif trop large l'accorde partout. Un contrôle automatique du motif est à décider.
4. **Une session dérogée peut n'être que partiellement enregistrée**, voire l'être en double : `AsyncRecorder` rejoue sur toute erreur. Assumé — c'est le prix d'une session qui ne bloque jamais sur le recorder.
5. **L'enregistrement après coup n'est pas reconstitué** : une commande perdue pendant la panne est perdue ; l'audit dit seulement que la dérogation a servi.

## mTLS interne : l'identité de l'appelant vient du certificat (ADR-0010)

Trois décisions antérieures (ADR-0003, ADR-0009, le recorder) reposaient sur « le mTLS interne, qui viendra ». Je l'ai fait maintenant, et pas comme un simple chiffrement du transport : la question de fond était *qui décide qu'un appelant a le droit d'appeler cette route* — et la réponse est le service lui-même, à partir du certificat. J'ai marqué ADR-0010 « Accepté » sans validation préalable de Bony Kiss, à partir de « Continuer » ; les choix ci-dessous sont les siens à renverser.

**Ce qui est livré.**
- `pkg/mtls` (stdlib seulement) : identité = unique SAN URI `spiffe://<domaine>/<service>` ; `Credentials` (relecture à chaud, échange atomique, refus d'un remplacement invalide) ; `Guard` (table `{méthode, chemin|préfixe, appelants}`, première règle gagnante, **aucune règle = 403**, table mal formée = panique au démarrage, chemin non canonique = 400) ; `Setup(service)` ; `Client(peers…)` qui épingle l'identité de chaque pair ; `pki` et `openbastion-pki` (`init`, `issue`, `all`) ; `mtlstest`.
- Les sept services qui reçoivent des appels de services, chacun avec `internal/interfaces/callers.go` et `callers_test.go` (le Gateway n'a pas de table : son listener est public) ; les cinq qui appellent d'autres services (Gateway, Broker, proxy SSH, Vault, recorder) le font par un client épinglé à l'identité de chaque pair. L'identité `admin-cli` (outillage opérateur) n'ouvre que `POST /auth/v1/users` et `GET /audit/v1/verify-chain`.
- Vault : `fetch-credential` déduit le proxy du certificat ; `calling_proxy_id` est facultatif et une discordance est un 403 qui **ne brûle pas** le jeton.
- `make pki` ; `make run-*` sous mTLS par défaut ou `INTERNAL_TLS=disabled`.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Requis par défaut**, `INTERNAL_TLS=disabled` à demander par son nom (avertissement). Conséquence : *tous* les tests d'intégration existants tournent désormais avec `INTERNAL_TLS=disabled` stipulé dans `buildEnv` — ils prouvent la logique, pas le transport. Le transport a ses trois tests.
2. **Les listes d'appelants sont dans le code, pas dans la configuration.** Une règle ne s'élargit pas par erreur de configuration ; en échange, changer la topologie est une livraison.
3. **Le listener public du Gateway reste en HTTP** (TLS à l'arête) ; le Gateway n'a une identité que pour ses appels sortants.
4. **Pas de CRL/OCSP** : certificats courts, et remplacement de l'autorité (testé, y compris l'ordre qui ne bloque personne : un service refuse de retirer l'autorité qui a signé son propre certificat).
5. **`PROXY_SERVICE_ID` est refusé sous mTLS** s'il diffère de `ssh-proxy` : l'identité du proxy est son certificat.
6. **Le mesh Envoy de `docs/architecture/system-overview.md` n'est pas remplacé ni exclu** : un sidecar qui termine le mTLS ferait du service un récepteur de connexions locales, qui ne saurait plus qui appelle — l'ADR dit pourquoi et comment SPIRE s'y raccorde.

**Preuves.** Tests de `pkg/mtls` (38 fonctions sur trois paquets, 20 mutations tuées au niveau unitaire) ; une table de règles testée par service (`callers_test.go` : qui peut appeler chaque route, et qu'une route inconnue est refusée à tous) ; trois tests d'intégration sur processus réels (`mtls_flow_test.go`, `mtls_lifecycle_test.go`) : (a) le parcours complet — création d'utilisateurs par `admin-cli`, puis uniquement la Gateway : politiques, compte, session, SSH interactif, replay relu par un auditeur — sous `INTERNAL_TLS=required` ; (b) **vingt-quatre appels forgés par une identité valide mais fausse** (vingt à l'origine, quatre ajoutés par ADR-0011), tous arrêtés à la porte avec le corps reconnaissable `forbidden` (et non par l'autorisation du service), puis la preuve que rien n'a eu lieu (pas de politique, pas de commande dans le replay, pas d'utilisateur) et le contrôle inverse que les appelants légitimes passent ; sans certificat, autre autorité, autre domaine, expiré : aucune poignée de main ; un jeton de scope volé est refusé à quatre autres identités, une revendication de corps contredisant le certificat est refusée **sans** brûler le jeton, puis le proxy le rachète ; un Broker dont l'adresse du Vault mène à un imposteur (certificat valide, mauvaise identité) n'envoie rien — l'imposteur compte zéro requête — et l'erreur dit `answered as "command-recorder", expected "password-vault"` ; (c) rotation d'un certificat, certificat d'une autre autorité refusé, certificat d'un autre service refusé, autorité ajoutée au bundle puis ancienne retirée, le tout sur un processus qui garde son PID ; (d) refus de démarrer : sans certificat, `INTERNAL_TLS` mal orthographié, certificat d'un autre service, expiré, autre domaine, `PROXY_SERVICE_ID` divergent. **Sept mutations au niveau intégration, toutes tuées** (serveur sans certificat client exigé, garde qui laisse passer une route sans règle, client sans épinglage d'identité, rotation qui garde l'ancien bundle, rechargement qui accepte une autre identité, démarrage qui accepte le certificat d'un autre service, Vault qui ignore le certificat).

**Une chose que j'ai vue en chemin et laissée telle quelle.** Le Gateway recopie le corps des erreurs de ses amonts (`io.Copy(w, resp.Body)`). Un échec de connexion interne montre donc à l'utilisateur, par exemple, `resolving account: Get "https://127.0.0.1:44663/…": mtls: … answered as "command-recorder", expected "password-vault"` — une adresse interne et un nom d'identité. C'était déjà vrai avec des erreurs de connexion en clair ; le mTLS y ajoute un texte plus bavard. À traiter à part (réponses génériques côté Gateway).

**Ce que cela ne fait PAS :**
1. **Les événements d'audit ne sont pas attribués par l'identité du certificat** : `actor_id` reste déclaratif sur `emit-event`, dont seuls le Broker et le proxy sont appelants autorisés.
2. **Un service compromis fait tout ce que sa table autorise** : le Gateway affirme les rôles des utilisateurs, donc un Gateway compromis agit en leur nom (RBAC d'Authorization comme limite).
3. **Le certificat est une dépendance de disponibilité de rang 1** : expiré = panne (`docs/deployment/high-availability.md` §4). Le service journalise l'approche (20 % restants) et l'échéance, mais rien ne surveille les fichiers d'un service qui ne tourne plus.
4. **Sondes kubelet** : elles ne présentent pas de certificat client ; `tcpSocket` ou un port de santé distinct (non fait).
5. **Le transport reste du HTTP/JSON** (pas de gRPC dans ce sandbox) ; la même garde se transposera en intercepteur.
6. **`INTERNAL_TLS=disabled` garde toutes les faiblesses antérieures.**
7. **Dans ce sandbox, rien ne tourne sur un vrai cluster** : les certificats sont ceux de `openbastion-pki`, générés par test ; l'émission par cert-manager/SPIRE n'a pas été exercée.

## Break-glass : la double validation (ADR-0011)

Suite directe d'ADR-0009, dont la première limite était « une seule personne suffit ». ADR-0011 la ferme : une demande break-glass n'ouvre plus rien, elle **attend** (`pending_approval`) qu'une **autre** personne l'approuve. J'ai marqué l'ADR « Accepté » sans validation préalable de Bony Kiss, à partir de « Go sur la prochaine étape, la double validation du break-glass » ; les choix ci-dessous sont les siens à renverser. C'est dans le Session Broker, pas un nouveau service : le Workflow Service du v0.0.1 reprendra l'idée avec des chaînes d'approbation, celle-ci ne contient qu'un décideur.

**Ce qui est livré.**
- `POST /sessions` avec `breakGlass: true` passe les verrous 1 à 3 d'ADR-0009, écrit `session.breakglass_requested` (fail-closed), puis enregistre la session `pending_approval` avec une échéance de décision (`BREAKGLASS_APPROVAL_WINDOW_MINUTES`, 15 par défaut, 1 à 1440). Pas de `session.create` : rien n'a été accordé.
- `POST /sessions/{id}/approve` et `/reject`. Le décideur doit détenir la ressource RBAC `breakglass-approve:account:{id}` — un préfixe **volontairement différent** de `breakglass:` : `Authorization.CheckAccess` ne compare que rôle et ressource, avec un `*` final comme seul joker, donc un motif `*` ou `breakglass*` accorderait les deux droits d'un coup (documenté, pas empêché).
- **Pas d'auto-approbation, par identifiant d'utilisateur et non par rôle** : celui qui a demandé ne décide pas, même avec les deux rôles. Un rejet exige la même autorité mais pas une autre personne (le demandeur peut retirer sa demande).
- **Qui décide vient du Gateway** : `decidedBy` et `actorRoles` sont ceux du jeton vérifié, le corps du client est jeté. Les routes `/sessions/...` du Gateway sont devenues une **liste blanche** : une route ajoutée plus tard au Broker n'est plus relayée telle quelle, avec le corps du client, par défaut.
- **La décision est auditée avant d'agir** (fail-closed), puis appliquée par un *compare-and-swap* atomique (`SaveIfStatus`, en mémoire sous verrou et en PostgreSQL par `UPDATE … WHERE status = $7`) : une seule décision par demande, y compris entre deux répliques du Broker.
- **La durée court à partir de l'approbation**, pas de la demande (`DurationMinutes` conservé). L'approbation revérifie **les règles du jour** : break-glass toujours activé, durée toujours sous la limite.
- **Seul le demandeur peut `connect`**, pour toutes les sessions (le Gateway injecte `callerId`) : sans cela, l'approbateur aurait pu ouvrir l'accès qu'il vient d'accorder. Le waiver n'est transmis au proxy que si la demande est approuvée (`DecidedBy != ""`).
- Config : `BREAKGLASS_APPROVAL=required|disabled` (valeur inconnue = fatale au démarrage ; `disabled` est annoncé au démarrage comme un mode faible). Le **zéro-valeur du service est strict**.
- Codes : 200 / 403 (pas l'autorité, ou auto-approbation) / 404 / 409 (déjà décidée, périmée, plus activée, au-dessus de la limite) / 503 (corps générique, la cause seulement dans le journal du Broker).

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Requis par défaut — cela change le comportement d'ADR-0009.** `BREAKGLASS_APPROVAL=disabled` le restaure ; les anciens tests break-glass tournent dans ce mode, ceux de l'approbation en mode strict.
2. **Fenêtre de décision de 15 minutes par défaut** : une urgence qui attend plus longtemps que ça n'attend plus.
3. **Un seul approbateur**, pas de quorum.
4. **Le demandeur peut rejeter sa propre demande** s'il a l'autorité d'approuver (il la retire).
5. **`connect` réservé au demandeur, pour toutes les sessions** — pas seulement le break-glass.
6. **Implémenté dans le Broker**, pas dans un nouveau service.
7. **404 pour une session inconnue**, y compris pour qui n'a pas l'autorité : l'existence d'une session n'est pas secrète pour un utilisateur authentifié du bastion, contrairement à celle d'un compte.

**Preuves.** Quatre niveaux. (1) Session Broker, application : 19 tests (verrous un à un, auto-approbation par rôle et par identifiant, audit fail-closed, expiration de la demande en attente, horloge qui démarre à l'approbation, règles du jour revérifiées, propriété du `connect`, waiver sans approbation), avec une horloge injectée. (2) Magasins : 2 tests en mémoire et 4 PostgreSQL — dont **six décisions concurrentes (cinq approbations et un rejet, sur des connexions distinctes), répétées sur 10 tours, dont une seule gagne à chaque tour** (50 tours en mémoire), la mise à niveau en place d'une base d'avant (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`), et la preuve que `Save` ne peut pas réécrire un décideur. (3) HTTP : 4 tests du Broker et 5 du Gateway (identité du jeton et non du corps, liste blanche, 401 sans jeton). (4) **Huit processus réels** (`breakglass_approval_test.go`, ports 18711–18719) : recorder tué, demande, tentative d'auto-approbation refusée, approbation par une autre personne, `connect` par l'approbateur refusé, `connect` par le demandeur accepté, sessions break-glass sans approbation toujours refusées, journal d'audit relu avec les acteurs ; plus deux tests de configuration (valeur illisible = refus de démarrer, mode annoncé). Le test mTLS passe de 20 à **24 appels forgés** (approve/reject par une identité fausse, connect avec `callerId` forgé).

**25 mutations, 25 tuées** (sauvegardes uniques par fichier et par mutation, restauration vérifiée par `cmp`) : auto-approbation permise, politique d'approbation ignorée, politique de demande acceptée à la place, échec d'audit ignoré, pas de compare-and-swap, horloge démarrée à la demande, demande en attente qui n'expire jamais, pas de propriété du `connect`, waiver sans approbation, défaut faible, contrôles d'activation / de limite / d'état sautés, échéance de décision, compare-and-swap mémoire et PostgreSQL qui ignorent le statut, `Save` PostgreSQL qui réécrit le décideur, fuite de la cause dans un 503, règle d'appelant élargie, Gateway qui relaie le corps du client ou une route inconnue, défaut faible dans `main`, fenêtre à 0 acceptée, `BREAKGLASS_APPROVAL` inconnu toléré. **Une survivante, rattrapée** : sauter le contrôle « break-glass activé » à l'approbation passait inaperçu parce que le contrôle de la limite le couvrait ; le test vérifie maintenant que le refus dit « not enabled ».

**Ce que cela ne fait PAS :**
1. **~~Personne n'est prévenu~~ — refermé par ADR-0012** (section suivante) : liste des demandes en attente et webhook. Les limites propres à ces deux mécanismes y sont consignées.
2. **Une même personne avec deux comptes** s'approuve elle-même ; seule l'identité par utilisateur est comparée.
3. **Pas de revue obligatoire après incident.**
4. ~~**L'expiration d'une demande en attente n'est pas auditée** (elle est reflétée paresseusement au prochain appel).~~ **Levé par ADR-0034** : le Broker la marque `expired` en base et écrit `session.expire`.
5. **Une course perdue peut laisser un événement d'approbation sans effet** : l'audit est écrit avant le compare-and-swap, donc deux approbateurs simultanés produisent deux événements `session.breakglass` pour une seule décision effective. Le choix (fail-closed) l'emporte sur la propreté du journal.
6. **`terminate` n'est pas réservé au demandeur** : n'importe quel utilisateur authentifié peut encore terminer une session par son identifiant. Non traité ici.
7. **Le Gateway recopie toujours le corps des erreurs de ses amonts** (déjà signalé en ADR-0010).
8. **Avec `INTERNAL_TLS=disabled`**, un appelant interne qui forge `decidedBy` n'est pas arrêté à la porte.

## Break-glass : découvrir les demandes en attente, et en être prévenu (ADR-0012)

Suite directe d'ADR-0011, dont la première limite était « personne n'est prévenu » : une double validation que l'approbateur ne peut pas trouver est inutilisable à l'heure où elle compte. J'ai marqué l'ADR « Accepté » sur la réponse de Bony Kiss à ma proposition (« Oui, tu as raison. Tu peux poursuivre »), sans validation plus détaillée : c'est une décision de conception que l'on peut renverser.

**Ce qui est livré.**
- `GET /sessions?status=pending_approval` (Gateway → Broker) : les demandes que l'appelant peut **approuver maintenant** — en attente, non périmées, pas les siennes, compte couvert par sa politique `breakglass-approve:account:{id}`, break-glass encore actif, durée dans la limite du jour. Aucune autorité : liste **vide** en 200, jamais 403 (la liste n'est pas un oracle). Autre statut ou statut absent : 400.
- **Le Gateway reconstruit la requête** : seuls `status`, `page`, `pageSize` viennent du client ; `callerId` et `actorRoles` sont ceux du jeton vérifié.
- **Une question à l'Authorization Service par compte distinct**, jamais par demande ; si l'une échoue, 503 générique — **jamais de liste partielle**. Lecture bornée à 100 demandes (`MaxPendingScanned`), `truncated: true` si l'on a coupé ; pagination sur la liste filtrée.
- Port `ApprovalNotifier` (sans valeur de retour) et adaptateur webhook, `BREAKGLASS_NOTIFY_URL` : `breakglass.requested` / `approved` / `rejected`, émis seulement **après coup** (demande enregistrée, comparaison-échange gagnée). Asynchrone, sans nouvelle tentative, 5 s, 16 envois simultanés. Le message nomme session, compte, demandeur, décideur, durée, échéance — **ni justification ni rien de la cible** (la structure n'a pas ce champ ; un test par réflexion le fige).
- **L'URL du webhook est un secret** : seul son schéma et son hôte sont écrits dans le journal ; les erreurs de transport sont purgées de l'URL ; https exigé (http seulement vers une boucle locale) ; identifiants dans l'URL, absence d'hôte, autre schéma, URL illisible : fatal au démarrage, sans répéter l'URL ; redirections non suivies.
- **Verrou supplémentaire** : l'identifiant de compte d'une demande break-glass doit être un identifiant (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`) — `targetAccountId` est de la saisie qui finit dans la liste et dans un canal de chat ; et le texte du webhook n'en reproduit que `[A-Za-z0-9._:-]`, 64 caractères au plus.
- `ListPending` dans les deux magasins (mémoire, PostgreSQL), index partiel idempotent `sessions_pending_approval_idx` (une base antérieure le reçoit au démarrage) ; au démarrage, le Broker annonce où il notifie, ou « no notification channel ».

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **La liste montre ce que l'appelant peut décider, pas ce qui existe** : un administrateur sans politique `breakglass-approve:` ne voit rien. Le contraire (voir toutes les demandes) révélerait quels comptes sont sensibles, qui les demande et pourquoi.
2. **Vide plutôt que 403** pour qui n'a aucune autorité.
3. **Un seul statut servi** : le reste de `GET /sessions` de `docs/api/rest/openapi.yaml` (« les siennes », « toutes pour un administrateur ») exige un modèle de visibilité que le RBAC sans sujet ne sait pas exprimer ; pas inventé ici.
4. **Prévenir est au mieux** (pas de retry, pas de file) : l'urgence ne dépend pas d'une messagerie ; la liste est le filet.
5. **Un port et un webhook, pas un Notification Service** (v0.0.1).
6. **La justification ne part pas dans le canal.**
7. **Les bornes** : 100 demandes lues, 5 s, 16 envois simultanés.
8. **Le verrou sur l'identifiant de compte** peut refuser un identifiant légitime qui contiendrait un caractère hors `[A-Za-z0-9._:-]` ; les identifiants que génère le Vault n'en contiennent pas.

**Preuves.** Quatre niveaux, mesurés : Session Broker, application : +19 tests (autorité, jamais les siennes, jamais une ligne qui n'est pas break-glass, règles du jour, fail-closed, une question par compte, bornes, événements de notification et leur absence sur une décision perdue, identifiant de compte) ; magasins : +16 (contrat de `ListPending` sur mémoire et PostgreSQL — dont le bord exact de l'échéance, l'ordre et le départage, la borne et `more` —, 10 tests du webhook sur serveurs réels : message, assainissement, retour immédiat, requête terminée, panne / refus / redirection / lenteur sans fuite de l'URL, bornage des envois, URL acceptées et refusées) ; HTTP du Broker : +6 ; Gateway : +4 (identité du jeton et non du client, rôles encodés, corps relayé nul) ; intégration : +4 sur **processus réels** (l'approbateur trouve la demande, le canal est prévenu ; puis le webhook refuse, bloque, disparaît sans que la demande ni la décision en souffrent ; refus de démarrer sur une URL inutilisable sans la répéter ; annonce du canal) ; mTLS : 24 → **27 appels forgés** refusés à la porte, plus un témoin.

**69 mutations, 69 tuées** (sauvegardes uniques par mutation, restauration vérifiée par `cmp`) : autorité de la liste ignorée, ses propres demandes incluses, ligne non break-glass incluse, limite de durée ignorée, lecture malgré break-glass coupé, une question par demande au lieu d'une par compte, compte muet sauté, erreur du magasin avalée, drapeau `truncated` perdu (page pleine et page au-delà), décalage de page, page 0 non bornée, appelant anonyme accepté, mauvaise ressource ou aucun rôle interrogés, chaque événement de notification, annoncé avant l'enregistrement, après une course perdue, avec le mauvais type ou sans décideur, mauvaise échéance, identifiant de compte non contrôlé (trois formes) ; magasins (mémoire et PostgreSQL : statut, expiration, bord de l'échéance, ordre, départage, borne, `more`, ligne en trop) ; webhook (redirection suivie, URL dans le journal d'une erreur ou d'un refus, envoi synchrone, annulation de la requête propagée, envois non bornés, http partout, identifiants acceptés, `Where` complet, texte non assaini ou non borné, URL illisible répétée, pas de délai, refus silencieux) ; HTTP du Broker (statut, rôles non séparés, appelant ignoré, cause dans le 503, `null` au lieu de `[]`, page non bornée, `truncated`, cause non journalisée) ; Gateway (`callerId`/`actorRoles` du client honorés, requête entière relayée, rôles non encodés, corps relayé, rôles vides) ; `main` (URL inutilisable non fatale, URL complète annoncée, annonce absente, notifieur jamais branché). **Ce que ces séries ont trouvé** : aucune défense manquante, mais **quatre mutants mal formés** (trois ne compilaient pas ; un « survivait » parce qu'il plantait le processus sur un pointeur nul, ce qui satisfaisait le test pour une mauvaise raison — réécrits) et **un test qui se bloquait au lieu d'échouer** (le serveur de test attendait des gestionnaires que le test n'avait pas libérés ; il échoue maintenant vite, avec un message). Côté méthode : un script lancé à la main avait été coupé par le délai de l'outil en laissant une mutation dans un fichier (détectée par `cmp` contre la sauvegarde, restaurée avant toute chose) ; le harnais borne désormais chaque mutation à 60 s et restaure sur SIGTERM.

**Ce que cela ne fait PAS :**
1. **Aucune nouvelle tentative** : une notification perdue est perdue ; la liste est le filet. Un réplica qui tombe entre l'enregistrement et l'envoi perd aussi la sienne.
2. **Un seul canal, sans routage par personne** : le Broker ne connaît pas les approbateurs ; les membres du canal apprennent qu'une demande existe, pour quel compte et de qui, sans avoir forcément le droit de l'approuver.
3. **Le message n'est pas signé** : l'URL est le seul secret que le destinataire ait. Une signature HMAC est possible sans changer le contrat ; elle n'est pas faite. — **fermé par ADR-0013** (signature optionnelle, voir plus bas).
4. **Pas de plafond de demandes en attente par demandeur** : qui détient `session:create` et `breakglass:` sur un compte peut noyer la liste et le canal. La borne de 100 est signalée (`truncated`), pas empêchée. — **fermé par ADR-0013** (plafond par demandeur, voir plus bas).
5. **Au-delà de 100 demandes en attente, les plus lointaines ne sont pas atteignables par la liste** (pas de curseur) tant que les premières ne sont pas décidées ou périmées : la liste dit qu'elle a coupé, elle ne permet pas d'aller plus loin.
6. **L'expiration d'une demande n'émet aucune notification** (pas de Scheduler ; ~~elle n'est pas non plus auditée, déjà consigné~~ — auditée depuis ADR-0034, toujours pas notifiée).
7. **Rien n'a été essayé contre un vrai Slack, Teams ou Mattermost** : les tests parlent à un récepteur local ; la clé `text` est la convention des webhooks entrants de type Slack, pas une compatibilité vérifiée.
8. **Les rôles voyagent séparés par des virgules** dans la chaîne de requête (comme pour le Vault et le Recorder) : un nom de rôle qui contient une virgule serait lu comme deux rôles.
9. **Avec `INTERNAL_TLS=disabled`**, un appelant interne peut écrire `callerId` et `actorRoles`.
10. **L'ajout au `.proto` (`ListPendingApprovals`) n'a pas été compilé** : `protoc` et `buf` ne sont pas disponibles dans ce sandbox ; le transport reste du HTTP/JSON.

## Break-glass : un plafond de demandes en attente par demandeur, et un webhook que l'on peut vérifier (ADR-0013)

Suite directe d'ADR-0012, dont deux des limites étaient « pas de plafond de demandes en attente par demandeur » et « message non signé ». J'ai marqué l'ADR « Accepté » sur la réponse de Bony Kiss à ma proposition (« Poursuis sur la prochaine étape »), sans validation plus détaillée : c'est une décision de conception que l'on peut renverser.

**Ce qui est livré.**
- **Un plafond par demandeur** : au plus `BREAKGLASS_MAX_PENDING_PER_REQUESTER` demandes break-glass en attente et non échues (défaut **3**, de 1 à 100). Au-delà : `429` (le corps dit le plafond), la demande est enregistrée `denied`, auditée (`session.breakglass_requested`, `success=false`), non notifiée, absente de la liste. Il ne s'applique que si l'approbation est requise : sans approbation rien n'attend, et le Broker ne compte même pas.
- **Atomique, y compris entre réplicas** : `SaveIfUnderPendingLimit` compte et enregistre en une opération — un seul verrou en mémoire ; en PostgreSQL une transaction sous `pg_advisory_xact_lock(0x0B7A, hashtext(requested_by))` (le demandeur se sérialise, pas la table). Une pré-vérification `CountPending` vient avant, **après** le contrôle de l'Authorization Service (seul qui a l'autorité de demander apprend qu'un plafond existe) : c'est elle qui rend le refus courant exact et audité avant toute écriture. La demande qui perd la course pour la dernière place laisse un second événement `session.breakglass_requested` avec `success=false` pour la même session (le dernier décide) et une ligne `denied`.
- **Fail-closed** : un décompte impossible est un `503` générique (la cause n'est que dans le journal du Broker), jamais une demande acceptée « au cas où » et jamais présenté comme un plafond atteint.
- **Webhook signé, si l'on veut** : `BREAKGLASS_NOTIFY_SECRET` (32 octets au moins, utilisé tel quel) ajoute `X-OpenBastion-Timestamp` (secondes Unix, à l'envoi) et `X-OpenBastion-Signature: v1=<hex HMAC-SHA256(secret, horodatage "." corps exact)>`. Un secret sans `BREAKGLASS_NOTIFY_URL`, ou trop court, est fatal au démarrage ; il n'est jamais journalisé ni répété dans une erreur ; le Broker annonce « signed » ou « not signed » et « at most N waiting ».
- Aucune migration : les index existants servent le décompte.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Par demandeur, ni global ni par compte** : un plafond global ou par compte serait une arme — n'importe quel détenteur de `session:create` et `breakglass:` remplirait la file et empêcherait les autres de demander, en pleine urgence.
2. **Défaut 3, bornes 1 à 100, pas de valeur « illimité »**, valeur invalide fatale (une faute de frappe ne désactive pas la protection).
3. **`429`**, pas `403` ni `409` : le client doit pouvoir distinguer « pas le droit » de « trop de demandes en attente ».
4. **Une demande à son échéance exacte compte encore** (`expires_at >= now`) : la demande est décidable jusqu'à cet instant.
5. **Un seul secret**, sans chevauchement de rotation ; HMAC-SHA256 ; préfixe de version `v1=` pour pouvoir changer d'algorithme sans casser les récepteurs.
6. **Pas d'identifiant de livraison ni de nouvelle tentative** : la liste reste le filet (ADR-0012).

**Preuves.** Tests nouveaux, comptés par fichier : Session Broker application +13 (plafond par défaut, par demandeur, libération par décision / rejet / échéance, bord exact de l'échéance, réglage et valeurs nulles ou négatives, pas sans approbation — y compris des demandes laissées par un mode plus strict et un décompte en panne —, seul qui peut demander l'apprend, fail-closed, décompte périmé, 40 goroutines × 20 tours) ; magasins +6 (contrat de `CountPending` et de `SaveIfUnderPendingLimit` sur mémoire et PostgreSQL, course de 40 demandes sur mémoire, sur PostgreSQL, et sur **deux pools de connexions** = deux réplicas) ; signature +6 (le récepteur du test est écrit **d'après la description du contrat**, pas d'après le notifier, avec ses contre-épreuves : corps altéré d'un bit, autre secret, horodatage changé, hors tolérance des deux côtés ; secret absent de la livraison et du journal par chaque voie d'échec ; corps hostile) ; Broker HTTP +3 ; Gateway +1 (le `429` et son motif sont relayés tels quels) ; intégration +2 sur processus réels (rafale de 12 demandes d'un même demandeur sur cinq processus avec un plafond de 2 : une acceptée, onze refusées et auditées, une décision libère une place, signature vérifiée par un récepteur indépendant, secret absent du journal du Broker ; plafond ou secret invalide : le Broker s'arrête et ce qu'il annonce est vrai). L'extrait Python de `docs/administration/` a été exécuté contre une vraie livraison du notifier : elle se vérifie, et corps altéré, autre secret, horodatage périmé et horodatage illisible sont refusés.

**63 mutations, 63 tuées** (sauvegardes uniques par mutation, restauration vérifiée par `cmp`) : plafond ignoré, ou d'une place de trop (service, mémoire, PostgreSQL), plafond infini, défaut changé ou nul, quota appliqué sans approbation, demandé avant l'autorité, décompte en panne accepté ou présenté comme plafond atteint, décompte de personne, du mauvais statut, des demandes échues, de l'échéance exacte (deux sens), enregistrement sans le plafond atomique, verrou retiré ou posé par demande, transaction jamais validée, refus qui écrit quand même, course perdante non auditée / acceptée / non conservée `denied` / annoncée, 429 devenu 403 (service et Gateway), motif du 429 supprimé, 503 qui montre sa cause ou qui n'est pas journalisée, limite invalide non fatale ou hors bornes, secret sans canal ou trop court non fatal, annonce fausse, secret jamais donné au notifier ou annoncé, signature absente / horodatage absent ou non signé / séparateur / corps / clé / version / millisecondes / horloge non injectée, secret minimal refusé ou d'un octet accepté, secret conservé ou répété dans l'erreur ou dans le journal. **Honnêteté sur la première passe** : sur 33 mutants, 26 ont été tués d'emblée ; six étaient mal écrits (indentation, import inutilisé : corrigés et rejoués) et **un a vraiment survécu** — « le plafond s'applique sans approbation » : sans approbation rien n'attend, le décompte vaut toujours 0 et mon test ne pouvait pas le distinguer. Deux tests de plus l'ont tué (demandes laissées par un mode plus strict ; décompte en panne).

**Ce que cela ne fait PAS :**
1. **K identités × N places** : le plafond est par demandeur ; K identités qui détiennent les deux politiques occupent K × N places de la liste.
2. **Un demandeur au plafond ne peut plus rien demander pendant la fenêtre d'approbation** (15 minutes par défaut) : un jeton volé permet de remplir la file de son titulaire et de l'empêcher de demander. C'est le prix d'un plafond par demandeur.
3. **Deux comptes, deux plafonds** : la règle compte des identifiants, pas des humains (comme pour la double validation).
4. **Les tentatives refusées ne sont pas limitées en débit** : chacune écrit une ligne `denied` et un événement d'audit. Le plafond borne ce qui attend, pas ce qui est refusé.
5. **Un seul secret de signature, sans chevauchement de rotation** : changer le secret est une coupure brève à coordonner des deux côtés.
6. **Pas d'identifiant de livraison, pas d'anti-rejeu dans la tolérance du récepteur** : une livraison interceptée peut être rejouée pendant cette fenêtre. La signature ne chiffre rien.
7. **Slack, Teams et Mattermost ignorent ces en-têtes** : avec eux, l'URL reste le seul secret.
8. **Aucun récepteur tiers réel n'a été essayé** : le récepteur des tests est écrit d'après la description du contrat, et l'extrait Python du guide a été vérifié contre une livraison réelle — pas contre un produit.
9. **Le stockage en mémoire n'est pas partagé** : son plafond est celui d'un processus (il ne convient pas à plusieurs Brokers).

## Une limitation de débit par identité sur `POST /sessions`, et un limiteur du Gateway aux unités et à la mémoire justes (ADR-0014)

Suite directe d'ADR-0013, dont la limite n° 4 était « les tentatives refusées ne sont pas limitées en débit ». J'ai proposé cette étape en fin d'incrément précédent ; Bony Kiss a répondu « Go pour la prochaine étape » puis « Continuer » : l'ADR est marqué « Accepté » sur ces réponses, sans validation plus détaillée — c'est une décision de conception que l'on peut renverser.

**Ce qui a été mesuré avant d'écrire quoi que ce soit** (en lisant le limiteur existant du Gateway pour y adosser le nouveau) : trois défauts qui n'étaient pas des hypothèses.
1. **Les unités mentent.** Le second paramètre de `NewRateLimiter` est le temps pour accumuler *un* jeton. `(60, time.Minute)` était une rafale de 60 puis un jeton par minute — 10 requêtes acceptées sur 10 minutes de requêtes régulières — et non « 60 par minute » comme l'écrivait `main.go`. Le login, `(5, time.Minute)`, était déjà une rafale de 5 puis une par minute, **plus strict** que son commentaire.
2. **Rien n'était évincé.** 100 000 clés distinctes laissaient près de 98 000 seaux en mémoire, toujours là 48 heures plus tard ; sur `/auth/login`, public et dont la clé est l'IP, c'est une fuite de mémoire à la portée d'un attaquant.
3. **La clé est l'adresse du pair TCP**, qui est celle de Traefik pour tout le monde : un seul seau partagé par tous les utilisateurs.

**Ce qui est livré.**
- **Un budget par utilisateur vérifié sur `POST /sessions`** : `SESSION_REQUEST_BURST` (défaut **10**, de 1 à 1000) puis `SESSION_REQUEST_RATE_PER_MINUTE` (défaut **6**, de 1 à 600), clé = le `UserID` issu de la vérification du jeton (jamais l'adresse, jamais le corps). Chaque tentative coûte un jeton, **avant** la lecture du corps. Une demande refusée ici n'atteint pas le Broker : ni ligne `sessions`, ni événement d'audit.
- **`429` avec un `Retry-After` vrai** (secondes, arrondies au-dessus, au moins 1), message distinct de celui du plafond du Broker (« too many session requests from this user … » contre « too many break-glass requests are waiting … »). Les trois limiteurs du Gateway (login, requêtes authentifiées, sessions) disent maintenant la vérité sur `Retry-After`.
- **Une ligne de journal par utilisateur et par épisode de refus**, jamais une par requête, jamais le jeton. Rien dans l'audit (le Gateway n'est pas un émetteur autorisé, ADR-0010).
- **Le limiteur réparé sans être affaibli** : les seaux inactifs depuis assez longtemps pour être pleins sont évincés (un seau plein équivaut à un seau neuf : aucune décision ne change) ; les requêtes authentifiées reçoivent les unités que le commentaire promettait (60 par minute soutenu) ; le login **garde** sa rafale de 5 puis une par minute, et c'est le commentaire qu'on corrige.
- Défauts stricts, pas d'« illimité », valeur invalide fatale en nommant la variable, annonce au démarrage. Aucun changement du Broker ni du schéma.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Par utilisateur, ni global ni par adresse** : un budget global serait une arme (un utilisateur le viderait pour que les autres soient refusés, y compris en urgence) ; l'adresse est la même pour tous derrière Traefik.
2. **Les tentatives comptent, pas les succès** : le Gateway ne sait pas ce que le Broker refusera, et une limite qui ne compte que les refus laisse écrire autant de succès qu'on veut.
3. **Défauts 10 puis 6 par minute** : choisis, pas déduits d'un usage mesuré ; réglables de 1 à 1000 / 1 à 600.
4. **Le journal, pas l'audit, pour les refus de débit** : un événement par refus recréerait le flux d'écritures que la limite borne.
5. **Le limiteur du login n'est pas relâché** pour ressembler à son commentaire ; **les requêtes authentifiées le sont en pratique** (60 par minute au lieu de « 60 puis une par minute ») : c'est ce que la documentation disait, ce n'est pas ce que le code faisait.
6. **Par processus**, pas d'état partagé (Redis) pour l'instant.

**Preuves.** Tests nouveaux : Gateway application +7 (3 → 10 : les unités sous leur nom, `Retry-After` vrai et arrondi au-dessus, un épisode annoncé une fois, défauts stricts et unités de la minute ; 3 d'éviction dont une **propriété** qui compare le limiteur à une référence qui n'évince jamais, 11 configurations × 5 graines × 20 000 opérations, choisies pour tomber sur la frontière flottante — par exemple capacité 1 et recharge de 13 ms donnent 0,9999999999999999 à l'instant « plein », d'où la marge d'éviction) ; Gateway interfaces +9 (25 → 34 : rafale puis refus et Broker jamais atteint par les refusés, par utilisateur et non par adresse ni par corps, chaque tentative comptée avant la lecture du corps, `Retry-After` vrai et reformation du jeton, seule `POST /sessions` est facturée, défaut strict et `nil` garde le défaut, une ligne de journal par épisode et jamais le jeton, le `429` propre du Broker relayé sans `Retry-After`, login et requêtes authentifiées disent la vérité) ; intégration +4 (29 → 33, sur processus réels : un utilisateur sans droit ne fait pas écrire au Broker plus que son budget ; 60 par minute et non une par minute après la rafale ; le login est une rafale de 5 puis une par minute ; une limite invalide arrête le Gateway et ce qui est annoncé au démarrage est vrai). `breakglass_quota_test.go` relève le budget par l'environnement (`SESSION_REQUEST_BURST=100`, `SESSION_REQUEST_RATE_PER_MINUTE=600`) : il envoie des rafales exprès.

**50 mutations, 50 tuées** (sauvegardes uniques par mutation, restauration vérifiée par `cmp`, `-timeout 60s`) : clé prise sur l'adresse ou sur le corps, contrôle après la lecture du corps, refusés qui atteignent quand même le Broker, tentative non comptée, bornes ou défauts changés, « illimité » accepté, valeur invalide tolérée, unités du limiteur rétablies à l'envers, `Retry-After` absent, tronqué ou faux, message confondu avec celui du Broker, ligne de journal par requête ou avec le jeton, éviction trop précoce (un seau encore vide effacé), éviction sans marge, éviction qui ne libère jamais, login relâché, épisode jamais refermé. Une de ces 50 (éviction immédiate de tout ce qui est inactif) est tuée par un **dépassement de délai** (un test attend un état qui ne revient jamais), pas par une assertion : elle est détectée, la preuve est plus brute. Deux autres n'ont d'abord pas compilé (import devenu inutile) et ont été réécrites ; elles et le survivant ci-dessous ont été rejouées après coup. Un survivant au premier passage (éviction sans marge) a conduit à choisir des configurations qui tombent sur la frontière flottante, puis à les ajouter à la propriété.

**Ce que cela ne fait PAS :**
1. **Seul `POST /sessions` a un budget par identité.** `approve`, `reject`, `connect`, `terminate` et la liste des demandes en attente ne dépendent que de la limite par adresse. *(Traité ensuite par ADR-0016 pour `approve`, `reject` et `connect`, puis par ADR-0017 pour `terminate` ; les lectures restent hors budget, par choix motivé.)*
2. **La limite par adresse reste fausse derrière Traefik** : tous les utilisateurs partagent le seau de l'adresse de l'arête — 60 requêtes authentifiées par minute pour **toute la plateforme** avec les unités corrigées, et une rafale de login de 5 qu'un seul peut épuiser pour tous. Corriger demande de décider à qui faire confiance pour `X-Forwarded-For` (une confiance mal placée permet de forger sa clé) : décision **non prise**, consignée.
3. **Un jeton volé peut priver son titulaire de son budget** (un jeton se reforme toutes les 10 secondes avec les défauts ; il va à qui arrive le premier) ; le remède est de révoquer le jeton.
4. **Les refus de débit ne sont pas dans l'audit**, seulement dans le journal du Gateway.
5. **K identités compromises, K budgets ; par processus, N réplicas donnent N fois le budget** ; un redémarrage rend un seau neuf.
6. **Les valeurs par défaut n'ont pas été éprouvées sur un usage réel.**

## Qui est « le client » derrière l'arête : `X-Forwarded-For` limité aux proxys déclarés, et des limites par adresse réglables (ADR-0015)

Suite directe d'ADR-0014, dont la première limite écrite était « la limite par adresse reste fausse derrière Traefik ». Bony Kiss a répondu « Go pour la prochaine étape » à ma proposition ; l'ADR est marqué « Accepté » sur cette réponse, sans validation plus détaillée — c'est une décision de conception que l'on peut renverser.

**Ce qui a été constaté avant de concevoir.** Le Gateway clé deux limiteurs (login, requêtes authentifiées) sur l'hôte de `RemoteAddr`, qui derrière Traefik est le même pour tout le monde (un seul seau pour la plateforme, et une rafale de login qu'un seul utilisateur épuise pour tous). Lire `X-Forwarded-For` est l'évidence, et c'est un piège : l'en-tête est écrit par qui l'envoie, et un limiteur qui prend la première valeur donne à l'attaquant une clé neuve à chaque requête — il **supprime** la protection contre la force brute qu'il devait fournir. Le dépôt n'a aucun fichier de déploiement Traefik (`deploy/*` est vide) : la règle vit dans le Gateway et dans les guides.

**Ce qui est livré.**
- **La confiance se déclare** : `TRUSTED_PROXY_CIDRS` (adresses ou CIDR, séparés par des virgules). Absente : **personne**, la clé est l'adresse du pair, comme avant (annoncé au démarrage).
- **`X-Forwarded-For` n'est lu que si le pair TCP immédiat est déclaré, de droite à gauche**, et on s'arrête à la première adresse qui n'est pas un proxy. La partie gauche, celle que le client écrit, n'est jamais lue tant qu'un élément non fiable à sa droite l'arrête. **Au moindre doute la clé est celle du pair** (en-tête absent, élément illisible, plus de 32 sauts, tout est proxy) : jamais une valeur choisie par le client.
- **Clés normalisées** : IPv4 écrite en IPv6 → IPv4 ; IPv6 → son **/64** (un abonné en possède 2⁶⁴) ; port, crochets et zone retirés.
- **Une configuration douteuse empêche de démarrer** (variable et entrée nommées) : entrée vide, ni adresse ni CIDR, **bits d'hôte non nuls** (`192.168.1.5/24`), et **tout réseau de longueur 0** — y compris sous la forme `::ffff:0.0.0.0/96`, qui aurait contourné un contrôle naïf de `0.0.0.0/0`. Pas de valeur « tout le monde ».
- **Les limites par adresse sont réglables** : `CLIENT_LOGIN_BURST` (5, de 1 à 100), `CLIENT_LOGIN_RATE_PER_MINUTE` (1, de 1 à 60), `CLIENT_REQUEST_BURST` (60, de 1 à 10000), `CLIENT_REQUEST_RATE_PER_MINUTE` (60, de 1 à 6000). Les défauts sont ce que le code faisait déjà : **rien n'est relâché** tant qu'on ne le demande pas par son nom. Pas d'« illimité » ; valeur invalide fatale en nommant la variable ; annonce au démarrage.
- Aucun changement des réponses, du schéma ni des autres services.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Défaut : personne n'est de confiance.** Tant que l'opérateur n'a rien réglé, rien ne change — le problème reste entier et seule la ligne du démarrage le dit. Un défaut qui ferait confiance aux réseaux privés ferait confiance à tout pod du cluster.
2. **Adresse la plus à droite non fiable**, pas « la première » ni « N sauts depuis la droite » : le premier est forgeable, le second fait confiance à une position et se casse en silence quand la chaîne change de longueur.
3. **/64 pour l'IPv6**, non réglable.
4. **Les refus par adresse ne sont pas journalisés ligne à ligne** : la clé d'adresse tourne librement pour qui a beaucoup d'adresses, une ligne par épisode deviendrait une ligne par requête (contrairement au budget par utilisateur d'ADR-0014, dont la clé est une identité authentifiée). Ils sont dans le journal d'accès de l'arête.
5. **Seul `X-Forwarded-For`** est lu (ni `X-Real-IP` ni `Forwarded`).
6. **Bornes** 100 / 60 / 10000 / 6000, choisies, non déduites d'un usage.

**Preuves.** Tests nouveaux : Gateway application +8 (10 → 18 : sans confiance l'en-tête n'est jamais lu, y compris pour `nil` ; depuis un proxy déclaré, le client est la première adresse qui n'en est pas un — y compris plusieurs lignes d'en-tête, ports, crochets ; depuis un pair non déclaré l'en-tête est ignoré, avec les bornes exactes des réseaux ; tout doute retombe sur le pair, bornes de 32 sauts comprises et un en-tête de 100 000 éléments ; clés normalisées, zone, IPv4-mappée ; configuration acceptée ; **23 formes douteuses refusées** ; défauts des limiteurs = ce qu'ils ont toujours fait) ; Gateway interfaces +5 (34 → 39 : chaque client a son seau derrière un proxy déclaré, et pas sans lui — le défaut mesuré en ADR-0014 —, deux adresses d'un même /64 sont un client, rien ne se forge ni depuis un pair non déclaré ni à gauche de l'adresse du proxy, plusieurs lignes d'en-tête, le budget de `POST /sessions` reste celui de l'utilisateur, un Gateway construit à la main ne fait confiance à personne et `nil` ne fait pas oublier ce qui était déclaré) ; intégration +4 (33 → 37, sur processus réels, **dont un attaquant qui se connecte depuis `127.0.0.2` en écrivant l'adresse d'un autre** : il épuise sa propre rafale, pas celle du propriétaire de l'adresse, qui passe par le proxy ; configuration douteuse qui arrête le Gateway ; annonce du démarrage vraie ; limites réglées qui s'appliquent, avec des valeurs différentes des défauts).

**66 mutations, 65 détectées et 1 équivalente** (sauvegardes uniques par mutation, restauration vérifiée par `cmp`, `-timeout 60s`) : première adresse de l'en-tête prise pour le client, en-tête lu de n'importe quel pair, jamais lu, élément illisible sauté, bornes de sauts décalées ou absentes, lignes lues dans le désordre ou une seule, IPv6 en adresse complète ou en /56 ou /72, IPv4-mappée non ramenée, réseau de longueur 0 accepté (aussi sous sa forme mappée), bits d'hôte acceptés, entrée vide sautée, zone acceptée, défauts et bornes changés (huit constantes), un limiteur qui emprunte les défauts d'un autre, taux « par seconde », limiteur du login ou des requêtes facturé sur `RemoteAddr`, en-tête non transmis ou autre en-tête lu, câblage de la configuration (rafale et débit de chaque limiteur, bornes, minimum, annonce du démarrage). **Cinq survivantes à la première passe** : quatre étaient de vraies lacunes (la lecture de plusieurs lignes d'en-tête n'était testée ni quand la dernière ligne n'est faite que de proxys ni au niveau HTTP ; une adresse de pair écrite sans port n'était testée que pour l'IPv4, où le résultat est le même ; un réglage de débit était testé **avec sa valeur par défaut**, donc non discriminant) — comblées puis rejouées ; la cinquième (« une confiance `nil` répond oui ») est **équivalente** : tous les éléments sont alors sautés et la clé reste celle du pair, c'est observablement le même résultat.

**Ce que cela ne fait PAS :**
1. **Traefik n'a pas été essayé.** Les tests jouent le proxy ; le réglage `forwardedHeaders` de l'arête est un prérequis documenté, non vérifié. L'algorithme est choisi pour ne pas en dépendre (que le proxy écrase l'en-tête ou y ajoute son pair, la clé est la même), mais cela reste à voir sur un vrai déploiement.
2. **Rien ne change tant que l'opérateur ne règle pas `TRUSTED_PROXY_CIDRS`.**
3. **La confiance est celle de l'opérateur** : un réseau trop large laisse tout hôte qu'il contient choisir sa clé (seule la longueur 0 est refusée) ; un proxy qui n'ajoute pas l'adresse qu'il voit rend l'en-tête forgeable à travers lui.
4. **Une adresse n'est pas une personne** : un NAT partage un seau ; qui possède beaucoup d'adresses a beaucoup de seaux — **une force brute distribuée n'est pas bornée**, et aucune limite par compte n'est ajoutée.
5. **Par processus** : N réplicas, N fois le budget ; un redémarrage rend un seau neuf.
6. **Les refus par adresse ne sont ni audités ni journalisés par le Gateway.**
7. **Le protocole PROXY** n'a pas été essayé ; **les défauts et bornes n'ont pas été éprouvés sur un usage réel**.

## Un budget par identité sur les actions de session qui écrivent à chaque appel : `approve`, `reject`, `connect` (ADR-0016)

Suite directe d'ADR-0014, qui avait consigné « seul `POST /sessions` est couvert » ; j'avais proposé d'étendre le budget à `approve`, `reject`, `connect`, `terminate` et à la liste des demandes en attente. Bony Kiss a répondu « Go pour la prochaine étape » puis « Continuer » ; l'ADR est marqué « Accepté » sur ces réponses, sans validation plus détaillée — c'est une décision de conception que l'on peut renverser. **Elle n'étend pas tout ce que j'avais proposé** : la mesure a montré que deux des cinq routes n'en ont pas besoin, et je l'ai dit avant de coder.

**Ce qui a été mesuré avant de décider** (lecture du Broker, puis preuve sur processus réels) :
- `approve` et `reject` : un refus « qui dit quelque chose de l'appelant » écrit un **événement d'audit à chaque tentative**, après un appel à l'Authorization Service. Témoin sur cinq processus réels, **sans budget** : 6 approbations refusées + 6 rejets refusés = **12 événements d'audit**.
- `connect` : pour le demandeur d'une session active, un scope du Vault, un ticket du proxy et un événement d'audit **à chaque appel**. Pour un autre appelant : un refus sans écriture.
- `terminate` : une écriture **une fois** par session. Les lectures (`GET /sessions/{id}`, l'enregistrement, la liste des demandes en attente) : **aucune écriture** ; la liste coûte un appel à l'Authorization Service par compte distinct en attente.
- L'attaquant réaliste n'est pas « n'importe qui » : un refus de création ne révèle pas l'identifiant de la session, il faut en détenir une. C'est un titulaire de jeton qui a un droit — un compte compromis.

**Ce qui est livré.**
- **Le budget suit le coût** : `approve`, `reject`, `connect`. Pas `terminate` (jusqu'à ADR-0017), pas les lectures.
- **Un seul seau par utilisateur pour les trois routes**, **distinct** de celui de `POST /sessions` : changer de route ne donne pas de budget neuf ; et avoir trop demandé ne fait pas perdre le droit de se connecter à une session accordée, en urgence surtout.
- **Clé = l'identité vérifiée** (jamais l'adresse ni le corps), compte pris **avant** que le Broker soit appelé : une action refusée par le budget n'atteint ni le Broker, ni le Vault, ni le proxy, et n'écrit **rien**. Un `405` ou un `404` ne coûte rien.
- `SESSION_ACTION_BURST` (défaut **10**, de 1 à 1000) et `SESSION_ACTION_RATE_PER_MINUTE` (défaut **6**, de 1 à 600) ; pas d'« illimité » ; valeur invalide fatale en nommant la variable ; un Gateway construit à la main applique les défauts ; annonce au démarrage sur sa propre ligne (« approve, reject, connect, terminate: at most N at once per user … »).
- **`429` avec un `Retry-After` vrai**, message distinct (« too many session actions from this user … ») ; **une ligne de journal par utilisateur et par épisode**, jamais le jeton ; rien dans l'audit. Aucun changement du Broker ni du schéma.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **`terminate` et les lectures ne sont pas couverts** (`terminate` l'est depuis ADR-0017, qui le fait écrire à chaque appel) : ils n'écrivent pas à chaque appel ; les limiter freinerait des interfaces qui interrogent l'état. À reconsidérer si une mesure montre une charge de lecture sur l'Authorization Service.
2. **Un seau pour les trois routes**, et non un par route (changer de route donnerait un budget neuf) ni un partagé avec `POST /sessions`.
3. **Mêmes défauts que `POST /sessions` (10 puis 6 par minute)**, choisis, **non mesurés sur un usage réel**.
4. **Le jeton est pris avant de savoir ce que le Broker dira** : un `connect` d'un autre utilisateur, qui ne ferait aucune écriture, coûte quand même un jeton. C'est le prix d'un compte fait avant tout travail.
5. **Les refus du budget ne sont pas audités** (un événement par refus recréerait le flux d'écritures borné) : ils sont dans le journal du Gateway.

**Preuves.** Tests nouveaux : Gateway application +1 (18 → 19 : défauts, bornes et unités du limiteur d'actions) ; Gateway interfaces +9 (39 → 48 : rafale puis refus pour chacune des trois routes avec le Broker qui ne voit jamais les refusés ; un seul seau pour les trois ; distinct du budget de `POST /sessions` **dans les deux sens** ; par utilisateur et non par adresse ni par session ; seules les trois routes sont comptées — `DELETE`, lectures, `405`, `404` ne le sont pas ; `Retry-After` vrai et seau qui se reforme ; Gateway construit à la main strict et `nil` qui ne le désactive pas ; une ligne de journal par épisode, qui nomme son budget, sans jeton ; la réponse du Broker relayée telle quelle) ; intégration +2 (37 → 39, sur processus réels : **le témoin sans budget** — 12 événements d'audit pour 12 refus — puis, avec une rafale de 3, **8 approbations ne laissent que 3 événements** et les 5 autres sont des `429` ; `reject` et `connect` refusés ensuite par le même seau sans atteindre le Broker ; un autre utilisateur a son propre seau, et son `connect` est compté comme les autres (`[403 403 403 429]`) ; lectures, liste et `terminate` non ralentis ; avec `SESSION_ACTION_RATE_PER_MINUTE=60`, `Retry-After` vaut 1 et attendre 1,15 s suffit ; limites invalides fatales ; annonce du démarrage vraie, et **chaque budget se règle sans déplacer l'autre**).

Un test existant a dû changer : les vérifications de l'annonce du démarrage du budget de `POST /sessions` cherchaient « at most 10 » dans toute la sortie, et la nouvelle ligne contient le même libellé : elles nomment maintenant leur ligne (« POST /sessions: at most … »). Aucun autre test d'intégration n'a été gêné par le budget : la suite complète passe sans relever aucune variable.

**44 mutations, 43 détectées et 1 équivalente** (sauvegardes uniques par mutation, restauration vérifiée par `cmp`, `-timeout 60s`) : défauts et maxima changés, budget d'actions qui emprunte les défauts du login, `terminate`, lecture d'une session, liste, enregistrement comptés à tort, `connect` / `approve` comptés avant la méthode (un `405` coûterait) ou **après** la réponse du Broker (les refus écriraient), un seau par route, un seau pour tout le monde, clé = nom d'utilisateur ou session, budget de `POST /sessions` partagé dans un sens ou dans l'autre, libellé, `Retry-After` décalé ou absent, statut 503, une ligne de journal par refus, jeton dans le journal, burst du mauvais budget dans le message, Gateway construit à la main laxiste, `nil` qui remplace le budget, setter sans effet, câblage de la configuration (rafale et débit, minimum, maximum, variable du budget voisin lue à la place, annonce permutée ou sans les noms de routes). **Une seule passe, aucune survivante à corriger, sauf une équivalente** : « le budget d'actions emprunte les défauts de `POST /sessions` » (A6) : les valeurs sont identiques aujourd'hui, aucun test ne peut distinguer les deux jeux de constantes. Que cette passe n'ait rien trouvé ne prouve pas l'absence de lacune : les mutations sont celles que j'ai imaginées, après avoir écrit les tests.

**Ce que cela ne fait PAS :**
1. ~~`terminate` n'a toujours ni contrôle d'appartenance ni politique propre~~ — **levé par ADR-0017** (voir la section suivante) ; le budget n'y changeait rien, et `terminate` rejoint maintenant ce seau.
2. **Les lectures ne sont pas limitées par identité** : seule la limite par adresse les borne ; la liste peut coûter un appel à l'Authorization Service par compte distinct en attente.
3. **En urgence, un jeton volé pèse plus** : qui détient celui d'un approbateur ou d'un demandeur peut épuiser son budget d'actions pendant l'incident. Le remède est de révoquer le jeton.
4. **Un utilisateur légitime très actif est ralenti** : plus de 10 actions d'un coup ou 6 par minute en continu, toutes sessions confondues. Les valeurs ne sont pas mesurées sur un usage réel.
5. **Par processus** : N réplicas, N fois le budget ; un redémarrage rend un seau neuf.
6. **Les refus du budget ne sont pas dans l'audit**, seulement dans le journal du Gateway.

## Mettre fin à une session : son demandeur ou une autorité déclarée, et au nom de celui qui le demande (ADR-0017)

Suite de la limite consignée par ADR-0014 et ADR-0016 (« `terminate` n'a ni contrôle d'appartenance ni politique propre »). Bony Kiss a répondu « Go pour la prochaine étape » puis « Continuer » à ma proposition ; l'ADR est marqué « Accepté » sur ces réponses, sans validation plus détaillée — le choix des règles ci-dessous est le mien et peut être renversé.

**Ce qui a été mesuré avant de décider** (lecture du code, puis test d'attaque sur processus réels, **rouge avant le correctif**) :
- Le Gateway relayait `DELETE /sessions/{id}` sans dire qui appelait ; `TerminateSession(ctx, id)` ne recevait aucun appelant. Bob (rôle `sre`, aucune politique) terminait la session d'Alice : **`200`**. Une session inconnue donnait **`409`**, pas `404`.
- L'événement d'audit `session.terminate` avait pour auteur `sess.RequestedBy` : la trace disait que le **demandeur** avait mis fin à sa session, même quand quelqu'un d'autre l'avait fait.
- Ce que `terminate` fait vraiment : il change l'enregistrement du Broker, donc empêche un **futur** `connect`. Le proxy n'expose que `establish-session` : **pas de route de révocation** — une connexion SSH déjà ouverte et un ticket déjà émis ne sont pas coupés avant leur expiration.
- `GET /sessions/{id}` renvoie n'importe quelle session (demandeur, compte, justification) à tout jeton valide (sondé avec un rôle `nobody` : `200`) — **non corrigé ici ; traité par ADR-0019** (section plus bas).

**Ce qui est livré.**
- **Qui** : le demandeur, toujours et sans politique ; ou une politique sur `session-terminate:account:{accountId}` (refusée par défaut ; préfixe distinct de `vault:`, `breakglass:`, `breakglass-approve:`). Approuver une urgence n'est pas terminer une session ; `platform-admin` n'y suffit pas.
- **Au nom de qui** : le Gateway construit `{callerId, actorRoles}` à partir du jeton vérifié, le corps du client est écarté ; sans `callerId`, `403`.
- **Ordre** : session (`404`) → appelant (`403`, quel que soit l'état) → état (`409`) ; Authorization injoignable : `503`, rien n'est terminé.
- **Audit** : l'acteur est l'appelant ; refus = `session.terminate` en échec sous son nom ; succès après l'action, au mieux ; `404`/`409` n'écrivent rien. Passage à `terminated` par comparaison-échange (`SaveIfStatus` depuis `active`).
- **Budget** : `DELETE` rejoint le seau d'actions d'ADR-0016, avant le Broker, après la vérification de la méthode ; la lecture reste gratuite. Annonce au démarrage : « approve, reject, connect, terminate: at most N … one budget for the four ».
- Aucun changement de schéma ni de proto (`TerminateSessionRequest` portait déjà `RequestContext`).

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Le demandeur peut toujours terminer sa session, sans politique** ; pour les autres, une politique **déclarée** (pas de rôle en dur).
2. **Une ressource à part** (`session-terminate:account:`), plutôt que de réutiliser `breakglass-approve:` : deux pouvoirs distincts.
3. **`403` pour un appelant sans droit, quel que soit l'état** de la session (il n'apprend rien de l'état) ; `404` seulement si la session n'existe pas.
4. **Le succès est audité après l'action, au mieux** : un audit en panne ne garde pas une session ouverte (c'est l'inverse d'un octroi, ADR-0011) — mais un refus reste audité.
5. **`terminate` rejoint le budget d'actions** : ses refus écrivent maintenant un événement d'audit à chaque tentative, donc il écrit à chaque appel.
6. **Aucune politique n'est créée par défaut** : après cette étape, seul le demandeur peut terminer tant que l'opérateur n'a pas écrit `session-terminate:account:…`.

**Preuves.** Tests nouveaux : Broker application +12 (71 → 83 : demandeur sans politique et sans appel à Authorization, refus audité sous le nom de l'appelant, autorité qui termine et que l'audit nomme, les autres politiques ne sont pas celle-ci, sans appelant, session inconnue, appelant avant état, session expirée, Authorization en panne, audit en panne, base en panne, course perdue) ; Broker interfaces +4 (19 → 23 : le corps du Gateway et rien d'autre, codes et qui peut, `503` sans la cause **et cause dans le journal**, Authorization interrogée avec les rôles du corps, la ressource du compte et l'action) ; Gateway interfaces +6 (48 → 54 : le Broker reçoit qui demande et avec quels rôles, pas le client ; sans jeton rien n'atteint le Broker ; un seul seau ; `Retry-After` vrai ; seau propre à l'utilisateur ; lecture et mauvaise méthode gratuites ; l'ancien test « seules les routes qui écrivent sont comptées » a été renommé) ; intégration +1 (39 → 40 : huit sous-tests sur processus réels, dont corps forgé, approbateur sans politique de terminaison, autre compte, double terminaison, refus jusqu'au budget : `[403 403 429 429 429 429]` et **2** événements d'audit).

Tests existants qui ont dû changer, par construction : la signature de `TerminateSession` (appels des tests du Broker), le test qui affirmait que `DELETE` n'est **pas** compté (renommé, `DELETE` retiré de la liste des routes gratuites), `brokerTerminateSession` de l'intégration (envoie `{callerId, actorRoles}` comme le Gateway) et le sous-test d'intégration d'ADR-0016 sur `DELETE` (attend maintenant `429`).

**53 mutations, toutes détectées** (sauvegardes uniques, restauration vérifiée par `cmp`, `-timeout 60s`) : appelant absent accepté, demandeur interrogé quand même, Authorization jamais interrogée, rôles perdus, ressource d'un autre pouvoir (`vault:`, `breakglass-approve:`, `breakglass:`), ressource `*` ou la session au lieu du compte, Authorization injoignable qui laisse passer ou qui devient un refus, état avant appelant, session inconnue en `409`, base en panne en `404`, session expirée vue active, session non active terminée, acteur de l'audit = demandeur (succès et refus), refus non audité ou audité comme un succès, succès non audité ou audité comme un échec, audit en panne qui refuse, événement émis avant la comparaison-échange, noms d'événements changés, comparaison-échange remplacée par une écriture simple, mauvais statut attendu, course perdue non signalée, date de terminaison perdue, statut `expired` au lieu de `terminated`, rôles ou appelant perdus au HTTP du Broker, corps illisible pris pour un appelant, codes `401`/`400`/`500`/`200` au lieu de `403`/`409`/`404`/`503`, cause renvoyée au client ou non journalisée, `DELETE` non compté ou compté **après** le Broker ou au seau de `POST /sessions`, lecture comptée, corps du client relayé, nom d'utilisateur au lieu de l'identifiant, rôles non envoyés ou ceux d'un administrateur, méthode changée, méthodes inconnues relayées. **46 d'emblée ; 3 survivants réels** — l'action passée à Authorization (**ignorée** par le service d'autorisation : le test épingle ce que dit le Broker), les rôles perdus entre le HTTP du Broker et le service, la cause du `503` non journalisée — comblés par deux tests ; **4 mutations qui ne compilaient pas** réécrites puis détectées. Rejeu des 43 mutations d'ADR-0016 contre les tests mis à jour (la mutation « `terminate` compté » est devenue le comportement voulu ; ajout de « l'annonce ne nomme pas `terminate` ») : 42 détectées, 1 équivalente (A6, déjà consignée).

**Ce que cela ne fait PAS :**
1. ~~**Terminer ne coupe pas une connexion déjà ouverte ni un ticket déjà émis**~~ — **levé par ADR-0018** (section suivante) : le proxy coupe et jette avant que le Broker marque la session terminée.
2. ~~**`GET /sessions/{id}` reste ouvert à tout utilisateur authentifié** (demandeur, compte, justification) : décision à prendre — qui peut **lire** une session.~~ — **levé par ADR-0019** (section plus bas).
3. **Un `platform-admin` sans politique ne peut plus terminer la session d'un autre** (le `docs/administration/audit-and-compliance.md` documente la politique à créer) ; une politique `session-terminate:account:*` est large par construction.
4. **La terminaison en masse est ralentie** par le budget d'actions (10 d'un coup, puis 6 par minute) ; `SESSION_ACTION_BURST` se règle.
5. **Le service d'autorisation ignore le champ `action`** : la décision se fait sur la ressource seule. Rien de nouveau, mais à savoir avant d'écrire une politique qui compterait dessus.
6. **Une autorité de terminaison compromise coupe ce qu'elle veut sur ses comptes** ; le remède est de réduire ses politiques et de révoquer le jeton.

## Rendre la terminaison réelle côté proxy (ADR-0018)

Suite de la première limite d'ADR-0017 (« terminer ne coupe pas la connexion ouverte »). Bony Kiss a répondu « Go pour la prochaine étape » à ma proposition ; l'ADR est marqué « Accepté » sur cette réponse, sans validation plus détaillée — les choix ci-dessous sont les miens et peuvent être renversés.

**Ce qui a été mesuré avant de décider** (test d'intégration sur processus réels, **rouge avant le correctif**) : l'opérateur ouvre un shell, le demandeur appelle `DELETE /sessions/{id}` → `200`, session `terminated` — et le shell reste ouvert (le test échouait à sa première assertion, « la session n'a pas été coupée » ; les assertions suivantes — ticket non consommé, mémoire de la révocation — n'étaient pas atteintes avant le correctif).

**Ce qui est livré.**
- **Ordre** : le Broker fait **révoquer au proxy d'abord**, puis change son enregistrement (`SaveIfStatus`, inchangé). Le proxy qui ne confirme pas ⇒ `503`, rien n'est terminé, `session.terminate` en échec sous le nom de l'appelant dans l'audit ; le même appel rejoué aboutit. Jamais d'appel au proxy pour une terminaison refusée, d'une session inconnue, non active, expirée, ou quand Authorization ne répond pas.
- **Route** : `POST /internal/v1/revoke-session` `{session_id, ttl_seconds}` sur le proxy SSH, **Broker seul** (ADR-0010). `200` si plus rien n'est ouvert, `503` sinon (attente ≤ 5 s), `400`, `405`, idempotente.
- **Registre** `proxycore.LiveSessions` (connexions ouvertes + mémoire des révocations, **un verrou**) partagé entre la route et `Listener.Serve` : `Begin` refuse atomiquement une session révoquée ; `Serve` enregistre **avant** l'admission, l'audit et le credential ; `relayCtx` dérive de `liveCtx` ; la connexion cible est fermée à l'annulation (`context.AfterFunc`, y compris pendant la poignée de main SSH). Sans registre, une session ne démarre pas (`ErrNotRevocable`, `503`).
- **Révoquer** = se souvenir (temps restant + 1 min, plafond 7 jours, comparé en secondes avant conversion), signaler, jeter les tickets non utilisés, attendre. `establish-session` refuse une session révoquée (`409`) avant d'interroger l'enregistreur, puis reprend le ticket si une révocation l'a croisé.
- **Audit** : le proxy émet `session.revoked` (succès) par connexion coupée, puis `session.terminate` (succès) ; un arrêt du proxy n'est pas une révocation. **Opérateur** : « openbastion: session ended because it was terminated. » — pas par qui.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Mode strict seulement** : proxy injoignable ⇒ on ne peut pas terminer (`503`). Un `PROXY_REVOCATION=best_effort` rouvrirait le mensonge « terminé » pendant qu'une connexion tourne ; je ne l'ai pas ajouté.
2. **Proxy d'abord, enregistrement ensuite** : si le proxy a coupé et que l'enregistrement échoue, la session est coupée mais encore marquée `active` — le bon sens de l'erreur.
3. **Appel direct plutôt qu'événement sur le bus** : l'appel répond « a-t-on coupé ? », une diffusion non.
4. **Le message de l'opérateur ne dit pas qui** a terminé.
5. **Mémoire des révocations en mémoire** : un redémarrage l'oublie, sans danger (le Broker n'émet plus de ticket).

**Preuves.** Tests nouveaux : `pkg/proxycore` +24 (65 → 89 : registre — coupe toutes les connexions d'une session et elles seules, refus d'une session révoquée jusqu'à l'échéance, mémoire jamais raccourcie / prolongée / balayée, `Wait`, `End`, `OpenConnections`, `RevokedUntil`, course enregistrement/révocation 500 fois sous `-race` ; `Serve` — coupe du relais, session terminée jamais démarrée et rien d'extrait pour elle, coupe pendant l'extraction du credential, entre l'extraction et le relais, sans registre, session avec échéance, coupe après l'échéance, arrêt du proxy ≠ révocation, révocation qui n'attend pas l'audit) ; ssh-proxy infrastructure +4 (19 → 23 : tickets d'une session et elle seule, session inconnue, ticket utilisé, concurrence) ; ssh-proxy interfaces +9 (6 → 15 en comptant les règles d'appelants : route de révocation, 400/405, idempotence, `503` si une connexion ne se ferme pas, durée et plafond de la mémoire, débordement, sans registre, `establish-session` refusé / en vol) ; ssh-proxy sshcodec +1 (13 → 14 : coupe pendant la poignée de main) ; Broker application +7 (83 → 90 : ordre proxy puis enregistrement, marge exacte, date au moment de l'enregistrement, proxy jamais appelé pour une terminaison non faite, échec audité sous le nom de l'appelant — demandeur et autorité —, rejeu après panne, coupe sans enregistrement) ; Broker infrastructure +6 (42 → 48 : client HTTP de la révocation) ; Broker interfaces +1 (23 → 24 : `503` sans la cause, cause dans le journal) ; intégration +1 (40 → 41 : `session_revocation_test.go`, sur processus réels, **rouge avant le correctif**) et des appels forgés ajoutés à `mtls_flow_test.go` (Vault, Gateway compromis, outil d'exploitation → `revoke-session` ; Vault et proxy SSH → `DELETE /sessions/{id}`).

Tests existants qui ont dû changer, par construction : le test d'intégration d'ADR-0017 (proxy de substitution qui enregistre les révocations ; une terminaison refusée n'y touche pas), **`TestPostgresFlow_SessionSurvivesSessionBrokerProcessRestart`** (trouvé par la vérification complète, pas par la série sans base : il termine une session sur un Broker sans proxy ; proxy de substitution), les tests HTTP du proxy (`newServer` donne un registre au serveur), la fixture `fakeProxyClient` du Broker.

**96 mutations, toutes détectées** : ordre (proxy jamais appelé / appelé après l'enregistrement / appelé pour une terminaison refusée, non active ou sans droit), marge absente ou nulle, temps restant faux, échec non audité / audité en succès / sous le nom du demandeur / ignoré (échec ouvert) / en conflit, client (tout statut accepté, chemin, méthode, arrondi, plancher, identifiant, en-tête), route du proxy (mémoire oubliée aussitôt, tickets non jetés, attente omise, `200` malgré une connexion qui se ferme, validations, méthode, débordement, plafond, durée, refus d'`establish-session` absent ou unique, ticket non repris, sans registre, mauvaise session), règles d'appelants (Gateway, tout le monde, Vault, règle absente, toute méthode), registre (refus absent, signal absent ou de mauvaise cause, mauvaise session, mémoire raccourcie / jamais écrite / éternelle / non balayée / non prolongée, comptes, `End`, verrou), `Serve` (registre absent, erreur de refus, coupe pendant l'extraction ou avant le relais non vue, non auditée, credential non purgé, fin du relais non signalée, succès de `terminate`, coupe prise pour une échéance, contexte du relais ou de l'échéance, connexion non enregistrée, arrêt pris pour une révocation), codec (connexion cible non fermée à l'annulation), message de l'opérateur (absent, qui l'a décidé, celui de l'échéance), câblage du proxy (registre absent ou distinct). Série finale : 96 sur 96 ; rejeu des 53 mutations d'ADR-0017 : 53 sur 53. Un test qui compare à la constante qu'il teste ne prouve rien : la marge de révocation est désormais écrite en dur dans l'attendu (21 min pour 20 min restantes).

Vérifié sur le code final (`grep -c '^--- PASS'`, pas estimé) : 501 unitaires sans base (46 ignorés), 547 avec ; 52 PostgreSQL ; 35 d'intégration sans base (6 ignorés), 41 avec ; `-race` propre (unitaires et intégration).

**Ce que cela ne fait PAS :**
1. **Plusieurs réplicas du proxy SSH** : tickets, connexions et mémoire sont dans le processus ; la révocation n'atteint que l'instance que le Broker connaît. **Ne pas déployer plusieurs réplicas** (`docs/deployment/high-availability.md`).
2. **Les octrois de portée du Vault ne sont pas révoqués** : le proxy abandonne le jeton avec le ticket (usage unique, réservé à l'identité du proxy).
3. **Proxy en panne ⇒ on ne peut pas terminer** (mode strict).
4. **Une révocation pendant la poignée de main vers la cible** ferme cette connexion ; le proxy ne peut pas faire mieux sans contexte dans la bibliothèque SSH.
5. ~~**`GET /sessions/{id}` reste ouvert à tout utilisateur authentifié** (limite d'ADR-0017, inchangée).~~ — **levé par ADR-0019** (section suivante).
6. **Le nombre de révocations mémorisées n'est borné que par leur expiration.**

## Qui peut lire une session (ADR-0019)

Suite du constat voisin laissé par ADR-0017 et reporté par ADR-0018 (« `GET /sessions/{id}` reste ouvert »). Bony Kiss a répondu « Go pour la prochaine étape » à ma proposition ; l'ADR est marqué « Accepté » sur cette réponse, sans validation plus détaillée — les règles ci-dessous sont **mes choix**, qu'il peut renverser.

**Ce qui a été mesuré avant de décider** (lecture du Gateway et du Broker, puis test d'attaque sur processus réels, **rouge avant le correctif : 4 affirmations sur 6 en échec**) :
- Le Gateway relayait `GET /sessions/{id}` tel quel ; `GetSession(ctx, id)` ne recevait aucun appelant. `nobody` (aucun rôle, aucune politique) obtenait **`200`** avec le demandeur, le compte, la justification et l'échéance de la session d'un autre.
- La **justification d'une urgence en attente** était lisible par n'importe quel porteur de jeton, alors que la liste d'ADR-0012 la cache à qui ne peut pas la décider : filtrer la liste n'avait aucun sens tant que la lecture directe restait ouverte.
- L'ancien gestionnaire répondait **`404` à toute erreur du store** : une base muette disait « session inconnue ».
- Dès que le Broker lit `callerId`/`actorRoles` dans la requête, un client qui les écrit lit comme n'importe qui : le Gateway doit les construire **et** écarter ceux du client, ensemble. Le test les forge.

**Ce qui est livré.**
- **Qui** : le demandeur, toujours et sans politique ni appel à Authorization ; la personne qui a décidé la session (`DecidedBy` = appelant), pour cette session ; ou une politique sur `session-read:account:{privilegedAccountId}` (action `session:read`, refusée par défaut, préfixe distinct de `vault:`, `breakglass:`, `breakglass-approve:`, `session-terminate:`).
- **Au nom de qui** : `forwardRead` du Gateway construit `?callerId=&actorRoles=` (rôles encodés) à partir du jeton vérifié ; la requête et le corps du client sont écartés. Les lectures restent hors du budget d'actions.
- **Ordre** : appelant vide `403` → session `404` → appelant `403` → Authorization (`503` pour un tiers, échec fermé). Refus **générique** : ni compte, ni demandeur, ni justification, ni état, ni la raison de l'Authorization Service (elle nomme le compte). Erreur du store qui n'est pas `ErrNotFound` → `503` (cause dans le journal du Broker).
- **Une lecture n'écrit rien** : ni audit (pas même un refus), ni `Save` (prouvé avec un store qui compte ses écritures). *Amendé par ADR-0020 (section suivante) : une lecture servie n'écrit toujours rien ; le refus de politique est audité, dans une limite.*

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Qui lit** : demandeur + décideur + une politique de lecture déclarée. Un approbateur qui n'est ni l'un ni l'autre est refusé (la liste d'ADR-0012 est son outil).
2. **Une ressource à part** (`session-read:account:`) plutôt que de réutiliser `breakglass-approve:` ou `session-terminate:` : trois pouvoirs distincts.
3. **Un refus de lecture n'est pas audité** : sinon tout porteur de jeton aurait une écriture à volonté dans la trace signée (le problème d'ADR-0014/0016). **Coût déclaré** : une sonde d'identifiants n'est visible nulle part (le Gateway ne journalise pas les requêtes). Alternative décrite dans l'ADR : auditer les refus avec un budget d'échecs par identité.
4. **`404` pour un identifiant inconnu** (aléatoire sur 64 bits, comme ADR-0017), plutôt qu'un `403` partout.
5. **Aucune politique n'est créée par défaut** : après cette étape, seuls le demandeur et le décideur lisent tant que l'opérateur n'a pas écrit `session-read:account:…` pour ses auditeurs. **Changement visible.**

**Preuves.** Tests nouveaux : Broker application +14 (90 → 104 : demandeur sans politique et sans appel à Authorization, politique sur le bon compte avec les rôles de l'appelant, refus sans fuite — la raison d'Authorization comprise —, les autres politiques ne lisent pas, compte voisin refusé, décideur de cette session seulement, requérant exact, ordre, Authorization muette, base muette, une lecture n'écrit rien — audit, enregistrement et store compté —, échéance lue sans être écrite), Broker interfaces +6 (24 → 30 : l'appelant est la requête du Gateway et rien d'autre, codes et qui peut, refus sans rien de la session, Authorization interrogée avec les rôles de la requête sur le compte de la session, `503` sans la cause et cause dans le journal, une lecture ne change rien), Gateway interfaces +6 (54 → 60 : le Broker reçoit qui lit et avec quels rôles et pas le client, rôles encodés, sans jeton rien n'atteint le Broker, ce que le Broker répond est relayé tel quel, `502` sans adresse, lecture hors budget), intégration +1 (41 → 42 : le test d'attaque sur processus réels, six affirmations, et quatre lectures forgées dans la table d'attaque mTLS — Vault, proxy SSH, outil d'exploitation, enregistreur — plus le Gateway servi pour le demandeur).

Tests existants qui ont dû changer, par construction : la signature de `GetSession` (appels des tests du Broker), les `GET` des tests HTTP du Broker (ils nomment maintenant qui lit : `?callerId=alice`), `brokerGetSession` de `postgres_flow_test.go` (lit en tant que le demandeur, `it-user1`), et la vérification finale de la table mTLS, qui lisait la session par le Gateway sans nommer personne : elle lit désormais avec le jeton de l'opérateur, par le vrai Gateway. L'ancre de la mutation G4 d'ADR-0017 (« lire est compté ») visait l'ancien relais brut du `GET` : réalignée sur `forwardRead`.

**65 mutations** : garde de l'appelant, ordre, correspondance **exacte** du demandeur (casse, préfixe, espaces) et du décideur, ressource, compte, action et rôles de la question posée à Authorization, panne d'Authorization (accordée, refusée, « introuvable »), fuites du message de refus (raison, compte, demandeur), erreur du store, écritures et audit d'une lecture, codes et cause du gestionnaire HTTP, source de l'identité du Gateway, requête du client, encodage, méthode, budget, et règles mTLS. 58 détectées d'emblée ; **4 survivantes réelles** — un demandeur reconnu par préfixe de nom (R10), la raison de l'Authorization Service recopiée dans le refus (R22, le test ne contrôlait pas ce texte), une lecture qui ré-enregistre l'enregistrement tel quel (U3, invisible par comparaison : il a fallu un store qui compte les écritures), et le retrait de la garde « décideur vide » (R7) — dont **3 closes par des tests** et **1 équivalente** : cette garde est redondante tant que l'appelant vide est refusé en premier ; elle reste en défense en profondeur. **2 mutations ne compilaient pas** (P1, E1 : `roles` devenait inutilisé) : réécrites. La série finale donne 64 sur 64 hors l'équivalente ; régression : les 96 mutations d'ADR-0018 donnent 96 sur 96 et les 53 d'ADR-0017 donnent 53 sur 53 (G4 réalignée).

Vérifié sur le code final (`grep -c '^--- PASS'`, pas estimé) : 527 unitaires sans base (46 ignorés), 573 avec ; 52 PostgreSQL ; 36 d'intégration sans base (6 ignorés), 42 avec ; `go build`, `go vet` et `gofmt -l` propres ; `-race` propre (unitaires et intégration).

**Ce que cela ne fait PAS :**
1. ~~**Un refus de lecture ne laisse aucune trace** (ni audit ni journal).~~ **Levé par ADR-0020** (section suivante), dans une limite.
2. **`404` pour un identifiant inconnu** révèle qu'il n'existe pas (identifiants à 64 bits aléatoires).
3. **Une politique `session-read:account:*` est large** et lit les justifications d'urgence de tous les comptes qu'elle couvre.
4. **Lire une session n'est pas lire ce qui s'y est tapé** : le Command Recorder garde son rôle auditeur.
5. **Les octrois du Vault ne sont toujours pas révoqués, le proxy SSH est toujours en instance unique, le mode de révocation est toujours strict** (ADR-0018, inchangé).

## Auditer les refus de lecture (ADR-0020)

Suite directe de la limite n° 1 d'ADR-0019 (« un refus de lecture ne laisse aucune trace »), que cet ADR désignait comme la première à lever. Bony Kiss a répondu « Go pour la prochaine étape » à ma proposition ; l'ADR est marqué « Accepté » sur cette réponse, sans validation plus détaillée — les règles ci-dessous sont **mes choix**, qu'il peut renverser.

**Ce qui a été mesuré avant de décider** (tests écrits d'abord, **rouges avant** : un unitaire, un sur processus réels) : trois refus de Bob sur la session d'Alice laissent trois `403` et **zéro** événement `session.read`, aucune ligne de journal. Et ce qu'ADR-0016 a mesuré pour `approve` et `reject` vaut ici : auditer chaque refus sans borne, c'est une écriture à volonté dans la trace signée pour tout porteur de jeton (douze refus, douze événements). L'événement et sa borne vont ensemble.

**Ce qui est livré.**
- **Un événement** `session.read`, `resource_type=session`, `resource_id` = la session, `success=false`, écrit pour le **refus de politique** seulement (le `403` d'un appelant nommé, sur une session qui existe, après un « non » de l'Authorization Service). **L'auteur est l'appelant que le Gateway a vérifié** — jamais `sess.RequestedBy`, jamais une valeur de la requête du client (un test forge `?callerId=<le demandeur>&actorRoles=…`).
- **Un budget par identité** (`RefusalBudget`, `refusal_budget.go`, seau à jetons) dans le Broker : rafale `SESSION_READ_AUDIT_BURST` (10, de 1 à 1000), puis `SESSION_READ_AUDIT_RATE_PER_MINUTE` (6, de 1 à 600) ; invalide ⇒ le Broker s'arrête en nommant la variable ; pas d'« illimité » ni de « désactivé » ; un Broker construit à la main a le budget strict. La clé est l'**identité**, pas la session. Mémoire bornée (un seau revenu plein est oublié, avec une marge pour l'arrondi flottant), horloge qui recule sans effet (la référence n'avance que vers l'avant).
- **La réponse ne dépend jamais du budget** : le refus est identique que l'événement soit écrit, supprimé ou perdu par une panne de l'audit (au mieux, comme ADR-0017 ; ce n'est pas « enregistrer ou refuser », ADR-0008). Une ligne de journal **par épisode** quand un budget est épuisé, une ligne avec la cause quand l'audit est en panne. `404`, `503`, appelant vide et lecture servie n'écrivent rien et ne dépensent aucun jeton.
- Le Gateway ne change pas ; OpenAPI, `docs/api/grpc/README.md` et les guides disent le nouveau comportement.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Auditer le refus** (et non le laisser sans trace, ni le journaliser seulement) : la sonde devient visible là où l'on cherche les tentatives.
2. **Un budget par identité**, 10 puis 6 par minute : des défauts stricts **choisis**, pas dérivés d'un usage réel. Réglables.
3. **Le refus ne dépend pas de l'audit** : lire n'engage à rien enregistrer ; faire d'une panne de l'audit une panne des lectures pénaliserait le demandeur.
4. **Pas d'événement de synthèse** à la fin d'un épisode : le nombre exact de refus supprimés n'est pas enregistré.
5. **Pas d'audit des lectures servies** aux titulaires de politique : décision d'une autre nature (volume, sens de « lire » pour un auditeur). *Repris par ADR-0021 (section suivante).*
6. **Un limiteur de plus** dans le Broker plutôt qu'un partage avec celui du Gateway (paquet `internal` d'un autre module, et il répond autre chose : un délai de reprise).

**Preuves.** Tests nouveaux : Broker application +22 (104 → 126 : le seau — rafale, débit et unités, plafond même avant le balayage, isolation par identité, premier refus non écrit, valeurs non positives, mémoire bornée, seau non rempli gardé par le balayage, horloge qui recule sans donner ni prendre, concurrence — et le service — événement au nom de qui a demandé, rien pour ce qui n'est pas un refus, budget par défaut strict et réglable, refus identique budget épuisé, audit en panne, une ligne de journal par épisode, horloge du service), Broker interfaces +3 (30 → 33 : l'événement sous le nom de l'appelant de la requête, ce qui n'est pas un refus n'écrit rien, même réponse quel que soit le budget), intégration +2 (42 → 44 : sur processus réels, onze refus de Mallory sur deux sessions, tous `403`, **trois** événements ; Bob garde son budget ; la requête forgée ne choisit pas l'auteur ; Alice, Carol et un `404` n'écrivent rien ; la chaîne d'audit se vérifie ; la configuration invalide arrête le Broker, les bornes passent, la ligne de démarrage dit le budget appliqué). Tests existants adaptés : l'ancien test « une lecture n'écrit rien, pas même un refus » est réécrit pour ADR-0020 (par construction) ; l'espion de `record_or_refuse_test.go` garde le type de ressource.

**81 mutations** sur le seau (arithmétique, plafond, unités, isolation, premier refus, balayage et marge, valeurs non positives, horloge, verrou), le service (nom, type, auteur, ressource et succès de l'événement, clé du budget, refus identique, audit en panne, lignes de journal, horloge, budget par défaut) et la configuration (noms des variables, bornes, défauts, ligne de démarrage, arrêt sur valeur invalide) : 73 détectées d'emblée, **4 survivantes réelles** (seau non plafonné, plafond relevé d'un, seau à moitié rempli supprimé par le balayage, horloge qui recule qui prend des jetons) closes par **3 tests**, **2 qui ne compilaient pas** (réécrites et détectées), **2 équivalentes** documentées (l'arrondi de `RatePerMinute` ; la marge du balayage) : 79 sur 79 hors équivalentes. Rejeu : ADR-0019 64 sur 64 (+ l'équivalente déjà documentée), ADR-0017 53 sur 53, ADR-0018 96 sur 96 (la reprise après qu'un processus du sandbox a été tué en cours de mutation — le fichier muté restauré depuis HEAD, vérifié — donne 15 + 81).

Vérifié sur le code final (`grep -c '^--- PASS'`, pas estimé) : 552 unitaires sans base (46 ignorés), 598 avec ; 52 PostgreSQL ; 38 d'intégration sans base (6 ignorés), 44 avec ; `go build`, `go vet` et `gofmt -l` propres ; `-race` propre (unitaires et intégration).

**Ce que cela ne fait PAS :**
1. **Le nombre exact de refus supprimés n'est pas enregistré** : on sait qu'un budget est épuisé et quand, pas combien d'essais ont suivi.
2. ~~**Une lecture servie à un titulaire de politique n'est pas auditée** : on voit qui est refusé, pas qui a lu.~~ **Levé par ADR-0021** (section suivante).
3. **Chaque refus interroge l'Authorization Service**, budget épuisé ou non : le budget borne ce qu'on écrit, pas ce qu'on interroge.
4. **Un jeton volé épuise le budget de son titulaire** (même limite qu'ADR-0016).
5. **Par processus** : *N* répliques, *N* fois la borne ; valeurs par défaut non mesurées sur un usage réel.
6. **Les octrois du Vault ne sont toujours pas révoqués, le proxy SSH est toujours en instance unique, le mode de révocation est toujours strict** (ADR-0018, inchangé).

## Enregistrer avant de servir une lecture à un titulaire de politique (ADR-0021)

Suite directe de la limite n° 2 d'ADR-0020 (« on voit qui est refusé, pas qui a lu »), que cet ADR désignait comme la suivante à lever. Bony Kiss a répondu « Go pour la prochaine étape » à ma proposition ; l'ADR est marqué « Accepté » sur cette réponse, sans validation plus détaillée — les règles ci-dessous sont **mes choix**, qu'il peut renverser.

**Ce qui a été mesuré avant de décider** (tests écrits d'abord, **rouges avant** : trois unitaires, et **5 sous-cas sur 7** du test sur processus réels) : Carol (rôle `auditor`, politique `session-read` sur le compte) lit la session d'Alice — `200`, avec la justification, le compte et le demandeur — et l'espion d'audit n'a vu **zéro** événement ; dix-sept lectures de suite, zéro ; et avec l'Audit Service rendu muet (l'espion répond `503`), Carol reçoit **toujours `200`** avec tout. Lu dans le code : `CreateSession` et l'approbation d'une urgence échouent déjà **fermés** quand l'événement ne s'écrit pas (« a grant nobody could record is not made », `docs/deployment/high-availability.md` §1) ; seule la lecture, qui accorde une connaissance, ne l'était pas. Vérifié aussi : la liste des demandes en attente (ADR-0012) et la lecture des enregistrements du Command Recorder (qui n'a aucun client d'audit) ne sont **pas** auditées — non traitées ici.

**Ce qui est livré.**
- **Un événement** `session.read`, `resource_type=session`, `resource_id` = la session, **`success=true`**, auteur = l'appelant vérifié par le Gateway (jamais le demandeur, jamais la requête du client), pour la lecture servie **sur la force d'une politique** (le chemin « oui » de l'Authorization Service) — pas pour le demandeur ni le décideur.
- **Écrit avant de servir ; sans lui, rien n'est servi** : `ErrUnavailable` (`503`), ni `ErrForbidden` ni `ErrNotFound` ; le message du service porte la cause (« recording the read: … ») pour que le gestionnaire HTTP l'écrive au journal, jamais au client. Le Gateway relaie le `503` ; il ne change pas.
- **Pas de budget** : un budget qui supprime un événement est une lecture que personne ne peut prouver. Le budget d'ADR-0020 est une autre chose : une lecture servie n'en dépense aucun jeton et un budget épuisé ne la fait pas taire.
- **Asymétrie voulue** : ce qui réduit un accès (terminer, un refus de lecture) reste au mieux ; ce qui accorde — session, approbation, connaissance — est fermé.
- Tests existants changés par construction : 4 unitaires/HTTP et 1 sous-cas d'intégration d'ADR-0020 (« une lecture servie n'est pas un événement »), qui comptaient comme « refus » tout `session.read` ; ils distinguent maintenant les refus (`success=false`) des lectures servies (`success=true`).

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Fermé, pas « au mieux »** : une panne de l'Audit Service rend la lecture d'un auditeur indisponible (le prix, y compris pour enquêter sur la panne). L'alternative « au mieux » laisse la divulgation continuer sans trace au pire moment.
2. **Pas de budget, pas de regroupement** : un événement par lecture servie, borné seulement par la limite par adresse du Gateway (ADR-0015). Le regroupement par lecteur et par session sur une fenêtre est repoussé (il perd des relectures alors que l'état change).
3. **Le demandeur et le décideur ne sont pas tracés** : rien de nouveau ne leur est divulgué ; un décideur qui perd son rôle relit sans trace.
4. **Un `503`, pas un `429`** : un code de plus pour une lecture serait pire qu'un volume.
5. **La liste des demandes en attente et la lecture des enregistrements restent hors de cet ADR** (le Recorder n'a pas de client d'audit).

**Preuves.** Tests nouveaux : Broker application +7 (126 → 133 : événement au nom de qui a lu, requérant et décideur sans événement ni dépendance de l'audit, un événement par lecture quelle que soit la quantité, le budget des refus indépendant, lecture non servie sans son événement et servie une fois l'audit revenu, un refus reste au mieux, rien d'autre n'est une lecture servie), Broker interfaces +2 (33 → 35 : l'événement sous le nom de l'appelant de la requête à chaque fois, `503` sans cause ni session avec la cause dans le journal, le demandeur lit toujours et un refus reste `403`), intégration +1 (44 → 45 : sur processus réels, la lecture de Carol laisse **un** événement sous son nom **à l'instant où la réponse arrive**, jamais sous celui d'Alice ni de la requête forgée ; dix-sept lectures, dix-sept événements ; Alice, trois lectures, aucun ; audit en panne : Carol `503` sans la justification, le compte, le demandeur ni l'identifiant, Alice `200`, Bob `403`, aucun événement pendant la panne ; audit revenu : la lecture de Carol est servie et laisse un événement ; la chaîne d'audit se vérifie). L'espion d'audit sait tomber en panne (`setDown`).

**23 mutations** (événement absent, panne ignorée / rendue en refus / en « introuvable », cause ou session dans le message, écriture en arrière-plan, nom, type, ressource, issue et auteur de l'événement, qui est enregistré — requérant, décideur, refus, Authorization muette, session absente, appelant sans nom —, budget de refus dépensé ou consulté, refus rendu strict) : les 23 sont tuées. Rejeu : ADR-0020 79 sur 79 hors 2 équivalentes ; ADR-0019 64 sur 64 hors 1 équivalente (R7, le garde du décideur vide, inatteignable tant que le refus de l'appelant vide tient) ; ADR-0017 53 sur 53 ; ADR-0018 96 sur 96. **Un incident à signaler** : la liaison de l'ordinateur à la session a tué la série de rejeu en cours (ADR-0019 coupée au 10ᵉ mutant, un fichier muté laissé en place) ; j'ai restauré le fichier depuis la sauvegarde d'avant mutation, vérifié que le diff ne contient que le bloc d'ADR-0021 (8 lignes), et relancé les séries concernées, détachées du shell.

Vérifié sur le code final (`grep -c '^--- PASS'`, pas estimé) : 561 unitaires sans base (46 ignorés), 607 avec ; 52 PostgreSQL ; 39 d'intégration sans base (6 ignorés), 45 avec ; `go build`, `go vet` et `gofmt -l` propres ; `-race` propre (unitaires et intégration).

**Ce que cela ne fait PAS :**
1. **Une panne de l'Audit Service rend la lecture d'un auditeur indisponible** (le prix choisi).
2. **Chaque lecture écrit, sans regroupement** : un titulaire de politique compromis remplit la trace de lectures vraies à la borne de la limite par adresse ; valeurs non mesurées sur un usage réel.
3. **Le demandeur et le décideur ne sont pas tracés.**
4. **L'événement ne dit ni ce qui s'affichait ni le compte**, et peut précéder une réponse perdue.
5. **La liste des demandes en attente (ADR-0012) et la lecture des enregistrements (Command Recorder) divulguent toujours sans événement** — la seconde est la plus lourde : ce sont les commandes tapées.
6. **Chaque refus interroge toujours l'Authorization Service** (ADR-0020, inchangé) ; budget des refus par processus.
7. **Les octrois du Vault ne sont toujours pas révoqués, le proxy SSH est toujours en instance unique, le mode de révocation est toujours strict** (ADR-0018, inchangé).

## Auditer la lecture des enregistrements du Command Recorder (ADR-0022)

Suite de la limite d'ADR-0021 (« la lecture des enregistrements divulgue sans événement — la plus lourde : ce sont les commandes tapées »). Bony Kiss a demandé « Continuer le développement » sur cette étape, proposée par le rapport précédent ; l'ADR est marqué « Accepté » sur cette demande, sans validation plus détaillée — les choix ci-dessous sont les miens et peuvent être renversés.

**Ce qui a été mesuré avant de décider** (test sur processus réels, **rouge avant le correctif** : 5 sous-cas sur 7 en échec) : Carol, titulaire de `recording:session:*`, lit `cat /etc/shadow` et `mysql -u root prod_customers` : `200`, **zéro** événement ; dix-sept lectures : zéro ; l'Audit Service en panne : `200` avec les commandes. Le Gateway ne transmettait au Recorder que les rôles, pas l'utilisateur ; le Recorder n'avait pas de client d'audit, et l'Audit Service refusait `command-recorder` sur `emit-event` (règle et test). En lisant le code : une Authorization muette se lisait `403`, et une erreur du store traversait le Gateway dans le corps du `500`.

**Ce qui est livré.**
- **Événement** `recording.read`, `resource_type=session`, `resource_id`=la session, `success=true`, auteur = l'utilisateur que le Gateway a vérifié ; **une par page servie**, page vide comprise ; **écrit avant de servir**, et **sans lui, rien n'est servi** (`503`) ; pas de budget.
- **Ordre** : appelant vide `403` → Authorization `403` / `503` (muette : n'est plus un `403`) → store `500` → audit `503` → servi. Le store est lu avant l'écriture, pour ne jamais écrire une lecture qu'une base en panne empêche ; un refus n'écrit rien.
- **Gateway** : `?callerId=` construit d'après le jeton vérifié, celui du client écarté (seuls `page` et `pageSize` sont recopiés). Proto : champ additif `actor_user_id = 5` dans `GetCommandRecordingRequest` (`docs/api/grpc/README.md` recopié).
- **Recorder** : `AUDIT_URL` (défaut `127.0.0.1:8082`, client mTLS épinglé à `audit-service`, aucun réglage pour s'en passer ; `make run-command-recorder` le passe) ; `503` et `500` au corps générique, cause au journal (« reading the recording of session … for user … not done: … »).
- **Audit Service** : `POST /audit/v1/emit-event` nomme `command-recorder` (cette méthode seulement).

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Une action distincte** (`recording.read`) sur la **ressource `session`**, plutôt que `session.read` ou une ressource `recording`.
2. **Un événement par page**, sans détail de page (le port d'audit n'a pas de champ de détail).
3. **Store lu avant l'écriture de l'événement.**
4. **Une Authorization muette est un `503`**, plus un `403` (le test existant `TestGetRecording_FailsClosedWhenAuthorizationIsUnreachable` attendait `ErrForbidden` : il encodait la confusion panne/refus que le commentaire de `statusFor` dénonçait ; il attend maintenant `ErrUnavailable`, toujours sans rien servir).
5. **Les refus ne sont pas audités** (pas de budget ADR-0020 côté Recorder).

**Deux changements d'environnement, sans rapport avec la sécurité**, nécessaires dans ce codespace (Go 1.27.1, `GOPATH=/go`, pas de PostgreSQL installé) :
- `buildEnv` des tests d'intégration transmet désormais `GOPATH` : il ne passait que `PATH` et `HOME`, et le cache de modules n'est pas toujours `$HOME/go` (ici `/go`) — sans cela aucun binaire ne se compilait (`module lookup disabled by GOPROXY=off`). Vide = défaut de Go, donc sans effet dans le sandbox d'origine.
- `TestSessionRoutes_OnlyKnownRoutesReachTheBroker` (Gateway) échouait **avant mon changement** (vérifié en le lançant sur le code d'origine) : le `ServeMux` de Go 1.27 répond `307` à un `POST` sur un chemin non canonique, là où le test attendait `301`. Ce que le test protège — la requête n'atteint pas le Broker — n'a pas changé ; il accepte maintenant l'une ou l'autre redirection.
- PostgreSQL 16 pour les tests : conteneur Docker local `postgres:16` (`docker run … -p 127.0.0.1:5432:5432`), à la place du `service postgresql start` de `settings.md` §7, qui n'existe pas ici.

**Preuves.** Test sur processus réels `test/integration/recording_read_test.go` (sept sous-cas, rouge avant : cinq en échec). Tests nouveaux : Command Recorder application +6 (12 → 18), infrastructure +1 (18 → 19 : client d'audit), interfaces +2 (~~1 → 3~~ 3 → 5 : les 2 tests d'appelants comptent aussi — corrigé à ADR-0024) ; tests existants changés : Gateway (le `callerId` du client écarté, celui du jeton transmis), règles d'appelants de l'Audit Service (`command-recorder` autorisé sur `emit-event`, refusé ailleurs), le test d'Authorization muette du Recorder (voir choix 4), et tous les tests d'intégration qui démarrent le Recorder reçoivent un `AUDIT_URL` (`TestPostgresFlow_RecordingSurvivesCommandRecorderProcessRestart` appelle le Recorder en direct et nomme maintenant un lecteur, comme le Gateway ; il a été trouvé par `make test-postgres`, pas par la série sans base). **32 mutations, toutes tuées** (détail dans ADR-0022). Vérifié sur le code final (`grep -c '^--- PASS'`, pas estimé) : 570 unitaires sans base (46 ignorés), 616 avec ; 52 PostgreSQL (`make test-postgres`, base PostgreSQL 16 dans un conteneur) ; 40 d'intégration sans base (6 ignorés), 46 avec ; `-race` propre sur les modules touchés et sur le test d'intégration nouveau ; `gofmt -l` vide sur les fichiers modifiés.

**Ce que cela ne fait PAS :**
1. **Une panne de l'Audit Service rend les enregistrements illisibles** (voulu, comme ADR-0021) ; le proxy continue d'enregistrer.
2. **Un refus de lecture d'un enregistrement n'est pas audité** : une sonde sur `recording:session:*` reste invisible.
3. **Le Recorder peut écrire dans la trace au nom de n'importe qui** s'il est compromis (événements non attribués par l'identité du certificat — limite connue, étendue à un troisième émetteur).
4. **L'événement ne dit ni la page ni le nombre de commandes servies.**
5. **Chaque page écrit, sans regroupement**, à la borne de la limite par adresse du Gateway.
6. **La liste des demandes en attente (ADR-0012) reste hors de la trace.**

## Auditer la liste des demandes en attente (ADR-0023)

Suite de la dernière limite d'ADR-0022 (« la liste des demandes en attente reste hors de la trace »). Bony Kiss a répondu « Go pour la prochaine étape » à ma proposition ; l'ADR est marqué « Accepté » sur cette réponse, sans validation plus détaillée — les choix ci-dessous sont les miens et peuvent être renversés.

**Ce qui a été mesuré avant de décider** (test sur processus réels, **rouge avant** : 5 sous-cas sur 8) : un approbateur liste les demandes — `200` avec la justification de l'urgence, **zéro** événement ; audit en panne — toujours `200` avec la justification. Le reste était déjà juste (appelant du jeton, appelant sans nom refusé, page vide, `503` sans liste partielle).

**Ce qui est livré.** Dans `ListPendingApprovals`, après la pagination : un `session.listed` en succès (ressource `session`, l'identifiant de la demande, auteur = l'appelant du Gateway) **par demande de la page servie**, écrits un par un **avant** de servir ; le premier qui échoue ⇒ `ErrUnavailable` (`503` générique déjà en place), rien n'est servi. Page vide : rien n'est écrit. Le Gateway, les schémas et le proto ne changent pas.

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Un événement par demande servie**, pas un par liste.
2. **Une action distincte** (`session.listed`), pas `session.read`.
3. **Une page vide n'écrit rien** et ne dépend pas de l'audit.
4. **Écritures séquentielles** (au plus 100 appels pour une page de 100), pas en parallèle.

**Preuves.** Test sur processus réels `test/integration/pending_list_read_test.go` (huit sous-cas) ; Broker application +5 (`pending_list_audit_test.go`). **14 mutations, toutes tuées** (détail dans ADR-0023). Vérifié sur le code final (`grep -c '^--- PASS'`) : 575 unitaires sans base (46 ignorés), 621 avec ; 52 PostgreSQL ; 41 d'intégration sans base (6 ignorés), 47 avec ; `-race` propre sur le Broker et les tests d'intégration de la liste ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Une panne de l'Audit Service cache les urgences en attente à leurs approbateurs** (la notification continue ; approuver dépend déjà de l'audit).
2. **Une interface qui interroge écrit un événement par demande et par interrogation**, sans regroupement.
3. **Écritures séquentielles** ; une panne au milieu d'une page laisse les premières demandes dans la trace sans qu'elles aient été vues.
4. **Le demandeur et le décideur d'une session ne sont toujours pas tracés quand ils la lisent** (ADR-0021, inchangé) ; les refus de lecture d'un enregistrement ne sont pas audités (ADR-0022, inchangé).

## Auditer les refus de lecture d'un enregistrement, et partager le seau à jetons (ADR-0024)

Suite de la limite d'ADR-0022 (« un refus de lecture d'un enregistrement n'est pas audité »). Bony Kiss a écrit « Tu peux poursuivre automatiquement sur les autres étapes » ; l'ADR est marqué « Accepté » sur cette consigne — les choix ci-dessous sont les miens et peuvent être renversés.

**Ce qui a été mesuré avant de décider** (processus réels, rouge) : un refus de politique ne laisse aucun événement ; l'identifiant de session du chemin n'était pas borné (257 octets : `200` vide et un événement pour un auditeur) ; l'Audit Service ne borne ni le corps ni les champs d'`emit-event` (lu dans le code).

**Ce qui est livré.**
- **Refus** : `recording.read` en échec, sous le nom de l'appelant vérifié, au mieux, dans un budget par identité (`RECORDING_READ_AUDIT_BURST` 10 de 1 à 1000, `RECORDING_READ_AUDIT_RATE_PER_MINUTE` 6 de 1 à 600, hors bornes fatal, annoncé au démarrage) ; même `403` quoi que disent le budget ou l'audit ; une ligne de journal par épisode.
- **Identifiant** : vide, plus de 256 octets ou pas UTF-8 ⇒ `400` « not a session id » (`domain.ErrNotASessionID`), avant toute question, sans événement.
- **`pkg/refusalbudget`** : le `RefusalBudget` du Broker déplacé (`git mv`, ses 13 tests avec lui), devenu `refusalbudget.Budget` ; module stdlib, ajouté au `go.work`, au `Makefile` (build, vet, test) et aux `go.mod` du Broker et du Recorder (`replace` local). Le Broker garde ses constantes publiques, qui renvoient au module ; son comportement ne change pas (125 tests du paquet `application` — 138 moins les 13 déplacés —, tous verts).

**Choix que j'ai faits et que Bony Kiss peut renverser :**
1. **Partager le seau dans un module** plutôt que le recopier.
2. **Les mêmes défauts qu'ADR-0020** (10 puis 6 par minute) et des variables propres au Recorder.
3. **Refuser (`400`) un identifiant impossible** plutôt que le tronquer ; cela change aussi la lecture servie d'ADR-0022 (un identifiant de 257 octets n'est plus une page vide).
4. **Ne pas borner l'Audit Service lui-même** dans cet incrément.

**Tests existants qui ont dû changer, par construction** : `TestGetRecording_ARefusalIsNotAServedRead` (ADR-0022) exigeait qu'un refus n'écrive rien ; il exige maintenant qu'un refus ne soit jamais écrit comme une lecture servie — ce que la règle amendée garde.

**Une erreur de ma part, corrigée** : la section d'ADR-0022 disait « Command Recorder interfaces +2 (1 → 3) » ; le paquet compte aussi les 2 tests d'appelants, c'était **3 → 5** (mesuré ici : 6 après le test ajouté par ADR-0024).

**Preuves.** `test/integration/recording_read_refusal_test.go` (deux tests : le parcours, sept sous-cas, et la configuration). Recorder application +6 (18 → 24), interfaces +1 (5 → 6). **25 mutations, toutes tuées** (une survivante réelle close par un test ; détail dans ADR-0024) ; rejeu d'ADR-0022 : 30 sur 30 applicables. Vérifié sur le code final : 582 unitaires sans base (46 ignorés), 628 avec ; 52 PostgreSQL ; 43 d'intégration sans base (6 ignorés), 49 avec ; `-race` propre (`pkg/refusalbudget`, Broker, Recorder, intégration des lectures) ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Le nombre exact de refus non écrits n'est pas enregistré.**
2. **Un jeton volé épuise le budget de son titulaire.**
3. **Chaque refus interroge l'Authorization Service** ; budget par processus.
4. **L'Audit Service ne borne toujours ni le corps ni les champs d'`emit-event`.**

## Borner ce que l'Audit Service prend dans la trace (ADR-0025)

Suite de la limite d'ADR-0024 (« l'Audit Service ne borne ni le corps ni les champs d'`emit-event` »), et de la policy §2.7 (« borne la taille des corps »). Pris sur la consigne « Tu peux poursuivre automatiquement » ; l'ADR est marqué « Accepté » sur elle — les choix sont les miens et peuvent être renversés.

**Mesuré avant** (processus réel, rouge) : corps de 1 Mio, action avec une espace ou des capitales, identifiant avec un saut de ligne, 257 octets — tous chaînés ; `GET` décodé ; messages du décodeur et du store renvoyés.

**Livré** : `validate` dans `AuditService.EmitEvent` avant tout verrou (action 1–64 `[a-z0-9_.]`, type 1–64 `[a-z0-9_]`, identifiant 1–256 et auteur 0–256 UTF-8 sans contrôle, `domain.ErrInvalidEvent`) ; `handleEmitEvent` : `POST` seulement, `MaxBytesReader` 16 Kio (`413`), `400` au message fixe ou nommant le champ, `500` générique et journalisé. Proto et `docs/api/grpc/README.md` : commentaires des bornes, aucun champ changé. Le Recorder (`usableSessionID`) refuse aussi un caractère de contrôle.

**Choix renversables** : un alphabet plutôt qu'une liste fermée d'actions ; refuser plutôt que tronquer ; ignorer (sans les stocker) les champs JSON inconnus.

**Preuves.** `test/integration/audit_bounds_test.go` (cinq sous-cas) ; Audit Service application +2 (5 → 7), interfaces +2 (1 → 3, avec les règles d'appelants). **24 mutations, toutes tuées** (deux survivantes closes par des tests ; détail dans ADR-0025). Vérifié : 586 unitaires sans base (46 ignorés), 632 avec ; 52 PostgreSQL ; 44 d'intégration sans base (6 ignorés), 50 avec ; `-race` propre ; `gofmt -l` vide.

**Trouvé pendant cet incrément, non corrigé ici :** `computeHash` concatène les champs **sans séparateur ni longueur** — un octet déplacé d'un champ au voisin laisse le hash inchangé, donc une modification rétroactive de cette forme n'est pas détectée ; et la chaîne n'a **pas de clé** : qui peut écrire en base peut recalculer toute la fin de la chaîne. Les documents affirmaient « toute altération d'un événement passé casse la chaîne » ; c'est faux dans ces deux cas. ADR-0026 traite le premier.

**Ce que cela ne fait PAS :**
1. **Un émetteur compromis écrit toujours des événements dans la forme, au nom de n'importe qui.**
2. **Le hash n'est pas canonique, et la chaîne n'a pas de clé** (voir ci-dessus).

## Un hash d'audit canonique et versionné (ADR-0026)

Suite du constat d'ADR-0025 (« `computeHash` concatène les champs sans séparateur »). Pris sur la consigne « Tu peux poursuivre automatiquement » ; l'ADR est marqué « Accepté » sur elle — les choix sont les miens et peuvent être renversés.

**Mesuré avant** (unitaire, rouge) : un octet déplacé entre deux champs voisins d'un événement stocké, sur les cinq frontières — 5 non détectés.

**Livré** : format 2 (étiquette `openbastion.audit.event.v2\x00`, chaque champ précédé de sa longueur sur 4 octets) pour tout événement écrit ; format 1 gardé pour vérifier ; `domain.Event.HashVersion` ; colonne `hash_version SMALLINT NOT NULL DEFAULT 1` ajoutée en place dans `001_init.sql` (additif, idempotent ; aucune table nouvelle, les `TRUNCATE` ne changent pas) ; `VerifyChain` refuse une version inconnue et une version qui recule. `docs/architecture/data-architecture.md` (colonne et rationale), `docs/security/`, README et ces notes corrigés : ils promettaient que « toute altération » est détectée.

**Choix renversables** : une longueur plutôt qu'un séparateur ; ne pas re-hacher l'histoire ; pas de clé dans cet incrément.

**Preuves.** `internal/application/canonical_hash_test.go` (+8 : les cinq frontières, nouveau format, chaîne héritée, versions qui reculent ou inconnues, version changée, vecteurs figés, pas de hash pour une version inconnue, hash vide) ; `TestPostgresStore_HashVersionRoundTrips` (PostgreSQL) ; `test/integration/audit_hash_format_test.go` (`TestPostgresFlow_…`, cinq sous-cas sur vraie base, mise à niveau en place). **14 mutations, toutes tuées** (trois survivantes closes par deux tests). Vérifié : 594 unitaires sans base (47 ignorés), 641 avec ; 54 PostgreSQL ; 44 d'intégration sans base (7 ignorés), 51 avec ; `-race` propre ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Les événements écrits avant restent au format 1**, sensibles au déplacement d'octets (asserté).
2. **La chaîne n'a pas de clé** : qui peut écrire en base peut recalculer toute la fin de la chaîne, et `verify-chain` la dira intègre.

## Une chaîne d'audit à clé, et l'émetteur de chaque événement (ADR-0027)

Bony Kiss a demandé les deux mécanismes contre la réécriture de la chaîne : une chaîne à clé (cet ADR) et un ancrage périodique hors de la base (ADR-0028). L'ADR est marqué « Accepté » sur cette demande ; les détails (format, identifiant de clé, rotation, émetteur dans le même format) sont mes choix et peuvent être renversés.

**Mesuré avant** (processus réel, vraie PostgreSQL, rouge) : une fin de chaîne réécrite et recalculée au format public — `200` ; démarrage avec base et sans clé.

**Livré** : format 3 (HMAC-SHA256, encadrement d'ADR-0026, émetteur et identifiant de clé couverts), seul format écrit ; `chain_keys.go` (`ParseChainKeys`, `RandomChainKeys`, `ChainKeyID`) ; `EmitEventAs` avec l'émetteur de `mtls.CallerFrom` ; `VerifyChain` par clé tenue ; colonnes `emitter` et `chain_key_id` ajoutées en place ; `AUDIT_CHAIN_KEY_HEX` obligatoire avec `DATABASE_URL`, `AUDIT_CHAIN_PREVIOUS_KEYS_HEX` pour la rotation. Guides Administrateur (configuration, sauvegarde, dépannage), PRA (la clé se sauvegarde à part), Sécurité, `docs/architecture/data-architecture.md` corrigés. Tests existants changés par construction : ceux d'ADR-0026 qui supposaient « le format courant est v2 », et les deux tests d'intégration qui démarrent l'Audit Service avec une base (ils fournissent maintenant une clé).

**Choix renversables** : HMAC plutôt qu'une signature asymétrique ; clé aléatoire en mémoire ; émetteur dans le même format.

**Preuves.** `test/integration/audit_chain_key_test.go` (`TestPostgresFlow_…`, quatre sous-cas) ; Audit Service application +7 (15 → 22), interfaces +1 (3 → 4), infrastructure : le test d'aller-retour relit aussi émetteur et clé. **21 mutations sur 21 tuées hors une équivalente** (une survivante close par un test). Vérifié : 602 unitaires sans base (47 ignorés), 649 avec ; 55 PostgreSQL ; 44 d'intégration sans base (8 ignorés), 52 avec ; `-race` propre ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. ~~**Une chaîne réécrite entièrement dans un format sans clé se vérifie** (ADR-0028 la trahit).~~ Refermé par ADR-0028 : `409` qui nomme l'ancre, sur processus réel.
2. ~~**La troncature de la fin de chaîne n'est pas vue par la clé seule** (ADR-0028, jusqu'à la dernière ancre).~~ Refermé par ADR-0028 jusqu'à la dernière ancre ; ce qui suit la dernière ancre reste exposé (ci-dessous).
3. **La clé est dans l'environnement du processus** ; une clé perdue rend l'histoire qu'elle a signée invérifiable.
4. **Pas de liste d'actions permises par émetteur.**

## Ancrer la tête de la chaîne d'audit hors de la base (ADR-0028)

Le second des deux mécanismes demandés par Bony Kiss. L'ADR est marqué « Accepté » sur cette demande ; le support (un fichier en ajout seul), la période par défaut et le format de l'ancre sont mes choix et peuvent être renversés.

**Mesuré avant** (processus réel, vraie PostgreSQL, rouge) : la chaîne entière réécrite depuis son premier événement au format v2 — `200` ; la fin de la chaîne coupée — `200` ; aucun fichier d'ancres demandé au démarrage.

**Un défaut trouvé en écrivant l'ancrage, avant de le livrer** : une ancre qui prenait la tête *telle que la base la donne* (`store.Last`) aurait validé une base falsifiée entre deux ancres. L'ancre nomme maintenant `tip`, le dernier événement que **ce processus** a écrit, avec le hash qu'il a calculé ; la base n'est lue qu'avant le premier ajout (un redémarrage).

**Livré** : `domain/anchor.go`, `application/anchors.go` (`Anchor`, MAC d'ancre étiqueté `openbastion.audit.anchor.v1`, `verifyAnchors`), `infrastructure/anchor_file.go` (`FileAnchorSink` : chemin absolu, 0600, ajout seul avec `fsync`, jamais recréé, ligne inconnue = erreur) ; `verify-chain` vérifie la chaîne contre ses ancres (`409` qui dit laquelle et pourquoi, `503` si elles sont illisibles) ; `AUDIT_ANCHOR_FILE` obligatoire avec `DATABASE_URL`, `AUDIT_ANCHOR_INTERVAL_SECONDS` (60 par défaut, 1 à 3600). Guides HA (Audit Service en instance unique, limite qui existait sans être écrite), Administrateur, PRA, Sécurité, `docs/architecture/data-architecture.md`, `architecture.md`, README. Tests existants changés par construction : les trois tests d'intégration qui démarrent l'Audit Service avec une base lui donnent un fichier d'ancres.

**Choix renversables** : un fichier plutôt qu'un service d'horodatage ou un stockage objet WORM (le port `AnchorSink` permet l'un ou l'autre sans toucher l'application) ; 60 s par défaut ; MAC sous la clé de chaîne plutôt qu'une clé à part.

**Preuves.** `test/integration/audit_anchor_test.go` (`TestPostgresFlow_TheChainIsAnchoredOutsideTheDatabase_ARewriteOrACutIsFound`, six sous-cas : configuration, réécriture entière, coupe, ancre modifiée, fichier disparu, une ancre par tête) ; Audit Service application +5 (22 → 27), infrastructure +4 (fichier d'ancres), interfaces +1 (4 → 5). **26 mutations : 24 tuées, 1 survivante équivalente (chemin vide) close par un test renforcé ; l'`fsync` retiré n'est observable par aucun test** (il ne se prouve qu'en coupant le courant). Vérifié : 612 unitaires sans base (47 ignorés), 659 avec ; 56 PostgreSQL ; 44 d'intégration sans base (9 ignorés), 53 avec ; `-race` propre ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Ce qui a été écrit depuis la dernière ancre peut être tronqué sans être vu** : la période est la fenêtre d'exposition.
2. **Qui écrit à la fois dans la base et dans le fichier d'ancres**, ou tient l'hôte de l'Audit Service (donc la clé), peut tout réécrire : la protection vaut la séparation des deux.
3. **Un fichier d'ancres vidé** (et non supprimé) ressemble à une installation neuve : seule une destination en ajout seul (WORM) l'empêche.
4. **L'Audit Service ne tourne qu'en une instance** : deux réplicas sur la même base feraient bifurquer la chaîne.

## Pas d'ORM (ADR-0029), et des migrations de schéma versionnées (ADR-0030)

Bony Kiss a choisi l'option A de l'analyse ORM (`docs/architecture/data-access-orm-analysis.md`) : l'accès aux données reste en `database/sql`, sans ORM (ADR-0029, Accepté). Il a ensuite donné son go pour ADR-0030. Deux règles ont été précisées avant le code, et l'ADR le dit : la clé de `schema_migrations` est `(component, version)` et le verrou est propre à chaque service, parce qu'en développement et en test **les six services partagent une seule base** — un fait du dépôt que le texte proposé ignorait.

**Mesuré avant** (rouge) : sur une base neuve, deux `psql` qui appliquent en même temps le schéma du Session Broker → l'un échoue dans 14 essais sur 20 ; puis sur processus réels, quatre Session Brokers démarrés ensemble, cinq tours → **15 réplicas sur 20 ne démarrent pas** (`postgres: pq: duplicate key value violates unique constraint "pg_type_typname_nsp_index"`, puis `log.Fatalf`).

**Livré** : `pkg/migrate` (nouveau module, bibliothèque standard seulement : `Load`, `Apply`, `LockKey`, `Result.Log`) ; dans les six services, `migrations.Files` (`embed.FS`, `*.sql`) remplace `migrations.InitSQL`, et `OpenPostgres` appelle `migrate.Apply` puis `res.Log`. `001_init.sql` n'a pas changé d'un octet : il est figé. `go.work`, `Makefile`, les sept `go.mod` concernés. `docs/architecture/data-architecture.md` (`schema_migrations`), guides Administrateur (§9 mise à jour, lire la version, revenir à un binaire précédent, trois lignes de dépannage), HA (réplicas qui démarrent ensemble), PRA (version des bases restaurées), Développeur, `.agents/architecture.md`, `.agents/tasks.md` §4 (le workflow « dans le même `InitSQL` » devient « une nouvelle migration numérotée »), README.

**Choix renversables** : migrations dans le binaire plutôt qu'un outil séparé ; une base plus récente que le binaire acceptée (avertissement) plutôt que refusée ; un verrou par service ; pas de migration descendante.

**Preuves.** `test/integration/schema_migrations_test.go` (processus réels : 20 réplicas sur 20 ; base d'avant ADR-0030 qui garde ses données et devient version 1 ; migration modifiée → refus de démarrer qui la nomme ; base plus récente → démarrage et `WARNING`) ; `test/integration/migrate_postgres_test.go` (6 tests PostgreSQL : 8 applicateurs × 20 tours sans échec, une fois et verrou relâché, six services qui créent la table ensemble, texte ou nom modifiés refusés, échec annulé et nommé, base en avance et services séparés) ; `pkg/migrate` 5 tests unitaires. **19 mutations : 18 tuées ; 1 équivalente (migration sur la connexion plutôt que la transaction, où `BEGIN` était déjà envoyé) remplacée par la vraie (aucune transaction), tuée par un test ajouté** (`TestPostgresMigrate_AMigrationAndItsRecordAreOne`). Vérifié : 617 unitaires sans base (47 ignorés), 664 avec ; 57 PostgreSQL ; 44 d'intégration sans base (17 ignorés), 61 avec ; `-race` propre sur `pkg/migrate` et les tests de migration et d'ancrage ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Pas de migration descendante** : revenir sur un schéma, c'est restaurer une sauvegarde.
2. **Une migration s'exécute en transaction** : pas de `CREATE INDEX CONCURRENTLY`.
3. **Une migration longue retarde le démarrage de tous les réplicas** du service, sous le verrou.
4. **Rien n'empêche d'écrire une migration non additive** : la règle « additive par défaut » est une règle de revue (`tasks.md` §4), pas un contrôle du code.
5. **Un schéma abîmé à la main n'est plus réparé au démarrage** (une table, une colonne ou un index supprimés) : la version 1 est enregistrée et n'est plus rejouée. Trouvé par la vérification complète : 25 tests PostgreSQL du Session Broker et un test d'intégration de l'Audit Service fabriquaient une « ancienne base » en retirant une colonne ou un index **sans** retirer la ligne de `schema_migrations` — ce qu'aucune vraie base d'avant ADR-0030 n'a. Ils retirent maintenant aussi cette ligne ; leurs affirmations n'ont pas changé.
6. Le partitionnement mensuel d'`audit_events` et `idempotency_keys` (`docs/architecture/data-architecture.md` §3) n'ont toujours pas d'équivalent dans le code ; ils ont maintenant une place (une migration numérotée).

## Pas de partitionnement d'`audit_events` (ADR-0031), la rétention d'abord (ADR-0032, proposé)

J'avais proposé comme étape suivante le partitionnement mensuel d'`audit_events` (`docs/architecture/data-architecture.md` §3). Je l'ai mesuré avant de l'écrire, sur PostgreSQL 16, dans un schéma jetable :
- `UNIQUE (id)` et `PRIMARY KEY (seq)` sont refusés sur une table partitionnée par `ts` ; avec `UNIQUE (id, ts)`, le même identifiant entre deux fois, dans deux mois ;
- une insertion hors de toute partition échoue, et l'audit est fail-closed ;
- la conversion prend 41 s par million d'événements, sous le verrou de migration ;
- `verify-chain` lit la chaîne 2,3 fois plus lentement (1,0 s → 2,3 s pour un million d'événements) ;
- et retirer une vieille partition casse la chaîne et les ancres, exactement comme retirer des lignes.

J'ai donc arrêté et demandé. Bony Kiss a choisi « la rétention d'abord » : ADR-0031 (Accepté) écarte le partitionnement ; ADR-0032 (**Proposé**, aucun code) conçoit une rétention par mois entiers vérifiés, archivés hors de la base, avec un point de contrôle sous la clé de chaîne ajouté au fichier d'ancres, d'où `verify-chain` repart. Deux documents étaient faux et sont corrigés (barrés) : le `docs/security/audit-integrity.md` (« archiver par partition plutôt que par ligne n'affaiblit pas la chaîne » — les deux la cassent ; et « la chaîne n'a pas de clé », périmé depuis ADR-0027) ; le `docs/architecture/data-architecture.md` dit maintenant que son DDL d'`audit_events` est une cible, pas le schéma réel. Le commentaire en tête de `001_init.sql` annonce encore le partitionnement : il **n'est pas corrigé**, parce que ce fichier est figé (ADR-0030, son checksum est en base) — c'est l'ADR qui fait foi.

## Une rétention de l'audit qui garde la chaîne vérifiable (ADR-0032)

Bony Kiss a donné son go pour ADR-0032, et demandé de continuer l'implémentation du MVP sans s'arrêter, sauf pour une validation. Trois précisions faites en écrivant le code, écrites dans l'ADR : `prev_hash` dans le point de contrôle (la série des points est chaînée) ; l'événement `audit.archived` écrit à la reprise s'il manque ; un lien (`link`) plutôt qu'un renommage pour mettre l'archive en place, parce qu'un renommage remplace un fichier existant.

**Mesuré avant** (rouge, sur `HEAD` dans un worktree jetable, processus réel, vraie PostgreSQL) : le service démarrait avec `AUDIT_ARCHIVE_DIR` seule (rien ne la lisait), et une chaîne de janvier et février 2025 restait en base — rien d'archivé en 10 s.

**Livré** : `application/archive.go` (`Archiver`, `WithArchive`, `ArchiveDue`, `checkpointMAC`, `startOfChain`, `checkpointsAgree`), `VerifyChain` qui repart du point de contrôle dont le `last_hash` est le `prev_hash` du premier événement ; `domain.Checkpoint`, `domain.ErrArchiveRefused` ; `infrastructure/archive_file.go` (`FileArchiver`) ; le fichier d'ancres lit et écrit des lignes `kind: checkpoint`, **les lignes d'ancre gardent leur format au caractère près** ; `Store.DeleteThrough` (mémoire, PostgreSQL : une transaction, le nombre exact ou rien) ; `main.go` (`AUDIT_ARCHIVE_DIR`, `AUDIT_RETENTION_MONTHS`, `archiveEvery`). `EmitEventAs` date l'événement avec l'horloge du service (`s.now`, `time.Now` en production) au lieu de `time.Now()` direct, pour les tests. Guides Administrateur (section rétention, sauvegarde, trois lignes de dépannage), PRA, Sécurité §9 et §12, `docs/architecture/data-architecture.md`, `architecture.md`, README.

**Choix renversables** : un mois civil comme unité ; une passe au démarrage puis toutes les heures ; les points de contrôle dans le fichier d'ancres ; l'archive en JSON lines.

**Preuves.** `test/integration/audit_retention_test.go` (`TestPostgresFlow_OldMonthsAreArchivedOutOfTheDatabase_AndTheChainStillVerifies` : huit configurations refusées ; deux mois archivés au démarrage, 3 et 2 événements, deux `audit.archived` de l'Audit Service, `verify-chain` `200` ; le premier événement restant supprimé → `409` ; le point de contrôle de février retiré → `409`) ; Audit Service application +15 (27 → 42), infrastructure +6 (dont 1 PostgreSQL : `DeleteThrough`). **31 mutations : 29 tuées (dont 3 par des tests ajoutés après coup), 1 équivalente retirée du code, 1 non prouvable** (relecture de l'archive). Vérifié : 637 unitaires sans base (48 ignorés), 685 avec ; 59 PostgreSQL ; 44 d'intégration sans base (18 ignorés), 62 avec ; `-race` propre sur l'Audit Service, `pkg/migrate` et les tests de rétention, d'ancrage et de migration ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Pas encore d'outil pour vérifier une archive hors ligne** (du `last_hash` du point de contrôle précédent au sien, avec la clé).
2. **Qui tient la clé peut écrire un point de contrôle** : même limite qu'ADR-0028.
3. **Un binaire d'avant ADR-0032 ne lit pas un fichier d'ancres qui contient des points de contrôle** (`409` « not an anchor »).
4. **Une horloge qui recule à cheval sur deux mois arrête l'archivage** (second segment du même mois refusé, « never overwritten ») — rien n'est perdu, rien ne part.
5. **Une archive détruite n'est plus consultable** ; sa destruction relève du stockage.

## Un déploiement `docker-compose` reproductible et le premier outil du CLI (ADR-0033)

Troisième critère de sortie du MVP (`docs/roadmap.md` §2), qui n'avait rien dans le dépôt. ADR « Accepté » sur la consigne de Bony Kiss de continuer l'implémentation du MVP ; les choix (une image, distroless, Compose plutôt que des binaires construits sur l'hôte, une cible SSH maison) sont renversables.

**Mesuré avant** : aucun `deploy/`, aucune image, aucun moyen de créer le premier utilisateur sans écrire une requête mTLS à la main (`POST /auth/v1/users` n'accepte que `admin-cli`, que rien ne portait).

**Livré** : `deploy/docker-compose/` (`Dockerfile`, `docker-compose.yml`, `init.sh`, `pki.sh`, `postgres-init.sh`, `README.md`) ; `cli/openbastion-cli` (nouveau module, stdlib + `pkg/mtls` : `user create`, `audit verify-chain`) ; `test/integration/cmd/demo-ssh-target` ; `test/integration/compose_test.go` ; `make test-compose` ; `go.work`, `Makefile`, `.dockerignore`. Guides Administrateur (§2 installation, §8 sauvegarde du `.env`), `.agents/architecture.md`, `.agents/settings.md` §7, `AGENTS.md`, README.

**Trouvé en chemin** :
1. **En le concevant** : monter le répertoire de certificats tel que `make pki` le produit aurait donné à chaque service la clé de l'autorité et celles des autres. L'autorité vit dans un volume monté par le seul job `pki` ; chaque service monte son sous-répertoire (`subpath`).
2. **En le lançant** : `authorization` est un mot réservé de PostgreSQL (`CREATE ROLE authorization` échoue, et les bases suivantes ne sont pas créées) — identifiants entre guillemets.
3. **En testant** : sonder la disponibilité par des connexions répétées épuise le budget de connexion par adresse de la Gateway (ADR-0014, 5 puis 1 par minute) — le test attend les lignes « listening ».
4. **Mon seuil deviné était faux** : « au moins 5 événements d'audit » ; le parcours en écrit **3** (`session.create`, `session.connect`, `recording.read`) — l'affirmation est maintenant cette suite exacte.
5. **Environnement** : dans ce codespace, deux conteneurs d'un même réseau Compose ne se joignent pas (une table `iptables-legacy` en `FORWARD DROP` qui n'accepte que `docker0`). Ma première tentative d'ajouter une règle a été refusée ; Bony Kiss l'a autorisée. Règle posée pour les tests (`-I FORWARD 1 -i br-+ -o br-+ -j ACCEPT`), **retirée ensuite** (`-D`), état d'origine vérifié.

**Preuves.** `TestCompose_TheMVPJourneyOnARealDockerComposeStack` (58 s, huit sous-cas) ; CLI : 2 tests unitaires (onze refus avant le réseau, pas d'appel sans mTLS). **11 contre-épreuves sur le déploiement, 11 tuées** (Recorder, Vault, Audit en mémoire ; clé de l'autorité aux services ; Authentication publié ; Gateway sans mTLS ; amorce de démonstration ; bases ouvertes à tous ; publication sur toutes les interfaces ; `init.sh` qui écrase ; `.env` lisible). Vérifié : 639 unitaires sans base (48 ignorés), 687 avec ; 59 PostgreSQL ; 63 tests d'intégration — 44 passent sans base (19 ignorés), 62 avec (1 ignoré : le test Compose, qui demande `COMPOSE_TEST=1` et passe à part, `make test-compose`) ; `-race` propre ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **PostgreSQL en clair sur le réseau Compose** (`sslmode=disable`).
2. ~~**Images non épinglées par empreinte** : reproductible pour le code (`go.sum`), pas pour les images de base.~~ — fermé par ADR-0051.
3. **Une instance de chaque service** ; pas de Helm (`docs/development/repository-structure.md` §6 : cible, pas écrite).
4. **Le CLI ne fait que l'amorçage** ; politiques, comptes, sessions passent par l'API publique.
5. **Les certificats expirent après 720 h** si personne ne relance `up` (rien ne surveille l'échéance).
6. **L'amorce de démonstration de l'Authentication Service existe toujours hors Compose** (`demo-dba` / `demo-password` sans `SKIP_DEMO_SEED`) : Compose la coupe, le binaire la garde par défaut.

## Les expirations dans la trace : le Scheduler du MVP (ADR-0034)

Le Scheduler du MVP n'a qu'une tâche, l'expiration des sessions (`docs/roadmap.md` §2). Le proxy coupait déjà une connexion ouverte à l'échéance (`session.expire`) ; une session accordée et jamais connectée, ou une demande break-glass jamais décidée, expirait **sans trace**, et la base disait `active` pour toujours. Fait dans le Broker plutôt que dans un service à part (renversable : la tâche ne touche que ses lignes).

**Mesuré avant** (rouge, vrai Broker, vraie PostgreSQL) : `SESSION_EXPIRY_SWEEP_SECONDS=0` acceptée ; rien d'expiré en base en 10 s ; aucun événement.

**Livré** : `application/session_expiry.go` (`ExpireDue`, `ExpiryAuditGrace` 30 s, `ExpirySweepTimeout` 10 s) ; `ExpireDue`, `ExpiriesToAudit`, `MarkExpiryAudited` au port `SessionRepository` (mémoire et PostgreSQL) ; `migrations/002_session_expiry.sql` — **la première migration numérotée d'ADR-0030** ; `main.go` (`SESSION_EXPIRY_SWEEP_SECONDS`, `expireEvery`). `docs/architecture/data-architecture.md`, guides Administrateur et Sécurité, `architecture.md`, README.

**Deux défauts trouvés par les tests, avant de livrer** : `UPDATE … RETURNING` rend les lignes dans un ordre quelconque, le port promet l'échéance la plus proche d'abord (trié par une CTE) ; un service construit sans horloge faisait planter le Broker au premier balayage (`s.now` nil — c'est le test d'intégration qui l'a vu, un test unitaire le garde maintenant).

**Preuves.** `test/integration/session_expiry_test.go` (`TestPostgresFlow_SessionsPastTheirEndAreExpiredOnce_AndTheExpiryIsAudited`, cinq sous-cas) ; Broker application +4, infrastructure +3 (contrat mémoire et PostgreSQL, course de huit balayeurs sur 300 sessions). **12 mutations, 12 tuées.** Vérifié : 644 unitaires sans base (50 ignorés), 694 avec ; 62 PostgreSQL ; 64 tests d'intégration — 44 passent sans base (20 ignorés), 63 avec (le test Compose à part) ; `-race` propre sur le test d'expiration et celui des migrations. Le test d'ADR-0030 qui attendait « schema migrations [1] applied » attend maintenant `[1 2]` : changé par construction, et c'est la preuve que `002` s'applique à une base d'avant.

**Ce que cela ne fait PAS :**
1. **Une panne entre l'événement et sa marque peut doubler `session.expire`** (au moins une fois, voulu).
2. **L'expiration d'une demande n'est notifiée à personne** (le webhook d'ADR-0012 ne part pas).
3. **Entre l'échéance et le balayage**, la base dit encore `active` ; le Broker répond déjà `expired`.
4. **Le test Compose n'a pas été relancé** pour cet incrément (il demande la règle de pare-feu du codespace, retirée) ; rien de Compose n'a changé.

## La connexion fédérée OIDC (ADR-0035)

Bony Kiss a choisi la règle des rôles (une table déclarée des groupes vers les rôles) et une implémentation sans dépendance nouvelle (stdlib et `golang-jwt`). ADR-0007 (Keycloak comme IdP de plateforme) n'est pas contredit : l'Authentication Service est un client OIDC de n'importe quel fournisseur conforme, Keycloak compris, et reste le seul émetteur des jetons.

**Mesuré avant** (rouge, sur `HEAD` dans un worktree jetable) : une configuration OIDC à moitié faite était ignorée (le service démarrait), aucune route de connexion fédérée.

**Livré** : `internal/infrastructure/oidc_provider.go` (découverte, JWKS RSA ≥ 2048 et EC P-256, URL d'autorisation PKCE S256, échange du code avec le secret du client, vérification du jeton d'identité) ; `internal/application/oidc.go` (`StartOIDC`, `FinishOIDC`, `RoleMap`, `LoadRoleMap`) ; `domain.User` porte `IdentitySource`/`ExternalSubject`, `LoginAttemptRepository` ; magasins mémoire et PostgreSQL ; `migrations/002_oidc.sql` ; routes internes `/auth/v1/oidc/start|callback` (réservées à `api-gateway`) ; Gateway : `POST /auth/oidc/start`, `POST /auth/oidc/callback` dans le budget de connexion ; `main.go` (tout ou rien). OpenAPI, guides Administrateur (§6 et dépannage) et Sécurité, `docs/architecture/data-architecture.md`, `architecture.md`, `TRUNCATE` du `Makefile` et de `settings.md` (`oidc_login_attempts`), README.

**Trouvé en chemin** :
1. **Le magasin mémoire de l'Authentication Service rendait l'objet qu'il garde** : un appelant qui modifiait l'utilisateur lu modifiait le magasin, ce que PostgreSQL ne fait pas. Une mutation (« rôles non enregistrés à la connexion ») survivait grâce à lui. Il rend maintenant des copies.
2. **Une connexion fédérée prend deux fois dans le budget de connexion par adresse** (ADR-0014) : vu par le test, qui atteignait `429` au bout de trois connexions ; c'est voulu (les deux routes sont publiques), et écrit.
3. Mes premiers tests de l'application figeaient l'horloge à midi alors que le jeton se vérifie sur l'horloge réelle : le jeton « expirait » avant d'être lu. Corrigé dans le test.

**Preuves.** `test/integration/oidc_flow_test.go` (neuf sous-cas, fournisseur joué par le test, RS256 en stdlib) ; Authentication infrastructure +6 (client OIDC : jeton valide RS256 et ES256, **20 jetons forgés ou mal adressés refusés**, rotation et rythme de relecture des clés, PKCE et secret du client, fournisseur refusé ; PostgreSQL : comptes fédérés et 20 retours simultanés pour un seul `state`), application +6. **21 mutations, 21 tuées.** Vérifié : 655 unitaires sans base (51 ignorés), 706 avec ; 64 PostgreSQL ; 65 tests d'intégration — 44 passent sans base (21 ignorés), 64 avec (le test Compose à part) ; `-race` propre sur l'Authentication Service, la Gateway et le test OIDC ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Un rôle retiré chez le fournisseur reste dans le jeton OpenBastion jusqu'à son expiration** (1 h).
2. **Ni déconnexion fédérée, ni jeton de rafraîchissement** du fournisseur.
3. **Les connexions ne sont pas des événements d'audit** (locales non plus).
4. **La table des rôles n'est relue qu'au démarrage.**
5. ~~**Pas de page de retour** : `OIDC_REDIRECT_URL` doit être une page qui renvoie `code` et `state` à `/auth/oidc/callback` — ce sera l'Admin UI (incrément suivant).~~ **Levé par ADR-0036** : `/ui/oidc/callback`.
6. **Compose ne configure pas OIDC** (les variables et la table sont à ajouter au service `authentication`).

## L'Admin UI (ADR-0036)

Bony Kiss a choisi React, Vite et TypeScript, et avec eux les dépendances npm. L'interface ne parle qu'à l'API publique de la Gateway, qui la sert sous `/ui/` (même origine : aucune origine à ouvrir).

**Mesuré avant** : rien sous `web/` ni sous `/ui/` (`404`).

**Livré** : `web/admin-ui/` (connexion locale et OIDC avec la page de retour `/ui/oidc/callback`, comptes privilégiés, création de politiques, demandes d'urgence à décider, session par identifiant et terminaison, relecture d'un enregistrement) ; Gateway `internal/interfaces/ui.go` (`NewUIHandler`, `WithUI`) et `ADMIN_UI_DIR` ; image Compose avec une étape Node (`npm ci`) ; `make ui-test`, `make ui-build` ; README de l'interface, guides Administrateur et Sécurité, `architecture.md`, `AGENTS.md`.

**Mesures des dépendances** : 3 paquets à l'exécution (`react`, `react-dom`, `scheduler`), 94 avec les outils de construction et de test, versions exactes, `package-lock.json` commité ; `npm audit` : 0 vulnérabilité connue (30 octobre 2026). `jest-dom` n'a pas été pris : les tests comparent le texte.

**Trouvé en chemin** : `http.ServeFile` redirige `…/index.html` vers `…/` — la page est servie par `http.ServeContent`. Le test Compose a été relancé avec la règle de pare-feu du codespace, posée puis retirée comme la première fois.

**Preuves.** UI : 17 tests (Vitest) ; Gateway : 4 tests du service de `/ui/` ; Compose : l'interface servie avec ses en-têtes (105 s, avec ADR-0034 et ADR-0035 dans la pile). **12 contre-épreuves, 12 tuées.** Vérifié : 659 unitaires Go sans base (51 ignorés), 710 avec ; 64 PostgreSQL ; 65 d'intégration (64 avec la base, le test Compose à part — et passé, 105 s) ; 17 tests de l'interface (Vitest) ; `-race` propre ; `gofmt -l` vide ; `tsc --noEmit` propre.

**Ce que cela ne fait PAS :**
1. **Pas de test dans un vrai navigateur** (Playwright demanderait des navigateurs téléchargés) : jsdom et Go seulement.
2. **Recharger la page déconnecte** (jeton en mémoire, voulu).
3. **Pas de liste des politiques ni des événements d'audit** : l'API publique n'en a pas.
4. **Pas de traduction** : l'interface est en français.

## Constaté : la rotation d'un secret ne touche pas la cible

En faisant le point sur le périmètre MVP (`docs/roadmap.md` : « rotation manuelle et post-usage »), j'ai lu `VaultService.Rotate` : il tire un secret, l'enregistre comme nouvelle version — **et rien ne le pose sur la cible**. Aucun composant ne change un mot de passe sur une cible (`grep passwd chpasswd` : rien). Après une rotation, le Vault injecte un mot de passe que la cible refuse : **le compte devient inutilisable**. `post_use` et `scheduled` sont acceptés et enregistrés, et rien ne les exécute. `docs/administration/` présentait la rotation comme fonctionnelle.

Fait tout de suite : le bouton « Renouveler le secret » que l'Admin UI (ADR-0036) venait d'ajouter est **retiré** (un test vérifie qu'il n'y est plus) ; le `docs/administration/privileged-accounts.md` et `docs/security/known-limitations.md` disent la limite. ~~**Non fait** : appliquer la rotation sur la cible — une décision de conception (avec quel compte la cible est-elle modifiée, comment on sait que c'est fait, que faire d'une rotation à moitié faite), soumise à Bony Kiss.~~ **Refermé par ADR-0037** (section suivante) ; le bouton est revenu.

## La rotation atteint la cible (ADR-0037)

Bony Kiss a choisi le modèle du compte de réconciliation. Un défaut de plus trouvé en concevant : l'ancienne rotation remplaçait la version courante **avant** d'écrire la nouvelle, hors transaction — une panne entre les deux laissait un compte sans secret courant ; la version en attente et sa promotion en une transaction le ferment.

**Mesuré avant** (rouge, sur `HEAD`, huit processus réels et une vraie cible SSH) : après une rotation, l'ancien mot de passe ouvrait encore la cible, et la session suivante échouait ; sans compte de réconciliation et l'audit coupé : `202`.

**Livré** : Vault — `application/rotation.go` (`RotateAs`, `RotateAfterUse`, `settlePending`, `OnboardAccountWithReconciliation`, `SetReconciliationAccount`), `infrastructure/ssh_target.go` (`chpasswd`, `sudo -S`), `infrastructure/audit_client.go`, `migrations/002_rotation.sql`, magasins (version en attente, promotion en une transaction), routes (`reconciliationAccountId`, `actorId`, `/vault/v1/rotate-after-use` réservée au Broker), `AUDIT_URL` ; `golang.org/x/crypto` ajouté au module (même version et miroir que le proxy, `go.sum` régénéré par `go mod tidy`). Broker — `after_use.go` (terminaison et expiration d'une session accordée). Gateway — `actorId`. Audit — le Vault peut émettre. Admin UI — le bouton revient, avec le champ du compte de réconciliation. Compose — `AUDIT_URL` du Vault. OpenAPI, guides Administrateur (§4 et dépannage) et Sécurité, `docs/architecture/data-architecture.md`, `architecture.md`.

**Trouvé en chemin** : j'ai d'abord ajouté des lignes à `go.sum` à la main, ce que la politique interdit — rétabli, puis régénéré par `go mod tidy`. Le test Compose d'ADR-0033 échouait **une fois sur deux** : au redémarrage, la connexion ouverte par le test est coupée et le proxy écrit parfois `session.terminate` avant l'arrêt de l'audit ; l'affirmation exigeait une trace sans cet événement légitime — elle exige maintenant la trace d'avant intacte en tête et la nouvelle lecture en dernier (trois passes sur trois). Deux tests modifiés par moi lançaient l'Audit Service sur le port d'un autre processus.

**Preuves.** `test/integration/rotation_flow_test.go` (huit processus, cible SSH à mots de passe changeants : rotation manuelle, après usage, sans réconciliation, audit coupé, acteurs) ; Vault application +8, infrastructure +3 (dont 1 PostgreSQL) ; Broker +1 ; Admin UI +1. **17 mutations, 17 tuées.** Compose relancé (trois passes vertes, règle de pare-feu posée puis retirée). Vérifié : 670 unitaires Go sans base (52 ignorés), 722 avec ; 65 PostgreSQL ; 66 d'intégration (65 avec la base, Compose à part — vert) ; 18 tests de l'Admin UI ; `-race` propre sur le Vault, le Broker et le test de rotation ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. ~~**La clé d'hôte de la cible n'est pas vérifiée** (comme par le proxy).~~ **Refermé par ADR-0039** : le Vault ne se connecte qu'à la clé épinglée du compte (`ssh.FixedHostKey`), et un compte sans clé n'est pas renouvelé.
2. ~~**`scheduled` n'est exécuté par rien.**~~ **Refermé par ADR-0040** : le Vault balaie et fait tourner les comptes planifiés échus.
3. ~~**Une rotation après usage échouée n'est pas réessayée.**~~ **Refermé par ADR-0044** : dette enregistrée au Broker et au Vault, renvoyée et payée jusqu'au bout.
4. **Quelques secondes** entre la pose et la promotion où une nouvelle connexion reçoit l'ancien secret.
5. **Les comptes de réconciliation eux-mêmes ne tournent que si on leur en donne un** (un `root` qui se réconcilie lui-même est refusé).

## SFTP et SCP à travers le proxy (ADR-0038)

Bony Kiss a choisi d'enregistrer chaque transfert (sens, chemin, taille, SHA-256, pas le contenu) et `github.com/pkg/sftp` **v1.13.7** dans les tests seulement — la plus récente compatible avec `golang.org/x/crypto` v0.24 du dépôt (v1.13.8 demande v0.31) ; ajoutée par `go get`, `x/crypto` reste v0.24 ; elle tire `kr/fs`.

**Commits faits pendant ce travail, hors de moi** : le propriétaire a committé et poussé mon travail SFTP **en cours** (`ef94fbb`, à 16 h 57, avant les corrections de cet après-midi), puis un environnement de développement Base44 (`0b0dc77`, `1e24491`, la PR n° 1, `1f043c7`). `0b0dc77` corrige **un vrai défaut de l'Admin UI que j'avais livré** (ADR-0036) : la valeur par défaut `api = new Api()` du composant `App` était recréée à chaque rendu, le jeton posé à la connexion se perdait, et tous les appels suivants partaient sans en-tête (`401`) ; mes tests passaient tous un `api` explicite et ne le voyaient pas. La correction (`main.tsx`) est gardée ; j'ai de plus rendu le client de `App` stable lui-même (`useRef`) et ajouté le test qui le voit (une contre-épreuve le confirme). Le rouge-avant d'ADR-0038 est mesuré sur `da1180b`, le commit qui précède `ef94fbb`. L'arbre de travail montre `.agents/skills.md` revenu et `.agents/skills/open-bastion/SKILL.md` absent (renommé par `1f043c7`, contenu identique) : je n'y ai pas touché et ne l'ai pas committé.

**Mesuré avant** (rouge) : `sftp`, `scp` et `scp -O` à travers le proxy échouaient (seul le shell était accepté).

**Livré** : `pkg/proxycore` `RecordingTap.RecordEvent` ; `sshcodec/sftp.go` (SFTP v3 lu dans les deux sens, enregistrement avant transmission, empreinte par fichier) ; `sshcodec/scp.go` (`ParseSCPCommand`, `scpStream`) ; `codec.go` (modes, statut de sortie puis fermeture du canal) ; `ssh_server.go` (attente de la première demande : shell, `sftp`, `scp` accepté — rien d'autre). Guides Administrateur (§4 et dépannage) et Sécurité, `architecture.md`, README.

**Trouvé en chemin** : `sftp -b` (mode batch) désactive l'authentification par mot de passe — les commandes passent par l'entrée standard ; ma cible de test bloquait (`exec.Cmd` avec `Stdin` sur le canal attend la fin du canal, puis le tube d'entrée n'était pas fermé) ; `CombinedOutput` attend une sortie que garde ouverte le `ssh` lancé par `scp` (`WaitDelay`) ; le chemin SCP enregistré joignait à tort la destination et le nom ; le proxy fermait seulement l'écriture du canal et attendait 5 s ; un `pkill -f` a tué mon propre shell (code 144) — les orphelins de passes interrompues sont depuis arrêtés par PID, après les avoir listés.

**Preuves.** `test/integration/transfer_flow_test.go` (huit processus, OpenSSH 9.6 : `sftp`, `scp`, `scp -O` dans les deux sens, `exec` refusé, relecture par un auditeur avec les empreintes) ; ssh-proxy `sshcodec` +9 ; `pkg/proxycore` +1 ; Admin UI +1. **17 mutations, 17 tuées** ; Admin UI 1 contre-épreuve tuée. Compose relancé (vert, règle posée puis retirée). Vérifié : 680 unitaires Go sans base (52 ignorés), 732 avec ; 65 PostgreSQL ; 67 d'intégration (66 avec la base, Compose à part) ; 19 tests de l'Admin UI ; `-race` propre sur le proxy, `pkg/proxycore` et le test de transfert ; `gofmt -l` vide.

**Ce que cela ne fait PAS :**
1. **Le contenu des fichiers n'est pas gardé** (choix).
2. **Un téléchargement est enregistré à la fermeture**, ses octets déjà chez le client (l'ouverture l'est avant).
3. **Pas d'empreinte pour un transfert non contigu** (parallèle) — la taille, si.
4. **Pas d'`exec` arbitraire, pas de `rsync`, pas de redirection de ports** : refusés.
5. ~~**La clé d'hôte de la cible n'est toujours pas vérifiée.**~~ **Refermé par ADR-0039** (section suivante) : le proxy n'envoie le mot de passe qu'à la clé épinglée au Vault.

## La clé d'hôte de chaque cible est épinglée (ADR-0039)

Demandé par Bony Kiss : « épingler la clé d'hôte de chaque cible (enregistrée au Vault, vérifiée par le proxy et le Vault), car c'est la seule protection contre quelqu'un qui s'interpose et lit les secrets en transit ».

**Mesuré avant** (rouge, sur 2e9166f) :
- un serveur qui présente une autre clé à l'adresse de la cible reçoit le mot de passe `the-target-root-password`, et le relais répond `nil` ;
- `SSHTargetChanger` (rotation) se connecte en `root` à des cibles dont il n'a jamais vu la clé : son propre test le faisait, avec une clé aléatoire par cible.

**Livré** :
- Vault :
  - `application/hostkey.go` : `NormalizeHostKey`, `OnboardPinned`, `SetHostKey` (RBAC `vault:account:pin`, `vault.host_key_set` avant le changement), `Delivered` ;
  - `AuthorizeScope`, `FetchCredential` et la rotation refusent un compte sans clé (`ErrNoHostKey`, `409`) ;
  - `ssh_target.go` : `ssh.FixedHostKey` ;
  - `migrations/003_host_key.sql` et les deux magasins ;
  - `PUT /vault/v1/accounts/{id}/host-key` ; `fetch-credential` rend `target_host` et `host_key` ; le compte rend `hostKey` et `hostKeyFingerprint`.
- `pkg/proxycore` : `Fetched`, `Credential.TargetHost` et `HostKey`, `ErrHostKeyMismatch`, `EmitHostKeyMismatch` (`session.host_key_mismatch`).
- ssh-proxy :
  - `codec.go` : le mot de passe ne part qu'à la clé épinglée, et l'adresse de session doit être celle du Vault ;
  - `ssh_server.go` : l'adresse passée au codec, et le message à l'opérateur ;
  - `vault_client.go`.
- Gateway : `PUT /vault/accounts/{id}/host-key`, où seule la clé vient du client.
- Admin UI : colonne « Clé d'hôte » (empreinte, ou « non épinglée »), « Épingler / Changer la clé d'hôte », champ obligatoire à l'enregistrement.
- Démonstration : `demo-ssh-target` a une clé stable, dérivée de son mot de passe, et l'écrit dans son journal ; le test Compose l'y relève. Les seeds (`acc_demo`, Vault et Base44) épinglent une clé dont la moitié privée a été jetée à sa création : la cible est fictive, aucune machine ne recevra ce secret.

**Trouvé en chemin** :
- Le repli `known_hosts` de `NormalizeHostKey` était du **code mort** : une mutation l'a montré. `ParseAuthorizedKey` lit déjà les noms d'hôtes en tête de ligne comme des « options ». Je l'ai retiré, et j'ai ajouté le refus de `@revoked` / `@cert-authority` : `@revoked <clé>` était accepté.
- Le journal du ré-épinglage affichait la **nouvelle** empreinte comme ancienne : le magasin mémoire rend son propre enregistrement, et l'ancienne valeur était lue après l'écriture. Elle est maintenant lue avant.
- La rotation d'un compte sans clé répondait `403` au lieu de `409` (`adminErrorStatus` ne connaissait pas l'erreur), et `authorize-scope` aussi.
- `TestPostgresStore_PendingVersion_Lifecycle` (ADR-0037, de moi) utilisait un nom et un hôte fixes : il échouait au deuxième passage sur une base qui garde ses lignes (unicité `(target_host, name)`). Il prend maintenant l'identifiant comme nom.

**Choix renversables** :
- La comparaison d'adresse est une égalité de chaînes : le Broker transmet l'adresse que le Vault lui a donnée.
- ~~L'enregistrement et l'épinglage sont deux écritures. Si la seconde échoue, le compte reste sans clé : inutilisable, donc sûr.~~ Refermé par ADR-0040 : le compte est écrit en une fois.
- ~~Le motif d'un `409` n'est pas relayé par le Broker : l'opérateur lit « authorize-scope: status 409 ».~~ Refermé par ADR-0042 : l'opérateur lit que le compte doit être épinglé, et par qui.

**Preuves** :
- `test/integration/hostkey_flow_test.go`, huit processus et le vrai client OpenSSH :
  - un imposteur à l'adresse de la cible reçoit **zéro** mot de passe ;
  - l'opérateur est prévenu et `session.host_key_mismatch` est audité ;
  - un opérateur ne ré-épingle pas (`403`) ;
  - un administrateur ré-épingle, l'audit l'attribue au nom du jeton, et la session suivante passe ;
  - un enregistrement sans clé, avec une clé vide, illisible ou privée : `400`.
- Tests unitaires ajoutés :
  - Vault application +4 ;
  - Vault infrastructure +2, dont 1 PostgreSQL ;
  - Vault interfaces +1 ;
  - `pkg/proxycore` +1 ;
  - `sshcodec` +4, dont un à travers le vrai `SSHServer` ;
  - Gateway +1 ;
  - Admin UI +2.
- **25 mutations, 25 tuées.** Deux survivaient d'abord :
  - le repli `known_hosts`, code mort, retiré ;
  - « rotation sans clé = `403` » : mon test HTTP passait par un compte sans réconciliation, qui répond déjà `409` pour cette raison. Il a maintenant un compte de réconciliation et exige le motif.
- Une race dans **mon** test (un même `bytes.Buffer` lu et écrit par les deux goroutines du relais), trouvée par `-race` et corrigée ; le paquet passe sous `-race`.

**Ce que cela ne fait PAS :**
1. **La clé vaut ce que vaut la façon dont on l'a relevée** : relevée par le réseau qu'on veut protéger, elle peut déjà être celle de l'imposteur. Le guide d'administration dit de la relever sur la cible.
2. **Une seule clé par compte**, et pas d'autorité de certificats SSH.
3. **Une cible qui change de clé refuse les sessions** jusqu'au ré-épinglage : c'est voulu, et c'est une panne si personne ne la prévoit.
4. **Les comptes enregistrés avant ADR-0039 n'ouvrent plus de session** tant qu'ils ne sont pas épinglés : c'est une opération de mise à jour.

## Instructions des agents réorganisées par thème

Demandé par Bony Kiss, qui a donné l'arborescence. Les sept fichiers plats de `.agents/` (`architecture.md`, `personas.md`, `policies.md`, `rules.md`, `settings.md`, `tasks.md`, et `skills.md`, qui avait remplacé `.agents/skills/open-bastion/SKILL.md` dans sa copie de travail) sont répartis en un fichier par sujet :

| Ancien | Nouveau |
|---|---|
| `architecture.md` §1–§9 | `.agents/architecture/` : `README.md` (produit, où est la vérité), `invariants.md`, `repository-layout.md`, `service-pattern.md`, `service-identities.md`, `transport-and-contracts.md`, `data.md`, `known-gaps.md` — découpés section par section, sans perte |
| `policies.md` (+ `rules.md` §5) | `.agents/policies/` : onze fichiers (sécurité, développement sûr et fichiers protégés, secrets, autorisation, cryptographie, audit, données, tests et honnêteté, dépendances, licence, livraison) ; « quand demander » et le vocabulaire dans `AGENTS.md` |
| `rules.md` | `.agents/rules/` : dix fichiers, dont `completion-gates.md` (« terminé » et format du rapport, ancien `tasks.md` §0 et `rules.md` §10) et `frontend.md` (nouveau : les règles de l'Admin UI d'ADR-0036) |
| `personas.md` | posture commune dans `AGENTS.md` ; dix personas dans `.agents/personas/` |
| `settings.md` + `skills.md` | `.agents/settings/*.yaml` (dont l'usage des outils dans `development.yaml`) et `environments/{local,ci,production}.yaml` |
| `tasks.md` | `.agents/tasks/` : `README.md` (index, reprise), `backlog.md`, `roadmap.md`, workflows par domaine |
| — | dix compétences par domaine dans `.agents/skills/<nom>/SKILL.md` ; les compétences génériques `better-*` et autres restent |

**Emplacement** : l'arborescence donnée plaçait les dossiers à la racine, hors de `.agents/` ; je les y ai d'abord créés, puis le propriétaire les a déplacés sous `.agents/` pendant le travail. C'est cet emplacement qui est retenu.

**Faits corrigés en chemin** : l'ancien `architecture.md` disait que l'UI « n'existe pas encore » (elle existe depuis ADR-0036) et citait `.agents/` comme « ce dossier ». `settings/security.yaml` reprend les bornes des variables de sécurité, vérifiées dans les `main.go` (`BREAKGLASS_APPROVAL_WINDOW_MINUTES` manquait).

**Ce que cela ne fait PAS :**
1. **Pas de CI** : `settings/ci-cd.yaml` et `environments/ci.yaml` décrivent ce qu'elle devra lancer, pas une CI qui tourne.
2. **Aucun outil ne lit les YAML** : ce sont des réglages pour les agents ; les valeurs réelles restent celles des `main.go`, qui font foi.
3. Les YAML ont été validés par `gopkg.in/yaml.v3`, depuis le cache de modules et hors du dépôt : PyYAML n'est pas installé dans le codespace.

## Les rotations planifiées sont exécutées (ADR-0040)

Demandé par Bony Kiss : « exécuter les rotations scheduled. Elles sont acceptées à l'enregistrement mais rien ne les lance aujourd'hui ».

**Mesuré avant** (rouge, sur `8d76787`) : vraie base PostgreSQL, vraie cible SSH, un compte `scheduled` en retard de deux jours — quinze secondes plus tard, la cible a toujours son mot de passe.

**Livré** :
- domaine : `RotationIntervalDays`, `RotationAttemptedAt`, `RotationDueAt` ; ports `ListDueForRotation`, `ClaimRotation` ;
- migration `004_rotation_schedule.sql` (30 jours aux comptes `scheduled` d'avant) ;
- les deux magasins ; le magasin mémoire rend désormais des **copies**, comme une base : il rendait ses propres enregistrements, ce qui avait faussé le journal d'ADR-0039, et aurait été une race avec un balayage de fond ;
- `application/schedule.go` : `checkSchedule`, `RotateDue`, `WithClock`, `RotationRetryAfter` = 1 h, `RotationsPerSweep` = 20 ;
- `OnboardPinned` écrit le compte **en une fois** (clé, réconciliation, intervalle) et exige un compte de réconciliation pour `scheduled` ;
- `main.go` : `ROTATION_SWEEP_SECONDS` (300, de 1 à 86 400, hors bornes fatal) ;
- HTTP : `rotationIntervalDays` à l'enregistrement (`400` hors bornes), `rotationIntervalDays` et `nextRotationAt` dans la réponse ;
- Admin UI : champ d'intervalle pour une rotation planifiée, cadence et prochaine échéance dans la liste.

**Trouvé en chemin** : une mutation mal écrite (la prise avait lieu avant que je la force) passait pour une survivante : réécrite, elle est tuée. Une vraie survivante, « l'échéance ignore la dernière rotation », n'était couverte que par le SQL : un test du domaine la couvre maintenant. Mon test PostgreSQL vérifiait trop tôt un compte repris à +61 min : c'était le test qui se trompait, pas le code.

**Choix renversables** :
- l'intervalle est en jours, par compte ; le délai avant un nouvel essai (1 h) et la taille d'un passage (20) sont des constantes ;
- le balayage n'a pas d'interrupteur, comme celui du Broker (ADR-0034) ;
- les comptes `scheduled` existants reçoivent 30 jours ;
- pas de route pour changer la politique ou l'intervalle d'un compte existant (comme avant pour la politique).

**Preuves** :
- `test/integration/schedule_flow_test.go` : deux Vaults réels sur la même base, balayage chaque seconde ; le compte non échu ne tourne pas ; échu, il tourne **une fois**, sur la cible, comme action du système, et le Vault injecte ce que la cible prend ; un compte manuel aussi ancien n'est pas touché.
- Tests unitaires ajoutés : Vault domaine +1, application +6 (dont deux Vaults au même instant, `-race`), infrastructure +1 PostgreSQL, interfaces +1 ; Admin UI +2.
- **19 mutations, 19 tuées.**

**Ce que cela ne fait PAS :**
1. ~~**Pas de fenêtre horaire**~~ (refermé par ADR-0041, `ROTATION_WINDOW_UTC`) : un compte pouvait tourner en pleine journée ; la session ouverte garde sa connexion, la suivante reçoit le nouveau secret.
2. ~~**Un échec est retenté chaque heure, sans limite ni alerte**~~ (refermé par ADR-0041 : échecs comptés, `vault.rotation_overdue` tous les N) autre que le journal et `vault.rotate` en échec ; un compte sans réconciliation ou sans clé ne laisse qu'une ligne de journal par heure.
3. **Les comptes `scheduled` d'avant tournent dès la mise à jour** s'ils ont plus de 30 jours (20 par passage).
4. **Le Scheduler complet** de la feuille de route n'existe toujours pas : c'est le Vault qui balaie.

## Une rotation planifiée qui échoue se voit, et se tient dans une fenêtre (ADR-0041)

Go de Bony Kiss pour l'étape proposée : alerter après plusieurs échecs, fenêtres horaires.

**Mesuré avant** (rouge, sur `cc081f7`, même test d'intégration) : le Vault démarrait avec une fenêtre illisible ; hors fenêtre, il tournait les deux comptes échus ; la cible injoignable ne laissait aucune alerte. Trois sous-tests sur quatre échouaient ; le quatrième, « dans la fenêtre », passait déjà, ce qui est attendu.

**Livré** :
- migration `005_rotation_failures.sql` ; `RotationFailures` ; port `RecordRotationFailure` (un `UPDATE … RETURNING`), remis à zéro par `MarkRotated` ;
- `RotationWindow`, `ParseRotationWindow` (UTC, passage de minuit, refus de ce qui ne se lit pas ou dure zéro), `WithRotationSchedule`, `countFailure` ;
- `ROTATION_WINDOW_UTC` et `ROTATION_ALERT_AFTER_FAILURES` (3, de 1 à 100), fatals hors bornes ;
- `rotationFailures` dans la réponse d'un compte ; « en échec (N) » dans l'Admin UI.

**Choix renversables** : l'alerte est un événement d'audit (pas un webhook) ; le rappel tous les N échecs ; une fenêtre pour la plateforme, en UTC ; la rotation manuelle n'est pas tenue par la fenêtre ; on continue de retenter.

**Preuves** :
- `test/integration/rotation_alert_flow_test.go` (vraie base, Vaults réels) : fenêtre illisible ou seuil 0 refusés au démarrage ; hors fenêtre, rien n'est pris ; dans la fenêtre, le compte échu tourne ; une cible injoignable compte un échec et écrit `vault.rotation_overdue` sous le système.
- Tests unitaires ajoutés : Vault application +5, infrastructure +1 PostgreSQL ; Admin UI +1 (et une assertion de plus).
- **17 mutations, 17 tuées** (deux survivaient d'abord : deux trous de **mes** tests, corrigés).

**Ce que cela ne fait PAS :**
1. **Pas de notification poussée** : l'alerte est dans l'audit ; il faut un SIEM ou une revue pour la voir.
2. **Une seule fenêtre, en UTC**, sans jour de la semaine ni fenêtre par compte.
3. **Les comptes qui attendent la fenêtre s'y accumulent** (20 par passage).

## Un refus dit son motif à l'opérateur, une panne jamais sa cause (ADR-0042)

Go de Bony Kiss pour l'étape proposée : relayer le motif d'un `409` du Vault.

**Mesuré avant** (rouge, sur `9cd7be3`, processus réels, vraie base, à travers la Gateway) : pour un compte non épinglé, l'opérateur lisait « authorizing vault scope: authorize-scope: status 409 ». Et, **trouvé en écrivant le test**, Vault arrêté, il lisait en `409` « resolving account: Get "http://127.0.0.1:18481/vault/v1/accounts/…": dial tcp 127.0.0.1:18481: … » : l'adresse interne du Vault.

**Livré** :
- Vault : `authorize-scope` refuse en JSON `{"code", "error"}` — `no_pinned_host_key` (`409`), `refused` (`403`) ;
- Broker : `domain.ErrAccountNotPinned` lu du code (jamais du texte, `409` seulement) ;
- `connect` : `404` (session inconnue), `409` (état, ou compte non épinglé, avec ce qu'il faut faire), `503` générique (dépendance, cause au journal) ;
- `POST /sessions` : les pannes d'Authorization, d'audit et de magasin sont des `ErrUnavailable` → `503` sans la cause, comme le `docs/api/rest/openapi.yaml` le promettait ; un refus reste `403` motivé.

**Jumeaux** : `connect` et `POST /sessions` laissaient sortir des causes internes ; terminer, décider et lire une session ne le faisaient déjà plus (ADR-0018 à ADR-0021). Les routes d'administration relayées vers le Vault renvoient encore le texte de leurs refus d'écriture : non revues ici.

**Un test d'attaque existant a changé, et pourquoi** : `TestMTLS_TheWholeProductOverMutualTLS…` vérifiait que le refus d'un Vault imposteur s'expliquait par l'épinglage d'identité **en lisant la réponse du Broker** — c'est-à-dire le texte interne qu'ADR-0042 cesse de laisser sortir. La garantie (l'imposteur ne reçoit rien) est intacte ; la cause se vérifie maintenant dans le journal du Broker, et le test exige en plus qu'elle **ne** soit **pas** dans la réponse (`503`).

**Choix renversables** : codes en JSON plutôt qu'un en-tête ; la phrase donnée à l'opérateur ; `404` pour une session inconnue à `connect` (c'était un `409`) ; un test existant qui fixait `409` pour une panne du proxy, remplacé (ce `409` n'était pas un état).

**Preuves** : `test/integration/refusal_reason_flow_test.go` ; tests unitaires ajoutés : Broker interfaces +3 (et un remplacé), infrastructure +1 ; Vault interfaces : une assertion de plus. **11 mutations, 11 tuées.**

**Ce que cela ne fait PAS :**
1. ~~**Une session peut encore être créée** sur un compte non épinglé ; c'est `connect` qui la refuse.~~ Refermé par ADR-0043.
2. ~~**Les autres routes publiques** n'ont pas été passées en revue de la même façon.~~ Refermé par ADR-0043 (section suivante).

## Aucune route publique ne rend une erreur interne ; une session ne se crée que sur un compte utilisable (ADR-0043)

Go de Bony Kiss pour l'étape proposée : revoir les autres routes publiques, refuser dès `POST /sessions` un compte non épinglé.

**La revue** (chaque `err.Error()` qui part vers un client, dans les services que relaie la Gateway) :
- Vault, routes d'administration (enregistrer, lister, lire, supprimer, renouveler, épingler) : le texte de toute erreur, y compris Authorization injoignable, audit coupé (son adresse), erreur PostgreSQL (le nom de la contrainte) ; `GET` d'un compte répondait `404` à une panne de la base ;
- Authorization, `POST /policies` : `403` avec le texte de toute erreur du magasin ; `check-access` : `500` avec le texte (route interne) ;
- Broker : break-glass, Authorization injoignable : `403` avec son adresse ;
- Gateway : six `500` avec le texte de ses propres erreurs ;
- Command Recorder : déjà protégé (ADR-0022) ; Authentication : seulement des `400` de lecture de corps.

**Mesuré avant** (rouge, sur `3fe3d4c`, processus réels, vraie base, à travers la Gateway) : sessions créées sur un compte non épinglé et sur un compte inexistant ; Authorization arrêtée, `403` « checking access (fail-closed): Post "http://127.0.0.1:18483/authz/v1/check-access": dial tcp … ». **Trouvé en écrivant le test de la Gateway** : `GET /vault/accounts/acc%0a1`, par n'importe quel utilisateur authentifié, renvoyait l'URL interne du Vault (`parse "http://127.0.0.1:…/vault/v1/accounts/acc\n1": net/url: invalid control character in URL`).

**Livré** :
- Vault : `ErrAccessDenied`, `ErrAuditUnavailable`, `domain.ErrAlreadyExists` (code PostgreSQL `23505` ; le magasin mémoire refuse aussi, au lieu d'**écraser**) ; `writeAdminError` sur toutes les routes d'administration ;
- Authorization : `ErrAccessDenied`, `domain.ErrAlreadyExists` (`409`), `503` générique ;
- Broker : `AccountLookup.CheckAccount` (lit au Vault l'existence et la présence d'une empreinte, jamais la clé) ; `POST /sessions` refuse `ErrAccountNotFound` (`404`) et `ErrAccountNotPinned` (`409`), enregistrés et audités ; Vault injoignable `503` ; break-glass, Authorization coupée `503` ;
- Gateway : `internalError` (`500` « internal error », cause au journal).

**Tests changés, et pourquoi** :
- `TestListAccounts_ClampsPageAndPageSize` enregistrait trois comptes du même nom sur la même cible, ce que la base refuse depuis toujours : il passait parce que le magasin mémoire était plus lâche. Corrigé (un nom par compte).
- L'attaque du Vault imposteur (`TestMTLS…`) a lieu maintenant à la création de la session, premier appel au Vault ; la garantie (l'imposteur ne reçoit rien, la cause est au journal, pas dans la réponse) est intacte.
- Neuf scénarios qui ne testent que le Broker (break-glass, lectures, terminaisons, budgets) pointaient vers un Vault qui n'existait pas : la création d'une session ne l'interrogeait pas. Ils jouent maintenant la lecture de compte du Vault (`playVaultAccounts`, `test/integration/hostkey_helpers_test.go`), qui ne répond qu'à cette lecture.
- Trois de mes tests HTTP du Broker (ADR-0042 compris) envoyaient `privilegedAccountId` au lieu de `targetAccountId` : ils passaient sans compte. Corrigés.

**Choix renversables** : la réponse d'une cible qui refuse une rotation reste relayée à l'administrateur (`502`) ; la lecture du compte se fait après la décision d'accès, pour qu'un appelant refusé n'apprenne rien ; le magasin mémoire d'Authorization accepte un doublon de politique (sans effet).

**Preuves** : `test/integration/refusal_reason_flow_test.go` (réécrit) ; unitaires ajoutés : Vault interfaces +1, infrastructure +2 (dont 1 PostgreSQL) ; Authorization interfaces +1, infrastructure +1 PostgreSQL ; Broker application +2, interfaces +2, infrastructure +1 ; Gateway +1 (rouge mesuré sur l'ancien handler). **18 mutations, 18 tuées.**

**Ce que cela ne fait PAS :**
1. **Le Vault est une dépendance de la création d'une session** (il l'était de la connexion).
2. **Les scénarios du Broker seul** jouent la lecture de compte du Vault.
3. **Pas de garde à la Gateway** sur les corps qu'elle relaie : la règle se tient dans chaque service.

## Correctif : un opérateur dont l'entrée se termine lit encore ce que la cible répond (proxy SSH)

**Trouvé** en vérifiant ADR-0043 : `TestHostKeyFlow…` échouait une fois sur plusieurs (« the session did not run: Connection to 127.0.0.1 closed by remote host »). Le mot de passe arrivait bien à la cible ; c'était sa réponse qui se perdait.

**Cause** : en mode shell, `Codec.Relay` rendait la main dès que **l'une** des deux copies se terminait. Un client dont l'entrée est finie (`ssh … < /dev/null`, `echo cmd | ssh …`, un script) la termine aussitôt : le proxy coupait la session sans attendre ce que la cible avait encore à dire. Défaut antérieur à cette série : le test passait selon l'ordre d'arrivée des paquets.

**Rouge d'abord** : `TestRelay_AnOperatorWhoseInputEnds_StillReadsWhatTheTargetAnswers` — l'opérateur ne recevait rien (« shown "" »).

**Correctif** : la fin de l'entrée de l'opérateur ferme l'entrée de la cible (comme un client SSH), et le relais continue jusqu'à ce que la cible termine le shell. Une erreur de ce côté — une commande qui ne peut pas être enregistrée surtout (ADR-0008) — termine toujours la session aussitôt.

**Jumeaux** : le relais des transferts (SFTP, SCP, ADR-0038) fermait déjà l'entrée de la cible et attendait sa fin.

**Preuves** : deux tests (`sshcodec`, +2) : la réponse tardive arrive ; une cible qui ne répond qu'à la fin de son entrée (comme `sort`) répond. **3 mutations, 3 tuées** (rendre la main à la fin de l'entrée ; ne pas fermer l'entrée de la cible ; attendre après une erreur d'enregistrement).

## Une rotation après usage n'est plus perdue (ADR-0044)

Go de Bony Kiss pour l'étape proposée : réessayer une rotation après usage échouée.

**Deux pertes, pas une** : le Broker prévenait le Vault dans une goroutine (Vault injoignable ou Broker redémarré : la demande était perdue) ; le Vault qui l'avait reçue ne réessayait pas une rotation refusée par la cible.

**Mesuré avant** (rouge, sur `3e2acd4`, processus réels, vraie base) : Vault arrêté à la fin d'une session `post_use`, puis relancé — 90 s plus tard, la demande était perdue et l'ancien mot de passe ouvrait toujours la cible.

**Livré** :
- Broker : `sessions.after_use_owed` (migration `003_after_use_owed.sql`), écrit par la terminaison (dans son compare-échange) et par l'expiration d'une session **active** (dans son `UPDATE`) ; `deliver` l'efface quand le Vault répond `200` ou `404` ; `DeliverAfterUse` renvoie, une minute après la fin, à chaque balayage (`SESSION_EXPIRY_SWEEP_SECONDS`) ; la demande porte `endedAt`.
- Vault : `privileged_accounts.rotation_owed_since` (migration `006_rotation_owed.sql`) ; `RotateAfterUse(accountID, endedAt)` : rien n'est dû si le compte a tourné depuis ; sinon la dette est enregistrée, puis le compte est pris et tourné ; « reçu » (`200 {"owed","rotated"}`) que la rotation ait réussi ou non ; un échec est compté et alerté (ADR-0041) ; le balayage paie les dettes, **hors fenêtre aussi** ; `MarkRotated` efface la dette.
- API et Admin UI : `rotationOwedSince`, « renouvellement dû ».

**Trouvé en chemin** : une seconde session finie moins d'une heure après une rotation attendait l'heure de délai prévue pour les échecs — une **nouvelle** dette lève maintenant ce délai, une dette qui échoue le garde.

**Changé en chemin** : `make test-postgres` lançait `TestPostgresFlow_*` avec `-timeout=60s` ; le nouveau scénario dure 67 s (la minute d'attente avant un renvoi) — la limite est portée à 300 s, comme celle de `make test-integration`. `TestPostgresFlow_ReplicasStartingTogether…` attend désormais les trois migrations du Broker.

**Vu une fois, cause non établie** : `TestPostgresFlow_SessionsPastTheirEndAreExpiredOnce…` a échoué une fois sous `-race`, dans le lot des tests PostgreSQL, sortie non conservée ; il a passé seul, puis trois fois de suite dans le même lot (43 à 131 s : la machine était chargée par la pile de prévisualisation Base44). L'hypothèse d'un balayage du Broker ralenti par les renvois d'ADR-0044 ne tient pas dans ce test (Vault sur `127.0.0.1:1`, refus immédiat ; aucune session due en base). Relancé le 2026-10-31, `GOFLAGS=-race make test-postgres`, sortie conservée : tout passe (76 tests, aucune course signalée), ce test en 8,84 s. Pas reproduit ; ses attentes sont à délai fixe (10 et 15 s), si bien qu'une machine très chargée reste l'explication la plus probable, sans preuve. À surveiller : au prochain échec, garder la sortie.

**Choix renversables** : le délai avant un renvoi (une minute) ; le Vault tourne avant de répondre (simple ; un renvoi peut donc attendre la cible) ; une session break-glass accordée sous l'ancien régime à une personne est tournée après usage.

**Preuves** : `test/integration/after_use_flow_test.go` (67 s) ; unitaires ajoutés : Vault application +5, infrastructure +1 PostgreSQL, interfaces +1 ; Broker application +2, infrastructure +2 (dont 1 PostgreSQL) ; Admin UI +1. **20 mutations, 20 tuées** (une survivante d'abord : l'ordre des dates dans mon test, corrigé).

**Ce que cela ne fait PAS :**
1. **Tant que la cible est injoignable, le secret utilisé reste en place** : retenté chaque heure, visible et alerté, pas résolu.
2. **Le Vault tourne avant de répondre** : un renvoi peut attendre jusqu'à 60 s.

## Documentation : `docs/` réorganisé par public, un sujet par fichier

Demande de Bony Kiss (31 octobre 2026) : une arborescence cible pour `docs/`. Choix tranchés par lui : les **44 ADR éclatés tels quels** (numéros et titres gardés, la liste proposée « 0001-record-architecture-decisions… 0012 » n'est pas reprise, elle aurait renuméroté des décisions acceptées que le code cite) ; **ne créer que le réel** (une page n'existe que si son contenu décrit le code ; le prévu est listé dans le `README.md` de sa section).

**Livré** : `docs/README.md` (plan, publics, table « ancien document → nouveau fichier », 74 lignes) ; `architecture/` (8 pages), `adr/` (44 ADR, `README.md` index lié, `template.md`), `api/` (`conventions.md`, `rest/openapi.yaml` extrait du doc 05, `grpc/README.md`), `security/` (12 pages, dont `known-limitations.md`, l'ancien Guide Sécurité §12), `development/` (6), `deployment/` (9), `administration/` (7), `user-guide/` (6), `roadmap.md` ; `operations/` et `compliance/` : index seulement. Contenu repris à l'identique par un script (titres renumérotés dans les fichiers découpés ; numérotation gardée dans les documents déplacés en entier : doc 02, 04, 06, 07, 08, HA, PRA) ; retirées seulement les sections qui décrivaient l'ordre de rédaction (« Prochaine étape », « Document suivant », « Clôture de la séquence »).

**Vérifié** : chaque ligne non vide des 15 anciens documents se retrouve dans un nouveau fichier, sauf les 62 lignes de ces sections retirées et les 14 de l'en-tête et de l'index des ADR, réécrits avec des liens (contrôle par script) ; `rest/openapi.yaml` chargé par `yaml.safe_load` (OpenAPI 3.1.0, 18 chemins) ; chaque lien relatif sous `docs/` et chaque chemin `docs/…` cité dans le dépôt existe ; 475 renvois réécrits automatiquement (`doc NN §N`, `Guide Sécurité §N`, `OpenBastion_*.md`) dans le code, `proto/`, `.agents/`, `AGENTS.md`, `README.md` et ce fichier, puis une trentaine à la main (« §N » internes devenus orphelins, un nom tronqué par mon premier motif : `OpenBastion_01_Diagrammes_C4.md`). `make build vet` et `make test` passent ; trois messages d'erreur Go citaient un document, aucun test ne les compare.

**Ce que cela ne fait PAS** : les commentaires des migrations SQL déjà appliquées gardent les anciens noms (leur texte ne change plus, ADR-0030) — la table de `docs/README.md` sert à les lire ; les pages de la liste sans contenu réel (Kubernetes, Helm, bus de messages, Postman, gRPC `buf.yaml`, MFA, métriques, runbooks, conformité…) n'existent pas ; les diagrammes restent dans les pages, sans copie `.mmd` ; `openapi.yaml` reste un seul fichier (pas de découpage `openapi-admin/sessions/secrets/audit`). Le contenu n'a pas été revu sur le fond : certaines pages reprises citent des cibles de conception initiale absentes du `Makefile` (`make dev-up`, `make proto-gen`) — signalé dans `docs/development/README.md`, pas corrigé.

**Choix renversables** : `roadmap.md` à la racine de `docs/` ; `architecture/data-access-orm-analysis.md` et `security/known-limitations.md`, hors de la liste demandée ; `deployment/prerequisites.md` plutôt que les prérequis dans `deployment/README.md` ; le break-glass sous `administration/approval-workflows.md` ; les noms de fichiers des ADR tirés de leur titre (60 caractères au plus).

## Une alerte écrite à l'audit est poussée par un webhook signé (ADR-0045)

Go de Bony Kiss (31 octobre 2026) pour le point 1 ter du backlog, sous la forme proposée : « Webhook signé ». ADR-0041 avait écarté ce webhook ; ADR-0045 y revient sans rien retirer à ADR-0041.

**Mesuré avant** (rouge, sur `4d1b5a5`, `test/integration/alert_push_flow_test.go` copié dans un worktree) : 3 sous-tests sur 4 échouent — un canal à moitié configuré démarre, rien n'est poussé, rien n'est annoncé. Le quatrième (« l'alerte du Broker n'est pas poussée ») passe trivialement : rien ne l'était.

**Livré** :
- `pkg/webhook` (stdlib) : l'URL vérifiée (https, ou http vers le bouclage ; ni identifiants ni autre schéma), jamais répétée (`Where()` = schéma et hôte), signature `v1` d'ADR-0013, pas de redirection, erreur de transport sans l'URL, `SafeText`. Le notificateur break-glass du Broker l'utilise désormais ; ses tests passent sans changement.
- Audit Service : `application/alerts.go` — une alerte est un couple (action, émetteur du certificat), aujourd'hui `vault.rotation_overdue` ← `password-vault` ; poussée après l'écriture, jamais une écriture refusée ; sans TLS interne, l'alerte sans émetteur est poussée (annoncé). `infrastructure/alert_webhook.go` — un seul livreur, 5 tentatives (transport, `408`, `429`, `5xx`), attente doublant à partir de `ALERT_NOTIFY_RETRY_SECONDS` (30 par défaut, 1 à 600), au plus 256 alertes en cours, `Notify` ne bloque jamais.
- `main.go` : `ALERT_NOTIFY_URL` et `ALERT_NOTIFY_SECRET` (≥ 32 octets) ensemble ou rien ; toute valeur fausse arrête le service sans répéter l'URL ni le secret ; le démarrage dit ce qui est poussé, vers quel hôte, combien de fois.
- Documentation : `docs/administration/notifications.md` (nouvelle page, avec un vérificateur Python exécuté contre une signature réelle), dépannage, limites, contrats internes (§7), `.agents/` (backlog, réglages, écarts connus).

**Preuves** : unitaires +7 (application), +8 (adaptateur contre un vrai récepteur HTTP), +9 (`pkg/webhook`) ; intégration +2 sur processus réels (mTLS : certificats réels du Vault et du Broker ; sans TLS interne). **24 mutations : 23 tuées, 1 équivalente** (retirer le cas « URL sans secret » du `main.go` laisse le refus à `WithSecret`, même arrêt, même variable nommée). Deux mutations n'échouaient d'abord qu'à la compilation : réécrites pour compiler, elles sont tuées par les tests.

**Ce que cela ne fait PAS** : ~~pas de file durable~~ (levé avec une base par ADR-0057 ; sans base, une alerte en attente d'un renvoi est perdue si l'Audit Service s'arrête ; elle reste dans la chaîne et le Vault la réécrit N échecs plus tard) ; un récepteur qui répond `2xx` est cru ; pas d'anti-rejeu propre au canal (tolérance d'horodatage et `eventId` côté récepteur) ; la liste des alertes est dans le code ; sans TLS interne, n'importe quel écrivain pousse une alerte ; les fichiers compose ne règlent pas le canal (optionnel, à poser par l'exploitant).

**Choix renversables** : le canal à l'Audit Service plutôt qu'au Vault ; signature obligatoire (optionnelle pour le break-glass) ; 5 tentatives et 256 en cours (constantes, non réglables) ; `408` et `429` renvoyés, une redirection abandonnée ; le texte anglais de `text`, comme le break-glass.

## Plusieurs instances du proxy SSH (ADR-0046)

Go de Bony Kiss (31 octobre 2026) pour l'étape proposée : le point 4 du backlog. Lecture retenue sans redemander : le Broker connaît toutes les instances et fait révoquer chez toutes, en mode strict (ADR-0018).

**Le défaut était double** : la révocation n'atteignait qu'une instance, et la connexion elle-même ne tenait pas — chaque instance annonçait `127.0.0.1:SSH_PORT`, et un ticket n'est connu que de l'instance qui l'a émis.

**Mesuré avant** (rouge, sur `13a90c0`, `test/integration/proxy_instances_flow_test.go` copié dans un worktree) : le Broker démarrait avec une liste illisible, ignorait `SSH_PROXY_URLS`, et le premier `connect` répondait `503`.

**Livré** :
- Proxy SSH : `SSH_PUBLIC_ENDPOINT` (`hôte:port` de cette instance, rendu avec chaque ticket ; défaut `127.0.0.1:SSH_PORT` ; illisible : fatal, lu avant tout le reste).
- Broker : `SSH_PROXY_URLS` (1 à 16 URL distinctes, chacune une instance, client mTLS épinglé sur `ssh-proxy`), exclusif de `SSH_PROXY_URL` ; `infrastructure.ProxyPool` derrière le port `ProxyClient`, sans changer l'application : ticket chez une instance à tour de rôle (la suivante si elle échoue, le refus d'enregistrer l'emporte), révocation chez toutes en parallèle, confirmée par toutes ou par aucune.
- Documentation : configuration, HA (limite barrée), dépannage (trois lignes), contrats internes, OpenAPI (texte de `DELETE /sessions/{id}`), limites ; ADR-0018 : limite barrée « Levé par ADR-0046 » ; `.agents/` (backlog, écarts connus, production, réglages, persona SRE, compétence résilience).

**Preuves** : unitaires +7 (pool) ; intégration +1 sur deux proxys réels (tickets à tour de rôle avec l'adresse de leur instance, ticket refusé ailleurs puis valable chez lui, les deux shells coupés, une autre session intacte, instance arrêtée : `connect` à l'autre, `DELETE` `503` sans adresse interne puis `200` au retour ; refus de démarrer du Broker et du proxy). **12 mutations, 12 tuées** ; une survivait d'abord parce que mon test annonçait la valeur par défaut (`127.0.0.1:<port>`) : il annonce désormais `localhost:<port>`.

**Ce que cela ne fait PAS** : une instance injoignable empêche **toute** terminaison (le Broker ne distingue pas arrêtée de coupée ; l'exploitant retire une instance qu'il sait arrêtée de `SSH_PROXY_URLS` et redémarre le Broker) ; pas d'équilibreur possible devant les ports SSH ; tour de rôle par processus du Broker, sans mesure de charge ; pas de découverte des instances (liste statique) ; les fichiers compose gardent une instance.

**Choix renversables** : révoquer chez toutes plutôt que retenir l'instance de chaque ticket (pas de migration, pas de course à fermer) ; 16 instances au plus ; tour de rôle plutôt qu'aléatoire ; le repli sur l'instance suivante pour tout échec d'`establish-session`.

## Une CI GitHub Actions (ADR-0047)

Go de Bony Kiss (31 octobre 2026) pour le point 5 du backlog ; choix des « actions officielles épinglées » (actions/checkout v7.0.1, actions/setup-go v7.0.0, actions/setup-node v7.1.0, par empreinte de commit vérifiée auprès de GitHub ; `postgres:16` par son empreinte d'index, `sha256:1beaa308…`).

**Livré** : `.github/workflows/ci.yml` — cinq jobs en parallèle (`go`, `race`, `integration`, `postgres`, `ui`), sur chaque `push` vers `main` et chaque pull request ; `permissions: contents: read`, `persist-credentials: false`, aucun secret lu ; Go 1.27.1 et Node 24.21.0. `.agents/settings/ci-cd.yaml` et `environments/ci.yaml` décrivent la CI réelle ; `docs/development/contributing.md` barre la CI imaginée de la conception initiale (`buf breaking`, filtrage par chemins).

**Mesuré** : première exécution (run `41212800565`, `cf95a4f`) verte en 8 min 24 s ; intégration 50 sans base, 74 avec, `make test-postgres` 76 — les mêmes comptes que la vérification locale ; 32 paquets unitaires `ok` sans base, sous `-race` et avec base ; Admin UI 25.

**Ce que cela ne fait PAS** : la CI ne bloque rien tant que la protection de `main` n'exige pas ses jobs (réglage du dépôt, au propriétaire) ; pas de test Compose, pas de `govulncheck` ni de `npm audit`, pas de construction d'images ; les empreintes ne se mettent pas à jour seules ; les tests à délai fixe peuvent échouer sur un runner lent.

**Choix renversables** : cinq jobs plutôt qu'un ; `ubuntu-24.04` ; Go 1.27.1 (les modules déclarent 1.26.0, aucune CI ne prouve ce minimum) ; `GOPROXY=direct` comme le Makefile, sans cache de proxy.

## Une cible reconnue par une autorité de certificats SSH (ADR-0048)

Go de Bony Kiss (31 octobre 2026) pour le point 6, et choix du modèle « par compte, au choix » (parmi « autorités de plateforme » et « ne pas le faire ») : l'invariant « secret envoyé seulement à la clé d'hôte épinglée » devient « à la cible que le compte reconnaît — sa clé, ou un certificat de l'autorité épinglée pour son nom » (`AGENTS.md`, `invariants.md`).

**Mesuré avant** (rouge, sur `30c4214`, `test/integration/hostcert_flow_test.go` dans un worktree) : la ligne `@cert-authority` est refusée (`400`).

**Livré** :
- `pkg/hostkey` (sur `golang.org/x/crypto/ssh`, déjà une dépendance du Vault et du proxy) : `Normalize`, `Parse`, `Trust.Configure` — la clé épinglée exacte, ou un certificat **d'hôte** de **cette** autorité, avec une liste de noms **non vide** contenant **ce** nom (pas l'adresse), dans sa période, **avec une fin**, sans option critique ; sous autorité, certificats proposés d'abord puis clés nues.
- Vault : `NormalizeHostKey` et la rotation (`SSHTargetChanger`) passent par `pkg/hostkey` ; l'empreinte d'un compte d'autorité est celle de l'autorité. Proxy : `sshcodec` passe par `pkg/hostkey`, chaque refus reste un `ErrHostKeyMismatch` (audité `session.host_key_mismatch`). Le contrat ne change pas de forme : `hostKey` accepte une valeur de plus.
- Admin UI : le libellé du champ dit la forme d'autorité. Documentation : administration (procédure `ssh-keygen` exécutée pour de vrai), dépannage, OpenAPI, limites, ADR-0039 (limite barrée).

**Preuves** : `pkg/hostkey` 6 tests (dont un certificat fabriqué par le vrai `ssh-keygen`) ; Vault +1 (rotation par autorité, trois imposteurs) ; intégration +1 sur processus réels et le vrai client OpenSSH (la cible certifiée ouvre la session ; six imposteurs ne reçoivent aucun mot de passe, et leur refus est audité). **16 mutations, 16 tuées par un test** (le lanceur écarte désormais une mutation qui ne fait qu'empêcher la compilation).

**Trouvé en chemin** : ne proposer que les algorithmes de certificats faisait échouer la négociation avec une cible sans certificat avant toute vérification — rien n'était envoyé, mais le refus n'était ni dit ni audité. Corrigé (clés nues proposées après les certificats), et le test le garde.

**Ce que cela ne fait PAS** : pas de liste de révocation (un certificat volé vaut jusqu'à sa fin) ; pas de durée maximale imposée aux certificats ; une autorité par compte ; pas d'autorités de plateforme ; un nom partagé par plusieurs serveurs les rend interchangeables pour le compte.

**Choix renversables** : le format `known_hosts` dans le même champ plutôt qu'un champ séparé ; le refus des certificats sans fin ; l'ordre certificats puis clés nues ; un nom en minuscules.

## Les clés de chiffrement gardées par Transit (ADR-0049)

Go de Bony Kiss (31 octobre 2026) pour le point 7, et choix de « Transit OpenBao/Vault » (parmi AWS KMS, PKCS#11 et « reporter »).

**Mesuré avant** (sur `02e7ad8`, binaire du Vault construit dans un worktree, vrai OpenBao) : `TRANSIT_*` ignorées — sans `KMS_KEY_HEX`, refus de démarrer ; avec, démarrage silencieux et tout scellé sous la clé locale.

**Livré** :
- `pkg/transit` (stdlib) : `encrypt`/`decrypt` d'une clé nommée, données associées obligatoires, `https` (ou `http` vers le bouclage), autorité facultative, pas de redirection ni de proxy de sortie, 5 s par appel ; jeton lu dans un fichier `0600`/`0400` (lisible par d'autres : refusé), jamais dans une erreur ; `Probe` (aller-retour d'essai).
- Vault : `TransitKMS` — une clé de données neuve par secret (AES-256-GCM), enveloppée par Transit ; le secret ne quitte pas le processus ; format `OBT1`. `Keyring` : on scelle avec la clé courante, on ouvre avec la clé que la version nomme ; `Encryptor.Open` reçoit désormais `encryption_key_id`. `domain.ErrKeysUnavailable` : `fetch-credential` rend `503` (message fixe) au lieu de `403` avec le texte de l'erreur.
- Recorder : `TransitKEK` ; `NewPostgresStore(…, previous...)` lit les enregistrements enveloppés sous une clé précédente (`kek_id`).
- `main.go` des deux services : Transit configuré → aller-retour au démarrage (sinon refus), `KMS_KEY_HEX` devient une clé précédente en lecture seule ; sinon, comme avant.
- Documentation : `docs/security/key-management.md` (nouvelle ; commandes OpenBao exécutées pour de vrai), configuration, dépannage, HA (Transit en tier 0), limites, secrets ; `.agents/` (backlog, réglages, écarts connus).

**Preuves** : `pkg/transit` 6 tests ; Vault +5 (enveloppe, trousseau, clé locale) ; Recorder +1 sur PostgreSQL (passage à Transit sans rien rendre illisible) ; intégration +1 contre un vrai OpenBao 2.7.2 en conteneur (image épinglée par empreinte), processus réels et vraie PostgreSQL — refus de démarrer sur six configurations douteuses, anciens secrets lus, nouveaux sous Transit, Transit en pause = `503`, Transit seul = ancien secret refusé, jeton limité refusé ailleurs. **19 mutations, 19 tuées par un test.**

**Trouvé en chemin** : `fetch-credential` rendait `403` pour toute erreur, en recopiant son texte (l'adresse de Transit serait partie dans la réponse) ; et mon test laissait OpenBao en pause quand il échouait, ce qui faisait échouer tous les suivants (corrigé par un `defer`).

**Ce que cela ne fait PAS** : ~~pas d'AppRole ni de renouvellement du jeton~~ (ADR-0058, ADR-0053) ; pas de ré-enveloppement en masse ; un appel réseau par secret ouvert et par clé d'enregistrement ; sans Transit, la clé reste locale ; les fichiers compose n'ont pas de Transit (à poser par l'exploitant) ; le test contre OpenBao demande Docker (sinon il se saute).

**Choix renversables** : l'enveloppe côté Vault plutôt qu'un chiffrement direct par Transit ; le jeton seulement par fichier ; l'identifiant `transit:<montage>/<clé>` ; le refus d'un fichier de jeton lisible par le groupe ; `503` pour une clé que le service ne tient plus.

## Le transport entre services reste HTTP/JSON sous mTLS (ADR-0050)

Go de Bony Kiss (31 octobre 2026) pour le point 8, après la mesure de son coût, et choix de « clore par un ADR » (parmi un pilote sur `EmitEvent`, la migration complète, le report).

**Mesuré avant de décider** : 6 contrats `proto/`, 19 RPC ; 29 routes internes dans 8 services ; 29 fichiers de tests d'intégration qui les appellent ; `google.golang.org/grpc` v1.85.0 apporte `protobuf`, `genproto`, `x/net`, `x/text`, exige Go 1.26 dans les modules et `x/sys` v0.48 (forcé à v0.21 aujourd'hui) ; aucun `protoc` ni `buf` installé.

**Livré** : `test/integration/contract_test.go` — 17 paires route ↔ message vérifiées dans les deux sens par lecture des sources (`go/parser`) et des `.proto`, chaque divergence déclarée avec sa raison (pas de `RequestContext`, durées plutôt qu'échéances, pas de `signature` ni de `valid_until`, la révocation qui répond par ses compteurs) ; une raison périmée échoue ; toute structure interne aux champs `snake_case` est dans la table ou déclarée sans contrat (7). ADR-0050 ; `.agents/architecture/transport-and-contracts.md` et `rules/api-contracts.md` (une nouvelle route se déclare dans ce test) ; `docs/api/grpc/README.md`, `README.md`, écarts connus, backlog.

**Preuves** : 2 tests ; **6 mutations, 6 tuées**. Trouvé en écrivant le test : une divergence que j'avais mal déclarée (`reason` n'est pas un champ du `TerminateSessionRequest` du proxy), refusée par le contrôle des déclarations périmées.

**Ce que cela ne fait PAS** : les noms sont vérifiés, pas les types ; les corps construits par une `map` côté client (dix appels, listés dans l'ADR) ne le sont pas ; pas de code généré, pas de flux, `buf breaking` ne garde pas les numéros de champs.

**Choix renversables** : la vérification par lecture des sources plutôt qu'un test par service ; les sept structures déclarées sans contrat ; les critères de reprise de gRPC.

## Les images tirées sont épinglées par empreinte (ADR-0051)

Go de Bony Kiss (31 octobre 2026) pour le point 9.

**Mesuré avant** : `test/integration/images_test.go`, écrit d'abord, échoue sur huit références épinglées par étiquette seule (`golang:1.23` ×2, `golang:1.23-alpine`, `node:24-alpine`, `gcr.io/distroless/static-debian12:nonroot`, `postgres:16` ×2, `node:22`).

**Livré** : chaque image tirée porte `name:tag@sha256:<empreinte d'index>` (relevée par `docker buildx imagetools inspect`) ; le test lit `deploy/*/Dockerfile*`, `deploy/*/docker-compose*.yml` et `.github/workflows/*.yml` et refuse toute image tirée sans empreinte (exemptées : les images `openbastion*` construites par Compose, et les étapes d'un même Dockerfile). Policy des dépendances, point 6 : « TOUJOURS épingler » remplace « ne sont pas épinglées » ; ADR-0033 : limite barrée ; `deploy/docker-compose/README.md` : comment mettre une empreinte à jour.

**Preuves** : rouge puis vert ; les trois images construites (déploiement, outils, Base44), un binaire démarre dans l'image distroless ; **3 mutations, 3 tuées**.

**Pas lancé** : `make test-compose` — sa règle de pare-feu temporaire a été refusée par le mode de permission de cette session ; la pile n'a donc pas été démarrée avec les nouvelles images.

**Puis, le même jour** : les images de construction passent de Go 1.23 (plus corrigé) à `golang:1.27.1` et `golang:1.27.1-alpine`, épinglées par empreinte — la version de la CI. Les trois images se construisent, `go version` y dit `go1.27.1`, un binaire démarre dans l'image distroless. `make test-compose` a d'abord été refusé deux fois (règle de pare-feu temporaire) ; autorisé ensuite explicitement par Bony Kiss, il passe sur ces images : **9 scénarios sur la vraie pile, 147 s** (Admin UI sous sa politique, seuls la Gateway et le proxy publiés, clés par service, bases cloisonnées, pas de compte de démonstration, l'auditeur relit ce que l'opérateur a tapé, chaîne vérifiée par le CLI, aucun secret dans les journaux, tout survit au redémarrage de la pile) ; règle retirée après (0 restante). La pile Base44 qui tourne garde son ancienne image jusqu'à `docker compose -f deploy/base44/docker-compose.yml up -d --build`.

**Ce que cela ne fait PAS** : pas de mise à jour automatique des empreintes ; l'image OpenBao des tests (dans le code Go) n'est pas lue par le test ; rien de plus.

## Les vulnérabilités connues, cherchées et corrigées (ADR-0052)

Demande de Bony Kiss (31 octobre 2026) : « traite d'abord les reliquats et fais un check sur les vulnérabilités ».

**Trouvé** (`govulncheck` v1.9.0, mode symboles, 17 modules ; `npm audit` sur deux lockfiles) :
- 12 vulnérabilités **appelées** de la bibliothèque standard de Go 1.27.1 (HTTP/2, `net/http`, `crypto/tls`, `crypto/x509`, `net/textproto`), corrigées en 1.27.2 et 1.27.3 ;
- 1 appelée dans `golang-jwt/jwt/v5` v5.2.1 (GO-2025-3553, Authentication) ;
- **un angle mort** : `golang.org/x/crypto` v0.24.0 était remplacé par le miroir `github.com/golang/crypto` (posé quand `golang.org` était injoignable du bac à sable) ; sous ce nom, le scan ne le reconnaissait pas et ne disait rien. Sous son vrai nom, la même version a 21 vulnérabilités publiées avec correctif (et `openpgp`, abandonné), dont une dizaine touchent un serveur SSH (le proxy) et un contournement des restrictions de certificat (GO-2026-5014, ADR-0048) ;
- npm : 1 de gravité faible, `esbuild` 0.27.7 (construction de la bibliothèque d'icônes, serveur de développement sous Windows). Un premier relevé l'avait manquée (sortie mal lue).

**Corrigé** : Go 1.27.3 (CI, images `golang:1.27.3` et `golang:1.27.3-alpine` épinglées) ; `x/crypto` v0.58.0, `x/sys` v0.49.0, `jwt/v5` v5.3.1 ; directive `go 1.26.0` dans les cinq modules concernés et `go.work` (exigée par `x/crypto`) ; miroir retiré (les modules viennent de `golang.org`, `GOPROXY=direct`) ; `esbuild` ramené à 0.27.2 par `npm audit fix`. **Aucune dépendance nouvelle.**

**Mis en place** : `make vuln` (`govulncheck` épinglé sur chaque module du `go.work`, `npm audit` sur les deux lockfiles) ; job `vulnerabilities` dans la CI, à chaque commit et **chaque lundi** ; policy des dépendances : plus de remplacement d'un module externe par un autre chemin sans ADR ; portes de qualité d'un jalon.

**Mesuré après** : `make vuln` sous Go 1.27.3 — 0 vulnérabilité appelée sur 17 modules, 0 sur npm ; contre-épreuve : `jwt` remis en v5.2.1, le scan échoue sur GO-2025-3553. Vérification complète sur la nouvelle chaîne : unitaires 778 sans base, 838 avec ; `make test-postgres` 78 ; intégration 54 sans base, 79 avec ; `-race` 34 paquets, aucune course ; Admin UI 25 ; `gofmt` vide ; **`make test-compose` vert (172 s)**.

**Trouvé en chemin** : sous `-race`, un test du proxy (`TestStrictRecording_ASessionIsRefusedBeforeTheCredentialIsFetched`) échouait environ une fois sur vingt : le proxy ferme une session refusée avant que le client ait la réponse à sa demande de shell (`EOF`). Comportement correct ; l'aide du test le tenait pour impossible. Corrigée, 100 passages sous `-race`.

**Ce que cela ne fait PAS** : pas d'analyse des images (paquets Alpine, Debian, Node) ; pas de mise à jour automatique (Dependabot ouvrirait des pull requests) ; la base de Go et celle de npm seulement.

## Reliquat d'ADR-0050 : les corps construits par une `map` sont vérifiés

Les clients internes construisaient neuf corps et réponses par une `map` ou une structure anonyme (le Broker vers le proxy, le proxy vers le Vault et l'audit, le Vault vers l'audit et l'Authorization, le Recorder vers l'Authorization) : le test de contrat ne les voyait pas. Ce sont désormais des structures nommées, ajoutées à la table (**24 paires**, contre 17), et le test **refuse** toute structure anonyme ou `map` littérale à champs `snake_case` dans `internal/interfaces` et `internal/infrastructure` (seul `oidc_provider.go` en est exempté : formats d'un fournisseur tiers). Le JSON envoyé ne change pas. **3 contre-épreuves, 3 tuées** ; unitaires des quatre services verts ; intégration sans base verte (178 s).

## Reliquat d'ADR-0049 : le jeton Transit se renouvelle de lui-même (ADR-0053)

Un jeton périodique (la procédure recommandée) expirait sous le Vault et le Recorder au bout de sa période : panne programmée. **Mesuré avant** (sur `3ff50c0`, vrai OpenBao) : jeton périodique de 4 s, au bout de 10 s, `fetch-credential` → `503`. **Livré** : `pkg/transit` `TokenLife` (`lookup-self`), `RenewSelf` (`renew-self`), `KeepAlive` (à mi-vie ; échec retenté au quart du temps restant, au moins toutes les 5 s ; jeton sans fin ou non renouvelable laissé tel quel et annoncé) ; lancé par le Vault et le Recorder après l'aller-retour d'essai ; politique minimale documentée + `lookup-self` et `renew-self`. **Après** : le secret est livré au bout de 10 s, les deux services annoncent le renouvellement. `pkg/transit` +4 tests ; **6 mutations, 6 tuées**. **Reste** : pas d'AppRole ; le fichier du jeton n'est pas relu à chaud ; un jeton à sa durée maximale se remplace à la main.

## Reliquat d'ADR-0048 : une clé d'hôte certifiée se révoque (ADR-0054)

Un certificat d'hôte volé valait jusqu'à sa fin. **Mesuré avant** (sur `10dc071`) : la ligne `@revoked` est refusée à l'épinglage (`400`). **Livré** : `pkg/hostkey` lit, sous une ligne `@cert-authority`, 0 à 64 lignes `@revoked <nom ou *> <clé>` (format de `known_hosts`) ; une clé révoquée est refusée même certifiée, par le proxy et par la rotation ; refusés : sous une clé épinglée, avant l'autorité, pour un autre nom, de l'autorité elle-même, d'un certificat, au-delà de 64 ; doublons fondus, liste rangée. Même champ, même route, même audit. **Après**, sur processus réels et OpenSSH : clé révoquée = aucun mot de passe, `session.host_key_mismatch` ; révocation levée = la session tourne. `pkg/hostkey` +4 tests ; **6 mutations, 6 tuées** (une survivait : mon test d'ordre, avec deux clés seulement). **Reste** : par clé, pas par numéro de série (pas de KRL) ; compte par compte.

## Reliquat d'ADR-0049 : le ré-enveloppement en tâche de fond (ADR-0055)

Tant qu'une ligne nommait `KMS_KEY_HEX`, la clé locale ne pouvait pas partir. **Mesuré avant** (sur `3e11ddf`, vrai OpenBao) : le secret d'avant reste sous `local-dev-key-v1`, 30 s plus tard. **Livré** : Vault — `SealedUnder` (par page, après un curseur) et `ResealIf` (compare-échange) dans les deux magasins, `RewrapDue` (audit `vault.secret_rewrapped` avant, ligne illisible sautée et comptée) ; Recorder — `RewrapDue` du magasin PostgreSQL (clé de session renveloppée sous le nouvel identifiant, compare-échange) ; les deux `main.go` lancent une passe toutes les `KEY_REWRAP_SWEEP_SECONDS` (60) quand ils tiennent une clé précédente, et disent quand `KMS_KEY_HEX` peut partir. **Après** : rescellé en 1,2 s, audité, relu par Transit seul. Vault +6 tests (dont 1 PostgreSQL), Recorder +3 (PostgreSQL, dont une course jouée entre lecture et écriture), intégration +1 scénario. **8 mutations, 8 tuées** (une survivait : le compare-échange du Recorder, jamais mis à l'épreuve). **Trouvé en chemin** : la première version s'arrêtait à la première ligne illisible — une ligne d'une autre époque bloquait tout le reste ; et mon test avait oublié que, sans audit, le Vault ne rescelle rien. **Reste** : le Recorder ne l'écrit qu'au journal ; retirer la clé reste un geste de l'exploitant.

## Reliquat d'ADR-0053 : un jeton Transit remplacé sur disque est pris à chaud (ADR-0056)

**Mesuré avant** (sur `eacf0cf`, vrai OpenBao) : fichier réécrit avec un nouveau jeton, ancien révoqué → `fetch-credential` `503`. **Livré** : `pkg/transit` `ReloadToken` (lu avec les règles du démarrage, puis présenté à `lookup-self` avant d'être pris ; sinon l'ancien reste) et `WatchTokenFile` (toutes les `TRANSIT_TOKEN_RELOAD_SECONDS`, 30 ; un échec répété dit une fois ; jamais un jeton au journal) ; lancé par le Vault et le Recorder. **Après** : le secret est livré, l'ancien jeton révoqué. `pkg/transit` +2 tests ; **5 mutations, 5 tuées** (une d'abord écrite de façon à ne pas compiler, réécrite). **Reste** : jusqu'à une période entre le remplacement et la prise — l'ordre sûr est documenté.

## Reliquat d'ADR-0045 : les alertes en attente survivent à un redémarrage (ADR-0057)

**Mesuré avant** (sur `42996d4`, processus réels, vraie PostgreSQL) : récepteur en `503`, Audit Service tué avant le renvoi, un nouveau sur la même base → aucune alerte en 15 s. **Livré** : une interface `AlertQueue` (`alert_queue.go`) et deux mises en œuvre — mémoire (sans base, comme avant) et `alert_outbox` (migration `002_alert_outbox.sql`, clé = identifiant de l'événement, borne de 256 inchangée) ; le livreur prend ce qui est dû dans l'ordre de son heure, livre, repose ou oublie ; `main.go` prend la file PostgreSQL avec `DATABASE_URL` et le dit au démarrage. **Après** : livrée une fois après le redémarrage, même corps, signature valable, file vide. Audit +3 tests (joués chacun sur la mémoire et sur PostgreSQL) et +1 (une alerte écrite pendant que le livreur attend part aussitôt), intégration +1 scénario. **9 mutations, 9 tuées** (une survivait : le réveil du livreur, jamais mis à l'épreuve). **Trouvé en chemin** : une file pleine au démarrage fait écrire le livreur au journal avant `WithLogf` — course corrigée par un verrou. `alert_outbox` est ajoutée aux purges des tests. **Reste** : gardée après l'écriture de l'événement, pas dans la même transaction ; une seule instance de l'Audit Service.

## Reliquat d'ADR-0049 : AppRole pour Transit (ADR-0058)

Un jeton arrivé à sa durée maximale ne se renouvelait plus : il fallait qu'un tiers en écrive un autre. **Mesuré avant** (sur `aedb217`, vrai OpenBao) : AppRole donné avec un jeton est ignoré sans un mot ; sans jeton, `TRANSIT_TOKEN_FILE` est exigé. **Livré** : `pkg/transit/approle.go` — `TRANSIT_ROLE_ID_FILE` et `TRANSIT_SECRET_ID_FILE` (règle du jeton, relus à chaque connexion), `TRANSIT_APPROLE_MOUNT` ; une seule façon de se connecter ; `Probe` se connecte d'abord ; `KeepAlive` renouvelle à mi-vie et se reconnecte quand le renouvellement est refusé ou rend moins que la vie d'origine ; une connexion refusée est retentée et dite, le jeton en usage reste. **Après**, sur un vrai OpenBao : jetons de 3 s (5 s au plus), le Vault livre 12 s plus tard, le Vault et le Recorder disent s'être reconnectés, aucune valeur au journal ; trois configurations refusées par les deux services. `pkg/transit` +4 tests ; intégration +1 scénario. **8 mutations, 8 tuées** (deux survivaient : la reconnexion à la durée maximale — mon test ne regardait qu'un appel ; et le masquage, à cause du défaut ci-après). **Trouvé en chemin** : le masquage du jeton dans les erreurs remplaçait la chaîne vide pour un appel sans jeton (la connexion), et mettait « [token] » entre chaque lettre. **Reste** : le jeton précédent n'est pas révoqué ; un `secret_id` emballé n'est pas déballé ; un `secret_id` à usage limité s'épuise.

## Outillage : Dependabot (ADR-0059)

**Livré** : `.github/dependabot.yml` — 17 modules Go, 2 paquets npm, actions, `Dockerfile`, compose ; chaque lundi ; une version n'est proposée qu'à 7 jours (`cooldown`) ; une pull request par dépendance, la même dans tous les modules (`group-by: dependency-name`), jamais en masse (policy des dépendances, point 3, complétée) ; fusion humaine après la CI entière. **Pas vérifiable localement** : la configuration est lue par GitHub après le push (YAML vérifié avec Ruby : 5 sources). **Constaté à la première passe** : acceptée, 5 passes réussies, 6 pull requests (#3 à #8) ; pour Go, `lib/pq` est une pull request sur 7 modules ; pour les images, `node` en deux (une par `Dockerfile`) — le regroupement ne joue pas entre dossiers pour Docker. Intégration demandée par Bony Kiss le 31 octobre 2026 : #6 (`pkg/sftp` 1.13.12) fusionnée, CI verte ; #5 (`lib/pq` 1.12.3, 7 modules) et #7 (`tsup` 9.0.0) rebasées par Dependabot, fusionnées après une CI verte sur les 7 jobs (Trivy compris) — la première CI de #7 était tombée sur l'échec intermittent de `scp -O` ; **non intégrées** — #3 et #4 (Node 25, fin de vie le 1ᵉʳ juin 2026 : 24 et 22 LTS restent) et #8 (TypeScript 7 : `rollup-plugin-dts requires the TypeScript compiler API`, mesuré aussi avec `tsup` 9 ; le contourner ajouterait `@typescript/typescript6`, une dépendance nouvelle à demander). Ces majeures ne sont plus proposées (`ignore` de `dependabot.yml`) ; Dependabot a fermé #3, #4 et #8 lui-même à la prise en compte de la règle. **Reste** : les alertes et mises à jour de sécurité de Dependabot sont un réglage du dépôt, à activer par le propriétaire ; `go.work`, `GO_VERSION` et l'image OpenBao des tests restent manuels.

## Outillage : les images analysées par Trivy (ADR-0060)

**Mesuré** (Trivy 0.76.1) : l'image d'OpenBastion (cible `runtime`) — 0 vulnérabilité HIGH/CRITICAL corrigée, Debian 12.15 et 11 binaires ; `postgres:16` épinglée — 0 dans Debian, 26 dans `gosu` (Go 1.24.6 ; HIGH 25, CRITICAL 1), et la dernière `postgres:16` publiée est la même empreinte. **Livré** : job `images` et `make scan-images` (échec sur HIGH/CRITICAL corrigée) ; Trivy = l'archive vérifiée contre `TRIVY_SHA256`, **jamais** `trivy-action`/`setup-trivy` (CVE-2026-33634, mars 2026 ; policy des dépendances, point 5 ter) ; `.trivyignore.yaml` : les 26 constats de `gosu`, par chemin, jusqu'au 31 janvier 2027. **Éprouvé** : telle que commitée, la porte passe ; sans le fichier, elle échoue ; `gosu` copié sous un autre nom, elle échoue malgré le fichier ; entrées expirées, elle échoue. **Reste** : « non atteignable » est jugé ; images `tools` et Base44 non analysées ; signature Sigstore non vérifiée ; version de Trivy à relever à la main ; le nom du job est à ajouter au ruleset.

## v0.0.1, premier lot : la connexion par annuaire LDAP et Active Directory (ADR-0061)

Choisi par Bony Kiss le 31 octobre 2026 (point 10), avec `go-ldap` v3.4.15 (MIT) et des tests contre OpenLDAP et Samba AD ; ADR accepté le même jour. **Mesuré avant** (sur `f4ca8a7`) : la configuration LDAP est ignorée, aucune connexion par annuaire. **Livré** : `POST /auth/ldap/login` et `GET /auth/ldap` (Gateway, budget de connexion ; Authentication, routes réservées à `api-gateway`) ; `application/ldap.go` (port `Directory`, `LoginLDAP` : mot de passe vide et nom invalide refusés avant l'annuaire, rôles de la table seulement, compte `ldap:<id stable>`, code partagé avec OIDC dans `externalUser`) ; `infrastructure/ldap_directory.go` (TLS toujours, StartTLS pour `ldap://`, compte de service, nom échappé, une seule entrée, bind de l'utilisateur sur une connexion à part, groupes imbriqués en `ad`, GUID dans l'ordre d'AD) ; `main.go` (tout ou rien ; un annuaire muet au démarrage n'arrête pas le service) ; l'Admin UI propose « Annuaire de l'entreprise ». **Après** : contre OpenLDAP et Samba AD réels — les annuaires sont construits depuis `debian:13-slim` épinglée (`test/integration/testdata/ldap/`, vérifiés par `images_test.go`, suivis par Dependabot), sans privilège (Samba range ses ACL dans un `tdb`) — connexion, rôles, refus, `503`, budget, aucun mot de passe au journal (détail dans l'ADR). Authentication +9 tests unitaires, intégration +2 scénarios, Admin UI +3. **13 mutations, 12 tuées** ; la treizième a fait retirer le contrôle d'un compte AD désactivé, que l'annuaire fait déjà. **Trouvé en chemin** : sans StartTLS, le bind du compte de service partait en clair (le test du premier message le prouve désormais côté client) ; une course dans la page de connexion perdait le choix « Compte local » ; mon test démarrait le service avant `slapd`. **Reste** : le temps de réponse trahit l'existence d'un nom ; les échecs comptent pour le verrouillage de l'annuaire ; pas d'audit des connexions ; ni Kerberos, ni référence suivie, un seul annuaire.

## v0.0.1, deuxième lot : le second facteur TOTP par rôle (ADR-0062)

Choisi par Bony Kiss le 31 octobre 2026 avec ses deux décisions (par rôle, enrôlement par code d'administrateur) ; ADR accepté le 1ᵉʳ novembre 2026. **Mesuré avant** (sur `e6cdad8`) : un `platform-admin` obtient son jeton avec son seul mot de passe. **Livré** : `MFA_REQUIRED_ROLES` et `MFA_SECRET_KEY_HEX` ; `application/mfa.go` (TOTP RFC 6238 sur la stdlib, défi en deux temps, un code une fois, enrôlement par code d'administrateur, remise à zéro) ; `domain/mfa.go` et `infrastructure/mfa_store.go` (mémoire et PostgreSQL, migration `003_mfa.sql`), `mfa_sealer.go` (AES-256-GCM lié au compte) ; routes `/auth/v1/mfa/*` (utilisateur par la Gateway, administrateur par `admin-cli` seul) ; Gateway `/auth/mfa/*` dans le budget de connexion ; CLI `mfa enrollment-code`, `mfa reset` ; Admin UI : écran du code, écran d'enrôlement. **Après** : sur processus réels et PostgreSQL, du refus sans code à l'enrôlement, au redémarrage, au rejeu, à une autre clé, au budget et à la remise à zéro (détail dans l'ADR). Authentication +10 tests unitaires (dont 1 sur PostgreSQL), CLI +5 cas, appelants +14 cas (dont 4 pour les routes LDAP du lot précédent, qui n'y étaient pas), intégration +1 scénario, Admin UI +3. **15 mutations, 15 tuées** (une survivait : une assertion vide de mon test). **Trouvé en chemin** : la base PostgreSQL de test (`obpg`) ne redémarrait plus (« RWLayer … unexpectedly nil ») — recréée ; et j'ai vidé `Login.tsx` par une erreur de script, rétabli depuis le dernier commit avant de refaire la modification. **Reste** : pas de WebAuthn, pas de codes de secours, pas d'audit des gestes d'administration, pas de QR code ; la connexion d'annuaire avec MFA n'est éprouvée qu'en unitaire (pas contre OpenLDAP/Samba).

## Semantic Versioning (ADR-0063)

Demandé par Bony Kiss le 1ᵉʳ novembre 2026 : les jalons « v1.0 » et « v2.0 » deviennent **v0.0.1** et **v0.0.2** — 73 mentions renommées dans 37 fichiers (documentation, commentaires du code et des `proto`), **sauf** 3 dans les commentaires de migrations déjà appliquées (`001_init.sql` du Broker et de l'Audit Service : une migration ne change jamais, ADR-0030). **Livré** : `VERSION` (`0.0.1-dev`), `pkg/buildinfo` (stdlib : grammaire de semver.org, commit enregistré par Go), estampille `-X …buildinfo.Version=VERSION+<commit>` dans `make build`, le `Dockerfile` et la CI ; chaque service écrit sa version en première ligne de son journal, `openbastion-cli version` l'affiche ; `make version`, `make version-check [TAG=vX.Y.Z]` ; CI : job `version`, déclenchement sur les tags `v*` (tag = `v`+`VERSION`, sans pré-version), image de release estampillée de la release, `make scan-images` vérifie que l'image dit sa version. **Mesuré** : `0.0.1-dev+91e3a1ed269d` dans l'image ; les trois cas de tag ; un service et la CLI estampillés, un binaire sans estampille dit `dev` (`pkg/buildinfo` 3 tests, intégration +1). **Reste** : aucun tag n'est posé (geste du propriétaire) ; ni `CHANGELOG.md` ni release publiée ; SemVer 0.y.z ne promet aucune compatibilité.

## v0.0.1, troisième lot : les connexions à l'audit (ADR-0064)

Accepté par Bony Kiss le 1ᵉʳ novembre 2026 avec ses deux réponses (connexion fail-closed, refus écrits dans un budget). **Mesuré avant** (sur `3dfb1c2`) : rien dans la chaîne ; l'audit coupé, un jeton quand même. **Livré** : `application/audit.go` (port, `ErrAuditUnavailable`, refus au mieux dans `pkg/refusalbudget` par nom de connexion, nom borné et désarmé), `infrastructure/audit_client.go` ; `auth.login` / `auth.login_mfa` écrits avant le jeton (local, annuaire, OIDC) ; `auth.mfa_enrollment_code_issued`, `auth.mfa_enrolled`, `auth.mfa_reset` avant le geste, l'acteur étant l'identité du certificat de l'appelant ; `/auth/login` répond `503` quand l'audit manque ; l'Audit Service admet `authentication` ; `AUDIT_URL` dans les deux fichiers compose. **Après** : sur processus réels et un vrai Audit Service, mTLS compris (détail dans l'ADR). Authentication +4 tests unitaires, appelants de l'audit +2 cas, contrat +1 paire, intégration +1 scénario ; le harnais donne un récepteur d'audit de test aux Authentication Service démarrés sans `AUDIT_URL` (environ 30 scénarios qui ne parlent pas d'audit). **14 mutations, 14 tuées** (trois réécrites : elles ne compilaient pas). **Reste** : l'Audit Service est une dépendance de toute connexion ; refus au-delà du budget non écrits ; budget par processus.

## v0.0.1, quatrième lot : WebAuthn, seul second facteur des rôles stricts (ADR-0065)

Choisi par Bony Kiss le 1ᵉʳ novembre 2026 avec `go-webauthn` v0.18.2 (BSD-3 ; sept modules liés, MIT/BSD/Apache) et « second facteur + rôles stricts » ; ADR accepté le même jour. **Mesuré avant** (sur `f688964`) : un `platform-admin` « strict » se connecte avec son seul mot de passe. **Livré** : `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS`, `MFA_PHISHING_RESISTANT_ROLES` ; `application/webauthn.go` (port sans type de la bibliothèque ; facteurs offerts selon le rôle et ce que le compte détient ; TOTP refusé aux rôles stricts ; une clé dont le compteur recule refusée — la bibliothèque ne fait que le signaler) ; `infrastructure/webauthn_verifier.go` ; migration `004_webauthn.sql` ; routes `/auth/mfa/webauthn/verify` et `/auth/mfa/webauthn/enroll/confirm`, `factor` sur `/auth/mfa/enroll` ; la Gateway transmet la réponse du navigateur seulement si c'est un objet ; Admin UI : `shared/webauthn.ts` (sans dépendance) et l'écran du second facteur. **Après** : sur processus réels avec un authentificateur logiciel écrit dans le test (sa propre CBOR, ses propres signatures) — enrôlement, connexion, refus de ce qu'enverrait l'hameçonnage (autre origine, autre `rpId`), d'une fausse signature, d'une clé de personne, d'un compteur qui recule, d'un défi servi, de TOTP pour un rôle strict (détail dans l'ADR). Authentication +6 tests unitaires, appelants +3 cas, intégration +1 scénario, Admin UI +4. **15 mutations, 14 tuées** ; la quinzième (la borne de 5 clés) est sans effet observable. **Écart à l'ADR** : la clé de secours n'est pas livrée — un compte enrôlé reçoit un défi de vérification, jamais d'enrôlement (c'est ce qui protège d'un remplacement du second facteur) ; ajouter une clé demande un parcours à concevoir. **Reste** : attestation `none` ; vérification de l'utilisateur non exigée ; un rôle strict ne passe que par un navigateur.

## v0.0.1, cinquième lot : la clé de secours (ADR-0066)

Referme l'écart d'ADR-0065, avec les deux décisions de Bony Kiss du 1ᵉʳ novembre 2026 (la clé actuelle **et** un code d'administrateur ; la révocation par l'administrateur). **Mesuré avant** (sur `ce4c567`) : `404` pour l'ajout, la liste et la révocation. **Livré** : `AddWebAuthnKey` (signature fraîche d'une clé du compte sur le défi, code d'enrôlement de ce compte ; le défi devient un enregistrement par compare-échange en base, une fois) ; `WebAuthnKeys` et `RevokeWebAuthnKey` (audit avant, les autres clés restent) ; migration `005_webauthn_last_used.sql` ; routes `/auth/mfa/webauthn/keys/add` (Gateway, budget de connexion), `/auth/v1/mfa/keys` et `/auth/v1/mfa/revoke-key` (`admin-cli` seul) ; CLI `mfa keys`, `mfa revoke-key` ; Admin UI « Ajouter une clé de secours ». **Après** : sur processus réels avec l'authentificateur logiciel (détail dans l'ADR). Authentication +4 tests unitaires et +1 contrat de magasin (mémoire et PostgreSQL), appelants +5 cas, CLI +3 cas, intégration +2 sous-tests, Admin UI +1. **10 mutations, 10 tuées** (deux réécrites ou mieux visées). **Reste** : l'utilisateur ne révoque pas lui-même une clé ; liste et révocation par la CLI seulement.

## Prochains incréments qui lèveront cette limite

Dans un environnement de développement ou de CI avec accès réseau complet :

1. ~~`buf generate` sur `proto/` produira le code gRPC réel~~ — écarté par ADR-0050 (HTTP/JSON décidé, test de contrat) ; les fichiers `internal/interfaces/http.go` seront remplacés par des serveurs gRPC générés, sans toucher `internal/application`.
2. ~~Remplacer `LocalKMS` par un vrai client KMS/HSM externe~~ — fait pour Transit (ADR-0049) — `KMS_KEY_HEX` est une étape vers une clé stable, pas un KMS réel ; voir le commentaire de doc de `NewLocalKMS`. **Vérifié bloqué dans ce sandbox** (contrairement au pari qui a payé pour `github.com/golang-jwt/jwt/v5`) : `go get github.com/hashicorp/vault/api@v1.15.0` tire transitivement `golang.org/x/net` et `golang.org/x/time` — aucun `replace` GitHub n'existe pour eux (seuls `x/crypto` et `x/sys` en ont un) — et `go get github.com/aws/aws-sdk-go-v2/service/kms@v1.33.0` time-out de la même façon ; les deux ont été testés avec `GOPROXY=direct GOSUMDB=off`, 30s chacun, aucune sortie après le premier (`hashicorp/vault/api`) ou aucune sortie du tout (`aws-sdk-go-v2/service/kms`). Un `go get github.com/golang-jwt/jwt/v5` témoin, lancé juste après dans un module vierge, a réussi en quelques secondes — la cause est bien les dépendances transitives de ces deux SDK, pas une dégradation réseau générale du sandbox. Lever ce blocage demanderait soit un accès réseau complet, soit d'ajouter les mêmes `replace` GitHub que pour `x/crypto`/`x/sys` à `golang.org/x/net` et `golang.org/x/time` (non tenté : risque de miroir GitHub introuvable ou désynchronisé, pour un gain incertain tant que le SDK complet n'a pas pu être résolu une seule fois de bout en bout).
3. Toutes les bascules PostgreSQL de ce projet reposent maintenant sur le même patron, prouvé six fois (Vault, Authorization, Authentication, Session Broker, Audit — plus `audit-service` qui ajoute la contrainte propre au chaînage de hash). `idempotency_keys` et le partitionnement mensuel d'`audit_events` (`docs/architecture/data-architecture.md` §3) restent les seules parties du DDL documenté qui n'ont pas encore d'équivalent dans le code (`session_command_entries` a le sien depuis le Command Recorder) — aucune n'est bloquée par le sandbox, simplement pas encore faites.

## État des tests à la date de cet incrément

**Mesuré le 31 octobre 2026, après ADR-0049** (vérification complète, comptes `grep -c '^--- PASS'`) : `make build vet` vert ; unitaires 778 sans base, 838 avec, 0 échec ; `make test-postgres` 78 (dont le scénario contre un vrai OpenBao) ; intégration 51 sans base, 76 avec, 0 échec ; `-race` sur `pkg/transit`, le Vault et le Command Recorder : vert, aucune course ; Admin UI 25 tests, construction verte ; `gofmt -l` vide. Les paragraphes et le tableau ci-dessous datent des incréments précédents.

788 tests unitaires Go passés avec base (comptés `--- PASS` de premier niveau ; dont 59 conditionnés à `TEST_DATABASE_URL` — 14 pour le Vault, 5 pour Authorization, 6 pour Authentication, 19 pour Session Broker, 5 pour Audit, 10 pour le Command Recorder — qui se *skip*, pas échouent, sans elle : 729 passent et 59 sont ignorés sans base, 788 passent avec, 0 échec — mesuré après ADR-0044), plus 25 tests de l'Admin UI (Vitest, `make ui-test`), plus 72 tests d'intégration (dont 24 conditionnés à `TEST_DATABASE_URL` et 1 à `COMPOSE_TEST` : 47 passent et 25 sont ignorés sans base, 71 passent avec et le test Compose passe à part, `make test-compose`), `go vet` propre, `gofmt -l` vide sur les fichiers modifiés, `go test -race` propre — **pour ADR-0022 à ADR-0044, sur les modules touchés seulement** (ADR-0044 : Vault, Session Broker ; ADR-0043 : Vault, Authorization, Session Broker, Gateway, ssh-proxy ; ADR-0042 : Session Broker ; ADR-0039 à ADR-0041 : `pkg/proxycore`, ssh-proxy, Password Vault) (Command Recorder, Audit Service, Gateway ; puis Session Broker ; puis `pkg/refusalbudget`) et sur leurs tests d'intégration ; les 11 modules l'avaient été à ADR-0021. 65 tests PostgreSQL dédiés (`make test-postgres`), dont ceux de persistance inter-processus (Vault, Authorization, Authentication, Audit, Session Broker, Command Recorder), vérifiés avec une vraie base PostgreSQL 16 — pour cet incrément, dans un conteneur Docker du codespace (`settings.md` §7). Avant SFTP et SCP (ADR-0038) : 722 unitaires, 65 PostgreSQL, 66 d'intégration. Avant la rotation sur la cible (ADR-0037) : 710 unitaires, 64 PostgreSQL, 65 d'intégration. Avant l'Admin UI (ADR-0036) : 706 unitaires, 64 PostgreSQL, 65 d'intégration. Avant la connexion fédérée (ADR-0035) : 694 unitaires, 62 PostgreSQL, 64 d'intégration. Avant l'expiration écrite (ADR-0034) : 687 unitaires, 59 PostgreSQL, 63 d'intégration. Avant le déploiement Compose (ADR-0033) : 685 unitaires, 59 PostgreSQL, 62 d'intégration. Avant la rétention (ADR-0032) : 664 unitaires, 57 PostgreSQL, 61 d'intégration. Avant les migrations versionnées (ADR-0030) : 659 unitaires, 56 PostgreSQL, 53 d'intégration. Avant l'ancrage (ADR-0028) : 649 unitaires, 55 PostgreSQL, 52 d'intégration. Avant la chaîne à clé (ADR-0027) : 641 unitaires, 54 PostgreSQL, 51 d'intégration. Avant le hash canonique (ADR-0026) : 632 unitaires, 52 PostgreSQL, 50 d'intégration. Avant les bornes de l'Audit Service (ADR-0025) : 628 unitaires, 52 PostgreSQL, 49 d'intégration. Avant l'audit des refus de lecture d'un enregistrement (ADR-0024) : 621 unitaires, 52 PostgreSQL, 47 d'intégration. Avant l'audit de la liste (ADR-0023) : 616 unitaires, 52 PostgreSQL, 46 d'intégration. Avant l'audit des lectures d'enregistrement (ADR-0022) : 607 unitaires, 52 PostgreSQL, 45 d'intégration. Avant l'audit des lectures servies (ADR-0021) : 598 unitaires, 52 PostgreSQL, 44 d'intégration. Avant l'audit des refus de lecture (ADR-0020) : 573 unitaires, 52 PostgreSQL, 42 d'intégration. Avant la lecture contrôlée (ADR-0019) : 547 unitaires, 52 PostgreSQL, 41 d'intégration. Avant la terminaison réelle (ADR-0018) : 495 unitaires, 52 PostgreSQL, 40 d'intégration. Avant le contrôle de la terminaison (ADR-0017) : 473 unitaires, 52 PostgreSQL, 39 d'intégration ; avant le budget d'actions de session (ADR-0016) : 463 unitaires, 52 PostgreSQL, 37 d'intégration ; avant l'adresse du client derrière l'arête (ADR-0015) : 450 unitaires, 52 PostgreSQL, 33 d'intégration ; avant la limitation de débit par identité (ADR-0014) : 434 unitaires, 52 PostgreSQL, 29 d'intégration ; avant le plafond par demandeur (ADR-0013) : 405 unitaires, 49 PostgreSQL, 27 d'intégration ; avant la découverte des demandes (ADR-0012) : 360 unitaires, 46 PostgreSQL, 23 d'intégration ; avant la double validation : 326 unitaires, 42 PostgreSQL, 20 d'intégration ; avant l'incrément mTLS : 274 unitaires, 42 PostgreSQL, 17 d'intégration ; avant le break-glass : 234 unitaires, 40 PostgreSQL, 15 d'intégration ; avant « enregistrer ou refuser » : 193 unitaires, 39 PostgreSQL, 13 d'intégration. (Comptage : `grep -c '^--- PASS'` sur `go test -v`, tests de premier niveau seulement — les sous-tests ne comptent pas.)

Rappel d'ordre d'exécution (déjà documenté plus haut, mais je l'ai retrouvé en vérifiant ce lot) : lancer `make test` avec `TEST_DATABASE_URL` puis `make test-integration` **sans purge entre les deux** fait échouer `TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart` sur un 403 — les tests unitaires PostgreSQL ont laissé des lignes dans `policies`, et le bootstrap de `platform-admin` ne s'exécute que sur un magasin vide. Ce n'est pas une régression : purger (`TRUNCATE policies, … RESTART IDENTITY CASCADE`) avant chaque suite, ou passer par `make test-postgres`, qui le fait.

**Particularité du test de redémarrage d'`audit-service`** : contrairement à `Count()`/`ForRoles()` ailleurs dans ce projet, `VerifyChain` relit la table `audit_events` **entière** depuis le tout premier événement — une seule ligne avec un hash non authentique (comme en écrivent délibérément les tests unitaires de `postgres_store_test.go`, qui exercent `Append` directement sans passer par le vrai calcul de hash) la casse **définitivement**, pas seulement le temps d'une assertion. `TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart` commence donc par un `TRUNCATE audit_events` explicite, pour rester déterministe quel que soit ce qui a tourné avant lui — un geste plus strict que le `TRUNCATE` déjà documenté pour les exécutions complètes, mais nécessaire spécifiquement ici.

**Un sixième problème réel trouvé pendant ce même incrément, dans le Makefile cette fois, pas dans le code applicatif.** `make test-postgres` enchaînait déjà les suites `*_store_test.go` (qui écrivent des lignes directement dans `policies`, entre autres) puis `test/integration` dans la même invocation. Dès que cinq services y écrivent au lieu de deux, `TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart` échoue systématiquement sur un 403 : `BootstrapAdminPolicy` voit un magasin non vide (à cause des lignes que les tests `*_store_test.go` viennent d'écrire dans la même exécution) et refuse — par conception — de bootstraper `platform-admin`. Une purge unique en tête de cible ne suffit pas, puisque ce sont les tests qui tournent *après* elle, dans la même invocation, qui polluent. Corrigé en purgeant une seconde fois juste avant la ligne `test/integration` — `make test-postgres` est maintenant vraiment rejouable d'affilée, sans geste manuel, vérifié par deux exécutions consécutives.

```
pkg/mtls (+ pki, cmd/openbastion-pki)                         38 tests (28 + 8 + 2 : identité, réglages, rechargement, poignée de main réelle, garde, rotation, exécution ; PKI ; CLI)
pkg/proxycore                                                 89 tests (+24 ADR-0018 : registre des connexions et mémoire des révocations, `Serve` coupé / refusé / jamais démarré ; 65 avant : 29 avant ADR-0008 : Recording Tap — terminateurs, édition de ligne, échappements, prompts de secret ; +18 : tap exigeant, politique, admission, perte d'enregistrement ; +18 ADR-0009 : dérogation, admission-preuve, expiration)
cli/openbastion-cli                                            2 tests (ADR-0033 : onze demandes refusées avant le réseau — commande inconnue, URL, nom, rôles, mot de passe vide ou en argument, certificat absent —, aucun appel sans mTLS)
pkg/migrate                                                    5 tests (ADR-0030 : fichiers numérotés lus dans l'ordre et checksum, onze ensembles refusés — trou, doublon, nom, extension, vide —, un verrou par service, nom de service exigé, journal de ce qui est appliqué et de ce qui est inconnu ; le comportement contre PostgreSQL est dans `test/integration`)
pkg/refusalbudget                                             13 tests (le seau à jetons par identité des refus écrits dans l'audit, déplacé du Broker à ADR-0024 : rafale, débit, isolation par clé, balayage, horloge qui recule, défauts stricts ; partagé par le Broker et le Recorder)
pkg/webhook                                                    9 tests (ADR-0045 : URL vérifiée et jamais répétée, secret ≥ 32 octets, signature recalculée indépendamment, pas de redirection, délai, texte désarmé)
services/access/api-gateway/internal/application              19 tests (dont 1 ADR-0016 : défauts, bornes et unités du limiteur d'actions ; 8 ADR-0015 : en-tête jamais lu sans confiance, première adresse qui n'est pas un proxy, pair non déclaré, tout doute retombe sur le pair, clés normalisées, configuration acceptée, 23 formes douteuses refusées, défauts des limiteurs ; 7 ADR-0014 : unités sous leur nom, `Retry-After` vrai et arrondi au-dessus, épisode annoncé une fois, défauts stricts ; éviction : propriété contre une référence qui n'évince jamais, mémoire bornée, seau vidé jamais oublié avant d'être plein)
services/access/api-gateway/internal/interfaces                64 tests (dont 4 ADR-0036 : en-têtes de sécurité sur chaque réponse de `/ui/` et la page pour ses routes, rien hors du répertoire et lecture seule, répertoire refusé, rien sans `ADMIN_UI_DIR` ; dont 6 ADR-0019 : le Broker reçoit qui lit et avec quels rôles, pas le client ; rôles encodés ; sans jeton rien n'atteint le Broker ; ce que le Broker répond est relayé tel quel ; `502` sans adresse ; lecture hors budget ; 6 ADR-0017 : le Broker reçoit qui demande et avec quels rôles, pas le client ; sans jeton rien n'atteint le Broker ; `DELETE` dans le seau unique, `Retry-After` vrai, seau propre à l'utilisateur ; lecture et mauvaise méthode gratuites ; 9 ADR-0016 : rafale puis refus pour approve, reject et connect sans que le Broker voie les refusés, un seau pour les trois, distinct de celui de `POST /sessions` dans les deux sens, par utilisateur et non par adresse ni session, seules les trois routes sont comptées, `Retry-After` vrai, Gateway construit à la main strict, ligne de journal par épisode sans jeton, réponse du Broker relayée telle quelle ; 5 ADR-0015 : un seau par client derrière un proxy déclaré et un seul sans lui, rien ne se forge (pair non déclaré, gauche de l'adresse du proxy, lignes d'en-tête), budget de `POST /sessions` resté par utilisateur, `nil` ne fait pas oublier une déclaration ; 9 ADR-0014 : budget par utilisateur et non par adresse ni corps, compté avant la lecture du corps, le Broker jamais atteint par un refusé, `Retry-After` vrai, ligne de journal par épisode sans jeton, login et requêtes authentifiées disent la vérité ; 1 ADR-0013 : le 429 et son motif relayés tels quels ; 3 GET /sessions/{id}/recording ; 4 ADR-0012 : la liste porte l'identité du jeton et non celle du client, rôles encodés, aucun corps relayé ; 5 ADR-0011 : identité du jeton et non du corps, liste blanche des routes, 401 sans jeton)
services/access/authentication/internal/application            12 tests (dont 6 ADR-0035 : rôles de la table et compte `oidc:<sub>`, état pris une fois et expiré, aucun rôle refusé et rôles qui suivent les groupes, code refusé et jeton d'une autre tentative, désactivé sans configuration, table des rôles refusée)
services/access/authentication/internal/infrastructure          28 tests (dont 5 ADR-0035 du client OIDC : jetons RS256 et ES256 valides, vingt forgés ou mal adressés refusés, rotation et rythme des clés, PKCE et secret du client, fournisseur refusé ; dont 6 PostgreSQL TEST_DATABASE_URL, 4 clé de signature, 2 alg confusion JWT)
services/access/authorization/internal/application              12 tests (dont 6 RBAC/bootstrap)
services/access/authorization/internal/infrastructure            4 tests PostgreSQL (TEST_DATABASE_URL)
services/access/session-broker/internal/application            129 tests (dont 4 ADR-0034 : ce qui est passé son échéance expire et s'écrit comme une action du système, une fois ; audit coupé, les expirations attendent et s'écrivent au balayage suivant sans délai de grâce ; ce qu'un autre réplica a laissé, après le délai ; un service sans horloge donnée ; 13 tests du seau à jetons déplacés dans `pkg/refusalbudget` à ADR-0024 ; dont 5 ADR-0023 : un événement par demande de la page servie aux champs exacts, 25 listes = 25 événements, trois pages vides sans événement, rien de servi sans l'audit puis servi à son retour, rien d'écrit pour une liste non décidée ; 7 ADR-0021 : l'événement `session.read` au nom de qui a lu, écrit avant que la session soit servie, jamais sans lui ; requérant et décideur sans événement ni dépendance de l'audit ; un événement par lecture, sans budget ; 22 ADR-0020 : le seau — rafale, débit et unités, plafond même avant le balayage, isolation par identité, premier refus non écrit, valeurs non positives, mémoire bornée, seau non rempli gardé, horloge qui recule, concurrence — et le service — événement au nom de qui a demandé, rien pour ce qui n'est pas un refus, budget strict par défaut et réglable, refus identique budget épuisé, audit en panne, une ligne de journal par épisode, horloge du service ; 14 ADR-0019 : qui lit — demandeur, décideur, politique —, refus sans fuite, ordre, Authorization muette, base muette, une lecture n'écrit rien, requérant exact ; 7 ADR-0018 : ordre proxy puis enregistrement, marge, date, échec audité sous le nom de l'appelant, rejeu ; 12 ADR-0017 : terminaison par le demandeur ou une autorité, refus audité sous le nom de l'appelant, ordre session → appelant → état, fail-closed, course perdue ; 13 ADR-0013 : plafond par demandeur, libération, atomicité sous 40 goroutines, fail-closed, sans approbation ; 19 ADR-0012 : liste filtrée par l'autorité, fail-closed, une question par compte, bornes, notifications, identifiant de compte ; 10 break-glass : chaque verrou, audit fail-closed, extinction immédiate ; 19 double validation : auto-approbation, audit avant d'agir, horloge, règles du jour, propriété du connect)
services/access/session-broker/internal/infrastructure           62 tests (dont 7 ADR-0046 : le pool des instances du proxy — révocation demandée à toutes et confirmée par toutes, en parallèle, tickets à tour de rôle, repli, refus d'enregistrer, bornes ; recompté le 31 octobre 2026 ; notificateur break-glass sur pkg/webhook depuis ADR-0045, tests inchangés ; dont 3 ADR-0034 : contrat d'expiration mémoire et PostgreSQL — échéance stricte, plus proche d'abord, par lots, une fois, comparer-échanger perdu, à écrire jusqu'à la marque, délai — et huit balayeurs sur deux connexions, 300 sessions expirées une fois chacune ; dont 6 ADR-0018 du client HTTP de la révocation ; 6 ADR-0013 de plafond — contrat mémoire/PostgreSQL, course sur deux réplicas — et 6 de signature du webhook ; 6 `ListPending` — contrat mémoire et PostgreSQL, index partiel — et 10 du webhook ; 16 PostgreSQL TEST_DATABASE_URL, avec `break_glass`, la décision, le compare-and-swap concurrent et deux mises à niveau en place ; 2 magasin mémoire : compare-and-swap ; 2 client du proxy : 503 « recording unavailable » reconnu, pas un 409 ; `break_glass` transmis)
services/access/session-broker/internal/interfaces                35 tests (dont 2 ADR-0021 : l'événement sous le nom de l'appelant de la requête, `503` sans cause ni session ; 3 ADR-0020 : l'événement sous le nom de l'appelant de la requête, ce qui n'est pas un refus n'écrit rien, même réponse quel que soit le budget ; 6 ADR-0019 : l'appelant est la requête du Gateway et rien d'autre, codes, refus sans rien de la session, Authorization interrogée avec les rôles de la requête, `503` sans la cause, une lecture ne change rien ; 1 ADR-0018 : `503` sans la cause quand le proxy ne répond pas ; 4 ADR-0017 : le corps du Gateway et rien d'autre, codes, `503` sans la cause et cause dans le journal, Authorization interrogée avec les rôles du corps ; 3 ADR-0013 : 429 avec le plafond, autres refus restés 403, 503 sans la cause ; 6 ADR-0012 : liste, 400, 503 sans la cause, vide et non `null`, page bornée, `truncated` ; 503 pour un enregistrement indisponible, 409 pour le reste ; `breakGlass` : 403 avec la raison, 201 avec le drapeau ; 2 tables d'appelants ; 4 approbation : cycle complet, codes, 503 sans la cause, `connect` réservé au demandeur)
services/proxy/ssh-proxy/internal/infrastructure                 23 tests (+4 ADR-0018 : tickets d'une session et elle seule, concurrence ; AsyncRecorder, client du Command Recorder, SyncRecorder : classification des erreurs rejouables, Ready)
services/proxy/ssh-proxy/internal/interfaces                     15 tests (dont 9 ADR-0018 : route de révocation, 400/405, `503`, durée et plafond de la mémoire, `establish-session` refusé, et les règles d'appelants ; hook d'admission → 503 à EstablishSession ; `break_glass` porté jusqu'au ticket)
services/proxy/ssh-proxy/internal/sshcodec                       14 tests (dont 1 ADR-0018 : coupe pendant la poignée de main ; vrai protocole SSH, 3 participants ; enregistrement interactif avec prompt `sudo` ; 4 « enregistrer ou refuser » avec une cible qui rapporte chaque ligne reçue ; 6 break-glass et coupure à l'échéance)
services/vault/password-vault/internal/application               26 tests (dont 6 RBAC, 1 versionnement, 6 liste/désactivation de comptes, 2 lastRotatedAt, 1 bornage de pagination)
services/vault/password-vault/internal/infrastructure            14 tests (dont 8 PostgreSQL TEST_DATABASE_URL, 6 LocalKMS)
services/recording-audit/audit-service/internal/application       49 tests (dont 7 ADR-0045 : seul l'émetteur déclaré pousse une alerte, rien de ce que la chaîne a refusé ; dont 15 ADR-0032 : rien sans configuration, les mois plus vieux que la rétention partent et la chaîne restante se vérifie, rien ne part d'une chaîne qui ne se vérifie pas ni sans archive écrite, reprise après une panne avant la suppression et avant l'événement — une seule fois —, archive changée non suivie, début coupé trouvé avec ou sans archivage, point de contrôle modifié, retiré, déplacé ou forgé, ancre non archivée exigée, mois retenus gardés, clé non tenue nommée, chaîne réécrite sans clé avant toute ancre — en attente de suppression et après —, vecteur du MAC ; dont 5 ADR-0028 : une ancre par tête et rien pour une chaîne vide, l'ancre nomme ce que le processus a écrit et non ce que la base dit ensuite, la chaîne contre ses ancres, ancres illisibles sans verdict, vecteur du MAC d'ancre ; dont 7 ADR-0027 : clés, identifiant, fin de chaîne recalculée sans clé, rotation, émetteur, ligne sans clé, vecteur v3 ; dont 8 ADR-0026 : cinq frontières, format courant, chaîne héritée, versions, vecteurs figés, version inconnue sans hash, hash vide ; dont 2 ADR-0025 : bornes exactes acceptées, quinze formes refusées sans répéter la valeur ni toucher la chaîne ; dont 1 précision d'horodatage)
services/recording-audit/audit-service/internal/infrastructure    22 tests (dont 8 ADR-0045 : webhook d'alerte signé, renvois, abandon à 5, file bornée, URL jamais écrite ; 3 ADR-0032 du fichier d'archive : chaque champ, relu, privé, sans temporaire ; jamais écrasé ; chemins et noms refusés ; 2 ADR-0032 du fichier d'ancres : points de contrôle relus et ligne d'ancre inchangée au caractère près, lignes d'un autre genre refusées ; 1 ADR-0032 PostgreSQL : `DeleteThrough` exactement ou rien ; 4 ADR-0028 du fichier d'ancres : ajout et relecture dans l'ordre, fichier disparu illisible et non recréé, ligne qui n'est pas une ancre, chemins refusés ; 5 PostgreSQL TEST_DATABASE_URL, dont 1 ADR-0026 : `hash_version` relu tel qu'écrit)
services/recording-audit/audit-service/internal/interfaces        5 tests (dont 1 ADR-0028 : ancres illisibles → `503`, jamais `200` ; dont 1 ADR-0027 : l'émetteur est celui du certificat, pas du corps ; 1 d'appelants ; 2 ADR-0025 : codes et corps de chaque refus d'emit-event, erreur du store générique et journalisée)
services/recording-audit/command-recorder/internal/application   24 tests (dont 6 ADR-0024 : refus sous le nom de l'appelant, budget par identité, même refus écrit / supprimé / perdu, une ligne par épisode, lectures servies sans jeton dépensé, identifiant impossible ; dont 6 ADR-0022 : un événement par page aux champs exacts, page vide comprise, rien servi sans l'audit puis servi à son retour, pas de nom ⇒ refus sans rien interroger, un refus n'écrit pas de succès, une page que le store n'a pas lue n'est pas dans la trace ; ordre, lot tout ou rien, normalisation, pagination, RBAC fermé par défaut, refus identique qu'une session existe ou non, Ready)
services/recording-audit/command-recorder/internal/infrastructure 19 tests (dont 1 ADR-0022 : le client d'audit envoie l'événement champ pour champ et ne croit qu'un `200` ; chiffrement enveloppe ; contrat mémoire ; contrat PostgreSQL, lot atomique, visibilité inter-connexions et readiness : 10 TEST_DATABASE_URL)
services/recording-audit/command-recorder/internal/interfaces     6 tests (dont 2 d'appelants ; 1 ADR-0024 : `400` pour un identifiant impossible ; dont 2 ADR-0022 : la lecture sous le `callerId` du Gateway et `403` sans lui ; `503`/`500` au corps générique, cause au journal ; `/readyz` suit l'état du store, 503 sans exposer la cause ; `/healthz` ne suit que le processus)
test/integration                                                 74 tests (dont 1 ADR-0046 sur deux proxys SSH réels ; recompté le 31 octobre 2026 avec base ; dont 2 ADR-0045 sur processus réels ; dont 1 ADR-0035 sur processus réels et vraie PostgreSQL, fournisseur OIDC joué par le test : tout ou rien, budget de connexion, rôles de la table seulement, rejeu et état forgé refusés, rôles qui suivent les groupes en base, identité sans rôle refusée sans compte, pas de mot de passe, connexion à cheval sur un redémarrage ; dont 1 ADR-0034 sur processus réels et vraie PostgreSQL : bornes, une session inutilisée et une demande non décidée expirées en base, audit coupé puis rétabli — écrit une fois, sans acteur —, rien d'autre touché, deux Brokers sur 40 sessions ; dont 1 ADR-0033 sous COMPOSE_TEST : la pile docker-compose réelle, parcours du MVP sur les ports publiés, CLI, secrets absents des journaux, clés isolées, bases isolées, redémarrage ; dont 1 ADR-0032 sur processus réel et vraie PostgreSQL : configurations refusées, deux mois archivés au démarrage, chaîne restante vérifiée, début coupé et point de contrôle retiré trouvés ; dont 8 ADR-0030 : réplicas démarrés ensemble sur processus réels — 20 sur 20, base d'avant gardée et enregistrée, migration modifiée refusée, base en avance dite — et 7 de `pkg/migrate` sur vraie PostgreSQL ; dont 1 ADR-0028 sur processus réel et vraie PostgreSQL : réécriture entière au format v2 et fin coupée trahies par l'ancre, ancre modifiée, fichier disparu `503`, une ancre par tête, configuration fatale ; 1 ADR-0027 ; 1 ADR-0026 ; 1 ADR-0025 ; dont 2 ADR-0024 sur processus réels : refus sous le nom de qui a demandé, nom forgé écarté, budget de 3 sur onze refus, budget propre à chacun, lectures servies non comptées, refus identique l'audit tombé, `400` sans événement ; configuration fatale hors bornes et annonce vraie ; dont 1 ADR-0023 sur processus réels : chaque demande servie à l'approbateur est un événement sous son nom avant la réponse, nom forgé écarté, seulement la page servie, liste vide sans événement même l'audit tombé, `503` sans rien des demandes, puis servie et écrite à son retour, chaîne vérifiée ; 1 ADR-0022 sur processus réels : la lecture d'un enregistrement par Carol, un événement sous son nom avant la réponse, nom forgé écarté, dix-sept lectures dix-sept événements, refus sans événement, `503` sans les commandes avec l'audit tombé, puis servi et écrit à son retour, chaîne vérifiée ; 1 ADR-0021 sur processus réels : la lecture de Carol, un événement sous son nom avant la réponse, `503` avec l'audit en panne ; 2 ADR-0020 sur processus réels : refus audité sous le nom de qui a lu, requête forgée sans effet sur l'auteur, onze refus sur deux sessions = trois événements et onze `403`, budget propre à chaque identité, lectures servies et `404` sans événement, chaîne d'audit intacte ; configuration invalide, bornes et ligne de démarrage — **rouge avant** ; 1 ADR-0019 sur processus réels : le demandeur lit sans politique, un tiers et `nobody` reçoivent `403` sans rien apprendre, une requête forgée ne change rien, une politique sur le compte lit et sur un autre non, les politiques de terminaison et d'approbation ne lisent pas, inconnu `404`, sans jeton `401` — **rouge avant (4 affirmations sur 6)** ; plus quatre lectures forgées dans la table d'attaque mTLS ; 1 ADR-0018 sur processus réels : deux shells coupés, ticket mort, frappe sans effet, autre session intacte, session terminée non reconnectable, connect en vol, proxy arrêté puis relancé, corps invalides ; appels forgés vers `revoke-session` dans `mtls_flow_test.go` ; 1 ADR-0017 sur processus réels, huit sous-tests : refus sous le nom de l'appelant, corps forgé, approbateur sans politique de terminaison, autorité nommée dans l'audit, autre compte, demandeur sans politique, 404/409/401, refus jusqu'au budget ; 2 ADR-0016 sur processus réels : témoin sans budget (12 refus = 12 événements d'audit) puis budget de 3 (8 approbations, 3 événements), un seau pour les trois routes, budget propre à chaque utilisateur, lectures et `terminate` non ralentis, `Retry-After` vrai ; limites invalides et annonce du démarrage vraie ; 4 ADR-0015 sur processus réels : un seau par client derrière un proxy déclaré, personne ne choisit sa clé — dont un attaquant depuis 127.0.0.2 —, limites réglées qui s'appliquent, configuration douteuse et annonce vraie ; 4 ADR-0014 sur processus réels : budget d'un utilisateur sans droit, 60 par minute des requêtes authentifiées, login en rafale de 5 puis une par minute, limite invalide et annonce vraie ; 2 ADR-0013 sur processus réels : rafale d'un demandeur sur cinq processus avec signature vérifiée par un récepteur indépendant, plafond ou secret invalide ; 4 ADR-0012 sur processus réels : l'approbateur trouve la demande et le canal est prévenu, webhook refusant / bloquant / disparu, identifiant de compte refusé, URL inutilisable et annonce ; 3 mTLS sur huit processus réels : parcours complet + vingt-sept appels forgés + imposteur ; rotation d'un certificat et de l'autorité ; refus de démarrer ; dont 6 TEST_DATABASE_URL — redémarrage Vault, Authorization, Authentication, Audit, Session Broker, Command Recorder ; 2 « enregistrer ou refuser » sur huit processus réels ; 2 break-glass : huit processus réels + refus de démarrer sur une limite illisible ; 3 double validation : huit processus réels, refus de démarrer sur une valeur illisible, mode annoncé)
```

Compte vérifié par `grep -c "^--- PASS"` sur la sortie `go test -v`, pas estimé.

## v0.0.1, sixième lot : approbation des sessions ordinaires (ADR-0067)

Le compte peut exiger qu'une autre personne approuve une session ordinaire avec un ticket au format déclaré. Le réglage est audité par le Vault avant application ; le Broker attend une décision, applique la règle des quatre yeux et enregistre ticket, demande et décision avant tout effet. Le ticket est lié aux événements par le hash v4 de l'Audit Service (ADR-0068), avec détails bornés et migration additive ; les formats de hash antérieurs restent vérifiables. La Gateway borne aussi les changements du réglage par utilisateur. Les contrats REST, protobuf et les guides d'administration/configuration sont alignés.

**Vérifications mesurées dans ce sandbox.** `make build vet` vert sur tous les modules ; `make test` vert ; le scénario `TestApprovalFlow_AnotherPersonApprovesWithATicket_AcrossEightRealProcesses` passe sur huit vrais processus ; `make ui-test ui-build` passe, avec 40 tests Vitest et le build TypeScript/Vite ; le YAML OpenAPI parse. Les tests ciblés de l'Audit Service et du Session Broker passent aussi. **Pas de test PostgreSQL réel pour ce lot** : `TEST_DATABASE_URL` n'est pas défini ; l'aller-retour JSONB et l'application de la migration restent à vérifier avec la base dédiée.

## v0.0.1, septième lot : Video Recorder et API de replay (ADR-0070)

Le service Video Recorder, son flux d'ingestion gRPC mTLS, les métadonnées PostgreSQL et les objets S3 chiffrés sous Transit sont implémentés ; la Gateway expose le replay sous Authorization et audit préalable. Le producteur graphique RDP et le lecteur Admin UI restent à faire (ADR-0069 et décisions ultérieures).

**Mise à niveau Compose.** Une installation créée avant ADR-0070 n'a pas les nouveaux secrets vidéo dans son `.env`, que `init.sh` refuse à juste titre d'écraser. `init-recording.sh` crée maintenant un fichier supplémentaire `.env.recording` en mode `0600`, de façon additive et idempotente ; Compose accepte l'absence de ces variables tant que le profil recording n'est pas sélectionné. `video-recorder-db-init.sh`, exécuté uniquement par ce profil, crée le rôle et la base du Recorder dans un volume PostgreSQL existant. Il vérifie le propriétaire de la base, assigne le mot de passe déclaré à un rôle déjà existant, puis révoque les privilèges `PUBLIC`. Ce bootstrap reçoit brièvement le mot de passe superutilisateur PostgreSQL : le job est isolé sur le réseau interne, sans port publié, et la limite est notée dans `docs/security/known-limitations.md`. Le `.env` local existant n'a pas été lu ni modifié.

**Preuves mesurées.** `make build vet` vert sur tous les modules Go. Les tests ciblés mTLS, Gateway et Video Recorder comptent 156 lignes `--- PASS`, zéro échec. Les configurations Compose de production (profil vidéo activé et désactivé) et Base44 passent `docker compose config --quiet`. Les tests du script d'upgrade des secrets et du bootstrap PostgreSQL passent sur un volume Compose temporaire ; le contrôle confirme `video_recorder:video_recorder`. `make test-compose` passe : 9 scénarios de parcours MVP, plus les 2 tests d'upgrade, sur de vrais conteneurs ; la pile est arrêtée après le test et la règle temporaire de pare-feu retirée. `git diff --check` et `sh -n` sur les scripts modifiés passent. Les deux tests PostgreSQL du Video Recorder avaient également réussi avant cette reprise.

**Non vérifié.** `make vuln` a été tenté avec Go 1.27.3, puis avec la concurrence réduite ; `govulncheck` est tué par l'environnement (`signal: terminated`), même sur son premier module : aucun résultat de scan n'est établi. Un passage `-race` ciblé a réussi pour mTLS et Gateway, mais la compilation race du Video Recorder a été tuée pendant la compilation de `goccy/go-json`; elle n'est donc pas validée dans cette reprise. Le `make test-postgres` complet a échoué sur l'assertion préexistante `TestPostgresFlow_ReplicasStartingTogetherOnAFreshDatabase/.../a_database_from_before_versioned_migrations_keeps_its_data_and_is_recorded_as_version_1` (`schema_migrations_test.go:114`, « the upgrade is not said ») ; ce résultat n'a pas été comparé au commit précédent. Le démarrage Base44 avec le profil vidéo a échoué pendant l'extraction d'image (« no space left on device ») avant que la pile devienne saine. La suppression explicite des trois images OpenBastion de test non utilisées (`openbastion:base44-dev`, `openbastion-tools:dev`, `openbastion:dev`) a rendu environ 1,5 Go ; l'espace libre est ensuite passé de 2,0 à 3,2 Go (10 % au dernier relevé). Les volumes, l'image PostgreSQL active, les images de base préexistantes et les caches Docker non identifiés comme inutilisés ont été conservés.

**Limites restantes.** Aucun proxy RDP ni lecteur vidéo Admin UI ; aucun test de charge. Le compte S3 du Recorder dans le Compose possède `Admin` sur l'instance SeaweedFS dédiée pour créer le bucket. Les objets S3 orphelins ne sont pas purgés automatiquement. La validation runtime complète de Base44 et le scan `make vuln` restent à reprendre dans un environnement avec ressources suffisantes.

## v0.0.1, huitième lot : fondation de confiance RDP (ADR-0069/0071)

`pkg/rdp` contient la primitive Go qui parse une empreinte SHA-256 hexadécimale non vide, valide le DER du certificat feuille et compare son empreinte en temps constant. Le module est ajouté au workspace et aux portes build, vet et test. Les tests couvrent l'épingle correspondante, un certificat imposteur, une empreinte absente ou mal formée et un DER invalide ; une mutation locale de la comparaison a fait échouer les tests du certificat correspondant et de l'imposteur.

**Limite de cet incrément.** Il n'y a encore aucun binding cgo, aucune configuration de négociation NLA/TLS, aucun callback TLS du moteur RDP relié à cette vérification et aucun proxy RDP exploitable. L'examen préparatoire d'une bibliothèque native a montré que les API nécessaires au rôle de serveur n'étaient pas disponibles dans l'environnement testé ; l'intégration d'un moteur natif restait donc à valider. Les tests Go de la primitive ne prouvent ni l'ordre réel du callback TLS par rapport à CredSSP, ni la négociation sans repli, ni l'interopérabilité avec une cible.

**Vérifications mesurées pour cet incrément.** Les 8 tests de `pkg/rdp` passent sous `-race` ; `go vet` du module passe. `make build vet` et `make test` passent sur le workspace complet. Le rouge avant l'implémentation échouait à la compilation sur les fonctions et erreurs absentes. Pas encore de test natif cgo, d'intégration RDP, ni de mesure des garanties au niveau protocole.

**Extension préparatoire du callback TLS.** `VerifyPinnedCertificatePEM` accepte une chaîne PEM bornée à 1 Mio et 16 certificats, parse le DER de chaque certificat et compare le pin uniquement au premier certificat (la feuille du serveur cible). Les 11 tests passent sous `-race` ; une mutation qui vérifiait le dernier certificat de la chaîne est tuée par le test feuille/intermédiaire. Après cette extension, `make build vet` et `make test` passent à nouveau. Cette fonction n'est pas encore reliée à un moteur RDP.


## ADR-0071 — incrément 1 : contrat écran et pinning TLS explicite

**Livré dans la branche `rdp-vnc-proxy`** : `pkg/screenstream` définit le contrat binaire borné FRAME/HELLO/END et les événements d'entrée ; le module est inclus dans le workspace et les cibles build/test/vet. L'identité mTLS réservée est désormais `rdp-vnc-proxy`, autorisée par le Video Recorder pour l'ingestion et la readiness. `pkg/tlspin` reçoit les primitives d'empreinte SHA-256, la validation PEM bornée et une configuration TLS cible qui exige un pool de confiance explicite, le nom attendu et une correspondance du pin en plus de la validation standard. Le code utilisant `InsecureSkipVerify` n'est compilé que sous `-tags development`, conformément à l'autorisation limitée au développement ; il n'est pas disponible dans les builds de production.

**Vérifications mesurées dans le Codespace `codespaces-909fd6`** : `make build vet` et `make test` passent sur le workspace complet ; `go test -race -count=1 ./pkg/tlspin/... ./pkg/rdp/... ./pkg/screenstream/...` passe ; `go test -tags development -count=1 ./pkg/tlspin/...` passe ; `gofmt` et `git diff --check` sont propres. Mutation de sécurité : supprimer la vérification du pin fait échouer `TestServerConfigEnforcesStandardTLSAndPin/wrong_pin` ; fichier restauré et comparé octet par octet. Aucun moteur RDP/VNC ni relais WebSocket n'est livré par cet incrément.

**Contrainte de sécurité** : contrairement à la proposition initiale du §3 d'ADR-0071, la production n'utilise pas le pin comme unique ancre sans validation PKI. La chaîne et le nom sont validés par Go contre le `RootCAs` explicitement fourni, puis le pin de la feuille est vérifié. Les cibles auto-signées nécessitent une confiance explicitement configurée ; l'exception pin-only reste strictement développement.

## ADR-0071 — incrément 2 : cycle de vie du relais écran partagé

`pkg/proxycore.ServeScreen` réutilise le cycle de vie commun de `Listener.Serve` : enregistrement révocable avant admission, contrôle de disponibilité du Video Recorder avant de consommer le scope Vault à usage unique, purge du credential, audit et terminaison. Le break-glass est refusé pour les sessions graphiques. Les sessions RDP/VNC sont abstraites par `ScreenCodec`/`ScreenSession`; les frames sont validées et numérotées, enregistrées avant leur envoi au `ScreenSink`, et l'acquittement doit correspondre exactement au numéro de frame. Le recorder reçoit une copie indépendante des octets, de sorte qu'une mutation de son adaptateur ne puisse pas modifier l'image envoyée à l'opérateur. Le scellement du recording est tenté sur chaque sortie après l'ouverture de la session, y compris révocation et erreur, avec un contexte de nettoyage borné indépendant de l'annulation du relais.

**Tests ajoutés** : sept tests ciblés couvrent le chemin nominal, l'acquittement ambigu (aucune frame envoyée), le refus avant le fetch Vault quand le recorder est indisponible même si une admission antérieure est fournie, la séquence invalide, la révocation et l'échec du scellement. Une mutation qui retire le contrôle `ack == frame.Sequence` est tuée par `TestServeScreen_AmbiguousRecorderAcknowledgementNeverReachesOperator` ; le fichier a été restauré et comparé octet par octet.

**Vérifications mesurées dans le Codespace `codespaces-909fd6`** : `make build vet` et `make test` avec `TEST_DATABASE_URL` ont passé ; `make test-postgres` a passé, y compris `TestPostgresFlow` sur PostgreSQL 16 réel (169,755 s) ; `make test-integration` a passé (267,911 s, le scénario PostgreSQL conditionnel est ignoré puisque `TEST_DATABASE_URL` n'était pas exporté pour cette passe). Après les dernières modifications du relais, `go vet ./pkg/proxycore/... ./pkg/screenstream/...`, `go test ./pkg/proxycore/... ./pkg/screenstream/...`, `go test -race -count=1 ./pkg/proxycore/... ./pkg/screenstream/...` et `git diff --check` passent.

**Compose non validé** : `make test-compose` a été tenté sur la pile Compose réelle. Pendant la construction BuildKit des binaires Go, l'espace disque est tombé à 0 octet disponible (100 % utilisé). Le test a été interrompu à 419 s pour éviter de laisser le codespace sans espace ; aucun conteneur de la pile Compose n'avait démarré. Cette commande est donc **non concluante**, et non un test vert. Aucun cache ni image Docker n'a été purgé, pour ne pas supprimer d'artefacts hors du dépôt. Après l’arrêt du build, 626 Mio étaient libres sur le système de fichiers (98 % utilisé) ; la suite Compose doit être rejouée après récupération d'espace disque.

**Limites restantes** : aucun moteur RDP/VNC ne fournit encore `ScreenSession`; l'entrée clavier/souris n'est pas relayée, aucun code `END` stable n'est encore émis par `ServeScreen`, et le proxy réseau, la Gateway WebSocket et le lecteur Admin UI ne sont pas câblés. Aucun schéma PostgreSQL n'a été modifié dans cet incrément.


## ADR-0071 — sous-incrément VNC : client RFB et adaptateur ScreenCodec

`pkg/vnc` est ajouté comme module Go autonome au workspace et aux portes `build`, `vet` et `test`. Le client impose RFB 3.8, exige VeNCrypt 0.2 et choisit X509Plain avant X509Vnc ; il construit la configuration TLS via `pkg/tlspin.ServerConfig` (racines explicites, nom vérifié et empreinte SHA-256 de la feuille). Aucun mot de passe n'est envoyé avant la réussite du handshake TLS. Le chemin X509Vnc refuse un mot de passe de plus de huit octets avant le handshake TLS pour éviter toute troncature historique.

Le moteur lit l'initialisation RFB (dont `ClientInit`), impose un format pixel 32 bpp, demande Raw/CopyRect/DesktopSize/ExtendedDesktopSize/Cursor/LastRect, borne les rectangles et le framebuffer, convertit les mises à jour en PNG complètes et transmet les événements clavier/souris normalisés ; `RELEASE_ALL` relâche les touches et boutons suivis. Le presse-papiers reste fermé. Les frames ne sont pas abandonnées lorsque le consommateur ralentit : le backpressure bloque la lecture plutôt que de perdre des images destinées à l'enregistrement.

`services/proxy/rdp-vnc-proxy/internal/engine.VNCCodec` implémente désormais `proxycore.ScreenCodec`. Il exige un pool de racines explicite et les métadonnées Vault `TargetUser`, `TLSCertificateSHA256` et `TargetDomain`, puis construit le client VNC à partir du credential à usage unique. `proxycore.Credential` et `Fetched` transportent ces champs ; `Credential.Purge` les efface. Les clients Vault HTTP/gRPC et le stockage du Vault ne les alimentent pas encore : toute tentative sans ces valeurs échoue avant l'ouverture d'une connexion cible.

**Preuves ciblées** : le serveur RFB factice valide la négociation VeNCrypt/X509Plain, `ClientInit`, les credentials transmis dans TLS, le décodage du pixel vers PNG, les événements d'entrée et la fermeture TLS ; les tests refusent un pin erroné, les mécanismes d'authentification en clair et les mots de passe VNC tronqués. Les tests du module engine prouvent le refus avant dial si le pin ou les racines explicites manquent. `go test -race -count=1 -timeout=30s ./pkg/vnc/... ./pkg/proxycore/... ./services/proxy/rdp-vnc-proxy/...` et `go vet` ciblé passent.

**Ce que cela ne fait PAS** : `services/proxy/rdp-vnc-proxy` ne possède pas encore de serveur exécutable, de gestion des tickets, de client gRPC Video Recorder ni de WebSocket Gateway ; le Vault ne stocke ni ne délivre encore les métadonnées de confiance et le nom d'utilisateur requis. Aucun parcours VNC de bout en bout n'est disponible. Le moteur RDP reste à implémenter et n'est pas annoncé. La prochaine étape est le raccordement de ces métadonnées au modèle de compte, à la migration, aux contrats Vault et à son client proxy.

## ADR-0071 — incrément 3 : métadonnées TLS du Vault et épinglage via Gateway

Le modèle de compte, les magasins mémoire/PostgreSQL et la migration additive `008_screen_targets.sql` stockent désormais `tls_certificate_sha256` et `target_domain`. La contrainte SQL accepte uniquement les deux champs vides, ou les deux renseignés pour un compte VNC/RDP ; un compte SSH ne peut pas recevoir de pin TLS. Le Vault expose les métadonnées dans `GET /vault/v1/accounts/{id}` et `fetch-credential`, et `SetTLSPin` normalise le pin et le nom, exige le RBAC administrateur et écrit `vault.tls_pin_set` avant la modification. L'opération refuse les comptes SSH, tandis que `SetHostKey` refuse les comptes graphiques ; la rotation programmée reste indisponible pour VNC/RDP.

La Gateway expose `PUT /vault/accounts/{id}/tls-pin` en n'acceptant du corps que l'empreinte et le nom cible ; `actorId` et `actorRoles` sont injectés depuis le jeton vérifié. La réponse de refus `no_pinned_tls_pin` (409) est stable, le client Vault du Broker la mappe à `ErrAccountTLSNotPinned`, et l'API du Broker renvoie 409 sans répercuter de détails internes. Le client Vault du proxy SSH ignore les champs graphiques supplémentaires ; le client du proxy RDP/VNC sait maintenant les décoder.

**Vérifications mesurées dans `codespaces-909fd6`** : `make build vet` et `make test` passent sur tout le workspace ; les tests ciblés sous `-race` passent pour VNC, `proxycore`, Gateway, Session Broker, les proxies SSH/RDP-VNC et le Vault. `make test-postgres` a passé sur un PostgreSQL 16 jetable, incluant `TestPostgresFlow` (172,583 s). Après renommage vers le nom de migration ADR `008_screen_targets.sql`, `TestPostgresStore_SetTLSPin_RoundTripsGraphicalTargetIdentity` repasse sur une base PostgreSQL fraîche et confirme que les migrations 1 à 8 s'appliquent. `make test-integration` passe (279,533 s ; les cas explicitement PostgreSQL sont ignorés car `TEST_DATABASE_URL` est désactivé pour cette passe). Le YAML OpenAPI parse. Les mutations qui forgent `actorId` dans la Gateway et qui contournent l'audit de `SetTLSPin` sont tuées par leurs tests ; les deux sources ont été restaurées et comparées octet par octet. `git diff --check` passe.

**Limite de l'incrément** : aucun parcours RDP/VNC de bout en bout n'est activé. Le Session Broker sélectionne encore SSH uniquement ; le service `rdp-vnc-proxy` n'a pas encore de serveur exécutable, de gestion des tickets, de client Video Recorder ou de relais WebSocket Gateway. Le client VNC et `VNCCodec` sont des composants, pas encore un service connecté ; le moteur RDP reste à implémenter. `make test-compose` n'a pas été lancé localement, conformément à la consigne ; il reste couvert par GitHub Actions.


## ADR-0072 — incrément 4 : adaptateur gRPC du Video Recorder pour les sessions écran

`services/proxy/rdp-vnc-proxy/internal/infrastructure.VideoRecorderClient` implémente `proxycore.FrameRecorder` et `proxycore.ScreenRecorderGate`. Le constructeur vérifie le mode URL/TLS et épingle le pair gRPC à l’identité mTLS `video-recorder` ; `Ready` vérifie la readiness avant dépense du scope Vault. Chaque frame PNG est envoyée sur un flux bidirectionnel persistant par session et n’est considérée enregistrée qu’après un ACK de session et de séquence exacts. `Seal` envoie le marqueur terminal sur le même flux, attend l’ACK `Complete` et la fermeture propre. Les ACK tardifs ou ambigus ne permettent jamais de déclarer la vidéo complète ; les erreurs de séquence, les identifiants de session invalides et un enregistreur non prêt sont refusés. `Close` annule les flux ouverts et ferme la connexion gRPC.

Le module `services/proxy/rdp-vnc-proxy` déclare maintenant explicitement ses dépendances gRPC/protobuf et les remplacements locaux des modules du workspace, et fonctionne aussi hors `go.work`.

**Vérifications locales** : `GOWORK=off GOPROXY=off go test ./...` et `go vet ./...` du module proxy passent ; `make build vet` et `make test` passent sur le workspace ; `go test -race ./services/proxy/rdp-vnc-proxy/...` passe ; `git diff --check` passe. Les tests du client couvrent readiness, flux de frames, scellement terminal, ACK incorrect, saut de séquence, ID invalide et validation de l’URL/TLS. Aucun test Compose n’a été lancé localement.

**Limite** : l’adaptateur n’est pas encore instancié par `cmd/rdp-vnc-proxy` (qui reste à créer). Il manque encore le serveur de contrôle/tickets, le routage du Session Broker, le transport écran Gateway/WebSocket et l’UI opérateur. Cette étape est le raccordement de l’enregistreur, pas une session VNC/RDP de bout en bout.

## ADR-0071 — incrément 4 : runtime, routage du Broker et relais WebSocket Gateway

Le binaire `cmd/rdp-vnc-proxy` est maintenant compilable et démarre sous l'identité mTLS `rdp-vnc-proxy`. Il exige un fichier PEM de racines cibles explicite (`TARGET_TLS_ROOTS_FILE`), raccorde le Vault, l'Audit Service, le Video Recorder gRPC et `proxycore.ServeScreen`. Le contrôle HTTP expose l'émission et la révocation des tickets ainsi que l'attachement WebSocket. Les tickets proxy sont aléatoires, à usage unique, expirent à la date de session et sont supprimés lors d'une révocation ; RDP est refusé explicitement tant que son moteur n'existe pas. Les événements clavier/souris binaires sont bornés et validés avant d'atteindre le moteur, et le cycle de vie écran émet maintenant un message `END` à texte stable après le scellement.

Le Session Broker sélectionne un pool par protocole depuis la session stockée, et propage `protocol` à l'instance proxy. `vnc` va au pool `rdp-vnc-proxy`; `rdp` ne bascule jamais vers un autre moteur. La Gateway remplace le ticket VNC du corps par un cookie `HttpOnly; SameSite=Strict`, limité au chemin `/sessions/{id}/screen` et valable au plus 30 secondes. La route WebSocket n'accepte pas le bearer token ni le ticket en URL, vérifie l'origine par la politique WebSocket same-origin, consomme l'attachement une fois, n'autorise qu'un socket actif par session et limite à dix upgrades par utilisateur et par minute avant de relayer les messages binaires sous mTLS vers le proxy. Le ticket proxy et l'adresse interne ne sont pas renvoyés au navigateur.

**Vérifications ciblées de cet incrément** : tests unitaires du runtime, du ticket proxy, des règles d'appelants, du routage de protocoles, du registre de cookies à usage unique, du contrat de connexion VNC sans fuite du ticket, du relais d'entrée vers `ScreenSession`, et des messages END ; les modules Gateway, Session Broker, RDP/VNC proxy, Video Recorder, `pkg/proxycore` et PKI passent les tests Go ciblés. Le YAML Compose de production parse avec `docker compose config --quiet`. Le profil de déploiement `rdp-vnc` exige `SCREEN_TARGET_CA_FILE` (PEM explicite) et doit être activé avec le profil `recording`.

**Limites restantes** : aucun moteur RDP ; le client VNC et le contrat de relais sont unit-testés mais aucun parcours VNC de bout en bout avec une vraie cible et une vraie session de navigateur n'a été exécuté dans cet incrément. Le lecteur Admin UI n'est pas encore raccordé au chemin `attach`, et la configuration du profil Compose avec une autorité cible réelle reste à valider. Ne pas annoncer RDP comme disponible.

## ADR-0071 — incrément 5 : socle de transport RDP strict

`pkg/rdp/transport.go` ajoute `DialHybrid`, premier étage du client RDP : adresse `host:port` explicite, pool de racines et nom TLS explicites, empreinte SHA-256 de la feuille obligatoire, requête X.224 sans cookie utilisateur et demande exclusive de `PROTOCOL_HYBRID`. Toute sélection de `PROTOCOL_RDP`, TLS seul, HYBRID-EX ou toute réponse de négociation mal formée est refusée avant l'ouverture TLS. Le transport n'est retourné qu'après validation de la chaîne, du nom et du pin TLS. Cette API ne prend aucun credential : aucun secret ne peut donc être envoyé avant la fin de cette étape. CredSSP/NTLMv2, MCS/GCC, capacités, décodage d'affichage, entrée et branchement au runtime restent à faire ; aucune session RDP n'est exposée.

**Preuves locales** : tests contre un serveur X.224/TLS factice, vérification de la demande HYBRID exclusive, refus des protocoles dégradés avant tout ClientHello, refus d'un pin imposteur, validation des configurations incomplètes, rejet de paquets mal formés ; `go test -race ./pkg/rdp/...`, `make build vet test` et `git diff --check` passent. Un fuzzer `FuzzReadConnectionConfirm` couvre le parseur de confirmation.

**Incident de validation local, résolu** : une passe complète `make test-integration` a échoué uniquement lors des builds Docker OpenLDAP/Samba, le magasin de contenu signalant un digest de couche manquant alors que le système de fichiers était à 97 %. `docker builder prune --all --force` puis `docker image prune --force` ont récupéré environ 2,1 Gio ; aucun volume Docker n'a été supprimé. Les deux tests LDAP concernés ont ensuite passé lors d'une exécution ciblée. La suite d'intégration complète n'a pas été relancée localement ; GitHub Actions reste la validation complète de référence. `TEST_DATABASE_URL` n'est pas configuré localement, les tests PostgreSQL locaux sont donc ignorés ; le workflow CI possède un job PostgreSQL dédié. Aucun test Compose n'a été lancé localement.


## ADR-0071 — incrément 6 : codec DER CredSSP TSRequest

`pkg/rdp/credssp.go` ajoute un encodeur/décodeur Go pur pour `TSRequest` : version 2–6, liste de jetons `negoTokens`, `authInfo`, `pubKeyAuth`, `errorCode`, `clientNonce`. Les champs ASN.1 sont explicitement taggés, ordonnés, bornés en taille/compte, et encodés en DER canonique. Le parseur refuse BER à longueur indéfinie, longueur DER non canonique, champ inconnu/dupliqué/hors ordre, structure imbriquée incorrecte, version non supportée, payload trop grand et nonce d’une taille incorrecte. Les octets de jetons sont opaques : cette tranche n’implémente ni SPNEGO, ni NTLMv2, ni envoi de credential, ni authentification CredSSP. Le runtime RDP reste désactivé.

Tests : round-trip de tous les champs, vecteur DER initial figé, cas malformés et bornes ; `go test -race ./pkg/rdp/...`, fuzzing `FuzzParseTSRequest` pendant 10 s (~152 000 entrées) et `make build vet test` passent. `git diff --check` et `gofmt` sont aussi vérifiés. La suite d’intégration complète n’a pas été relancée sur cette tranche ; aucun code d’authentification réel n’est activé.


## ADR-0071 — incrément 7 : parseur SPNEGO strict

`pkg/rdp/spnego.go` parse les formes DER SPNEGO `InitialContextToken` / `NegTokenInit` et `NegTokenResp`. Les listes de mécanismes sont limitées à NTLM OID ; Kerberos et les OID inconnus sont refusés. Les champs sont uniques, ordonnés, bornés à 16 Kio et les OID doivent être canoniques DER. Les états `reject` et `request-mic` sont refusés, car aucune vérification de MIC n’existe. Les jetons NTLM et MIC sont conservés comme octets opaques et ne constituent jamais une preuve d’identité.

Les tests couvrent les deux structures, les champs opaques, le refus des mécanismes non pris en charge, les états de négociation refusés, les octets surnuméraires et la borne de taille ; un fuzzer couvre les deux parseurs. Ce composant n’est pas branché au transport CredSSP et ne met en œuvre ni NTLMv2, ni preuve cryptographique, ni transmission de credential. Le runtime RDP reste désactivé.

## ADR-0071 — incrément 8 : primitives NTLMv2 et validation AV_PAIR

`pkg/rdp/ntlmv2.go` ajoute les primitives cryptographiques NTLMv2, sans construire ni envoyer de message NTLMSSP : dérivation `NTOWFv2` (MD4 du mot de passe UTF-16LE, puis HMAC-MD5 de `Uppercase(username) + domain`), construction du blob client, `NTProofStr`, réponse LMv2 et `SessionBaseKey`. Le challenge client de 8 octets est produit par `crypto/rand`. `NTLMv2Response.Purge` efface les champs de réponse et de clé exposés ; les buffers intermédiaires manipulables sont effacés au terme du calcul.

`ParseNTLMv2AVPairs` valide les longueurs, les chaînes UTF-16LE, l'unicité des identifiants et le terminateur EOL final ; la taille est bornée à 16 Kio et 64 attributs. Les attributs inconnus restent opaques et sont conservés. `MsvAvTimestamp` est supporté : le FILETIME serveur est utilisé dans le blob NTLMv2 et entraîne `LMChallengeResponse = Z(24)`. `MsvAvTargetName` et `MsvAvChannelBindings` restent refusés jusqu'à leur liaison au pair TLS épinglé ; seul `MsvAvFlags.MIC_PRESENT` est accepté. NTLMv1 et LMv1 ne sont pas implémentés.

Le vecteur Microsoft MS-NLMP §4.2.4 vérifie `NTProofStr`, la réponse LMv2 et `SessionBaseKey`. `NTProofStr` est la preuve du client ; NTLMv2 n’expose pas de preuve serveur distincte dans cette couche. Tests négatifs sur AV_PAIR et identités, test de purge, génération aléatoire, et fuzzer `FuzzParseNTLMv2AVPairs`.

**Vérifications sous Go 1.27.3 (outil fixé par ADR-0052)** : `make build vet` et `make test` passent sur tout le workspace ; `go test -race ./pkg/rdp/...` passe ; fuzzing AV_PAIR 10 s (152 345 exécutions) passe ; `make vuln` passe sur les modules Go et les deux lockfiles npm (aucune vulnérabilité appelée ; `openpgp` demeure seulement signalé au niveau du module `x/crypto`, non importé) ; YAML parse, `gofmt` et `git diff --check` passent. Sept mutations de sécurité (unicité AV_PAIR, fail-closed MIC/timestamp/target-name/channel-binding, calcul du proof, challenge aléatoire, purge) sont toutes tuées et la source est restaurée octet par octet.

**Limite** : aucune authentification NTLMv2 n'est branchée au SPNEGO/CredSSP. Le code ne lit pas encore un `CHALLENGE_MESSAGE`, ne construit pas `AUTHENTICATE_MESSAGE`, ne valide pas de MIC, ne lie pas l'identité à la cible TLS et ne transmet aucun credential. RDP reste désactivé. `make test-compose` et les tests d'interopérabilité avec une cible Windows réelle ne sont pas exécutés dans cette tranche.

## 2026-11-03 — ADR-0071, incrément 9 : codecs NTLMSSP et MIC

`pkg/rdp/ntlmssp.go` ajoute les codecs du profil NTLMSSP strict :

- `MarshalNTLMSSPNegotiate` émet le profil Unicode/NTLM/AlwaysSign/ESS/TargetInfo, sans OEM, LM-key, NTLMv1, SIGN, SEAL, KEY_EXCH ni VERSION. Le champ Version fixe est nul ; les security buffers vides pointent sur l'offset 40.
- `ParseNTLMSSPChallenge` valide la signature/type, les flags réellement offerts, le champ Version nul, les security buffers, leurs bornes et leur non-chevauchement, l'alignement UTF-16LE, le challenge serveur non nul et la liste AV_PAIR bornée. Le header fixe est de 56 octets.
- `NTLMv2ServerTargetInfoForProof` conserve le TargetInfo serveur octet pour octet pour le NTProof ; `MsvAvFlags.MIC_PRESENT` est posé ensuite dans le blob AUTHENTICATE.
- `MarshalNTLMSSPAuthenticate` vérifie le NTProof, le blob et le TargetInfo attendu, lie le LMv2 au client challenge, sérialise LMv2 + NTLMv2, aligne les offsets UTF-16LE, laisse Version nul et calcule le MIC HMAC-MD5 sur NEGOTIATE + CHALLENGE + AUTHENTICATE (MIC nul pendant le calcul). `EncryptedRandomSessionKey` reste vide car KEY_EXCH n'est pas négocié.

Le timestamp serveur `MsvAvTimestamp` est maintenant supporté : son FILETIME remplace le timestamp local du blob et la réponse LM est `Z(24)` selon MS-NLMP. Les AV `MsvAvTargetName` et `MsvAvChannelBindings` restent refusés jusqu'à leur liaison cryptographique au pair TLS épinglé. La liaison TLS `pubKeyAuth`, le dialogue CredSSP, le chiffrement `authInfo`, MCS/GCC et l'affichage restent absents. Aucun credential n'est transmis et le runtime RDP reste désactivé.

Tests et contrôles réalisés :

- `GOTOOLCHAIN=go1.27.3 go test ./pkg/rdp/... -count=1` : OK.
- `GOTOOLCHAIN=go1.27.3 go test -race ./pkg/rdp/... -count=1` : OK.
- Fuzz `FuzzParseNTLMSSPChallenge` et `FuzzParseNTLMv2AVPairs`, 10 secondes chacun : OK.
- 11 mutations ciblant downgrade, buffers, Version, alignement Unicode, proof NTLMv2, LMv2, clé de session, MIC et MIC_PRESENT : toutes tuées.
- `make build vet test` : OK. `make vuln` : OK ; `govulncheck` ne détecte aucune vulnérabilité dans le code atteignable, mais signale des avis au niveau de modules requis non appelés ; `npm audit` retourne 0 vulnérabilité pour les deux workspaces UI.
- `make test-integration` sans `TEST_DATABASE_URL` : OK (`test/integration`, 203,652 s). Les scénarios PostgreSQL sont donc ignorés dans ce run.
- Le premier run d'intégration avait exposé un défaut du helper SSH de test : `Session.Shell()` peut renvoyer EOF après que le serveur a écrit le refus d'enregistrement. Le helper draine désormais stdout avant la requête shell et n'accepte EOF que si le message de refus attendu est reçu ; le test ciblé puis toute la suite d'intégration passent.
- Une tentative locale PostgreSQL avec une base fraîche non migrée a échoué avant les assertions (`audit_events` absent) ; ce conteneur n'est pas une base de test initialisée. La validation PostgreSQL dédiée reste confiée au job GitHub Actions PostgreSQL 16.
- Les tests Compose ne sont pas lancés localement, conformément à la consigne : ils restent dans GitHub Actions.

Références de protocole : MS-NLMP §§2.2.1.1–2.2.1.3 et §3.1.5.2.1. Les messages NTLMSSP ne sont pas encore branchés à SPNEGO/CredSSP ; aucune interopérabilité avec une cible Windows réelle n'est revendiquée.


## 2026-11-04 — ADR-0071, incrément 10 : timestamp serveur NTLMv2

- `ComputeNTLMv2Response` utilise les huit octets FILETIME de `MsvAvTimestamp` pour le blob NTLMv2, sans dépendre de l'horloge locale de l'appelant.
- La présence de cet AV impose `LMChallengeResponse = Z(24)` (24 octets nuls) ; le validateur AUTHENTICATE n'accepte cette forme que si le timestamp est réellement présent et refuse une LM response non nulle.
- Sans timestamp serveur, le LMv2 reste calculé et lié au client challenge.
- Tests ciblés couvrent le remplacement du timestamp local, le contenu du blob, le security buffer `AUTHENTICATE_MESSAGE` et le refus d'une LM response non nulle.
- `MsvAvTargetName` et `MsvAvChannelBindings` restent refusés jusqu'à leur construction depuis le pair TLS épinglé. `pubKeyAuth`, le dialogue CredSSP, `authInfo`, MCS/GCC, l'affichage et l'entrée ne sont pas implémentés.

- Validation complémentaire de l'incrément 10 : `make build vet test`, `make vuln`, `make proto-lint`, `go test -race ./pkg/rdp/... -count=1`, les fuzzers NTLMSSP/AV_PAIR (10 s chacun) et `make test-integration` sont verts. L'intégration multi-processus a duré 226,162 s ; les tests PostgreSQL ont été ignorés localement faute de `TEST_DATABASE_URL` (la CI PostgreSQL 16 dédiée reste la preuve de ce périmètre). `git diff --check` et `gofmt` sont propres. Les tests Compose restent exécutés dans GitHub Actions, pas localement.

- Revue de protocole : le TargetInfo serveur reste inchangé pendant le calcul de NTProof. La clarification de l'incrément 11 ajoute `MsvAvFlags.MIC_PRESENT` uniquement après ce calcul dans le blob AUTHENTICATE, conformément à MS-NLMP §3.1.5.1.2.

## 2026-11-04 — ADR-0071, incrément 11 : NTLMv2 target-name et channel binding

- `Transport.NTLMv2Bindings` revalide le pin SHA-256 mémorisé, dérive le SPN `TERMSRV/<TLS server name>` depuis le nom vérifié par le handshake (DNS strict, IP canonisée), et le CBT depuis le certificat présenté sur la même connexion TLS épinglée.
- `tls-server-end-point` suit RFC 5929 : hash lié à l'algorithme de signature du certificat, SHA-256 en repli pour MD5/SHA-1, refus des signatures sans hash unique ; sérialisation GSS/NTLM et MD5 selon MS-NLMP.
- `NTLMv2TargetInfoWithClientBindings` et `MarshalNTLMSSPAuthenticateWithBindings` posent `MsvAvFlags.MIC_PRESENT` et ajoutent les AV_PAIR client TargetName/ChannelBindings après calcul de NTProof sur le TargetInfo original du serveur. Le MIC est calculé sur l'AUTHENTICATE final.
- Tests ciblés couvrent certificat absent/handshake incomplet, changement de certificat, SPN invalide, préservation de la preuve sur le TargetInfo serveur et substitution du SPN/CBT.
- Aucun dialogue CredSSP, pubKeyAuth ou authInfo n'est activé ; aucun credential n'est transmis et RDP reste désactivé.
- Validation finale : `make build vet`, `make test`, `go test -race ./pkg/rdp/... -count=1`, `make proto-lint` et `GOTOOLCHAIN=go1.27.3 make vuln` sont verts. Le scan govulncheck avec Go 1.27.3 ne trouve aucune vulnérabilité atteignable ; `npm audit` est propre pour les deux packages UI.
- `make test-integration` passe en 216,000 s. Les tests PostgreSQL sont ignorés faute de `TEST_DATABASE_URL` ; les parcours multi-processus non PostgreSQL passent. Les tests Compose restent dans GitHub Actions et n'ont pas été exécutés localement.


## 2026-11-04 — ADR-0071, incrément 12 : CredSSP v5/v6 public-key binding

- `Transport.NewCredSSPPublicKeyBinding` exige un handshake TLS achevé et revalide le pin SHA-256 de la feuille avant d'utiliser la clé publique du pair.
- Extrait le contenu du BIT STRING `SubjectPublicKey` depuis le `SubjectPublicKeyInfo` X.509 ; ne hash jamais le certificat entier ni le SPKI entier.
- Génère un `clientNonce` de 32 octets avec `crypto/rand` et calcule les hashes directionnels SHA-256 `CredSSP Client-To-Server Binding Hash\0 || nonce || SubjectPublicKey` et `CredSSP Server-To-Client Binding Hash\0 || nonce || SubjectPublicKey`.
- `VerifyServerToClientHash` vérifie en temps constant le hash attendu après déchiffrement par le futur GSS_Wrap.
- **Ce n'est pas encore un `pubKeyAuth` transmissible** : la protection GSS_Wrap/NTLMSSP (signature, sealing et séquences), l'échange TSRequest, SPNEGO et `authInfo` ne sont pas implémentés. Aucun credential n'est transmis et RDP reste désactivé.
- Tests : hashes indépendants, nonce et direction, pin TLS absent/différent, handshake incomplet, SubjectPublicKeyInfo invalide, retour serveur altéré ou tronqué.
- Validation de l'incrément 12 : `make build vet test`, `go test -race ./pkg/rdp/... -count=1`, `make proto-lint`, `GOTOOLCHAIN=go1.27.3 make vuln`, `gofmt` et `git diff --check` passent. `govulncheck` ne trouve aucune vulnérabilité atteignable ; certains modules requis contiennent des avis non appelés. `npm audit` retourne zéro vulnérabilité pour les deux workspaces UI.
- `make test-integration` passe : 287,742 s de tests (299,22 s pour la commande complète). Les tests PostgreSQL sont ignorés faute de `TEST_DATABASE_URL` ; les tests Compose restent réservés à GitHub Actions et n'ont pas été lancés localement.


## 2026-11-04 — ADR-0071, incrément 13 : protection GSS_Wrap NTLMSSP

- Branche de travail : feat/rdp-ntlm-gss-wrap, créée depuis main après fusion de la PR #26.
- Ajout de pkg/rdp/ntlmssp_seal.go : contexte client NTLMSSP, clés de signature/scellement directionnelles, RC4 persistant par direction, HMAC-MD5 et séquences indépendantes.
- Le profil NEGOTIATE exige SIGN, SEAL, 128 bits et Extended Session Security ; KEY_EXCH reste non négocié, donc SessionBaseKey sert d'exported session key.
- Le contexte n'accepte qu'une réponse NTLMv2 calculée par ComputeNTLMv2Response et un CHALLENGE issu du parseur strict ; server challenge et TargetInfo doivent correspondre exactement au proof calculé. Les erreurs de signature, rejeux, désordres et messages mal formés empoisonnent la direction concernée.
- Vecteur de référence MS-NLMP GSS_WrapEx ajouté, avec variante sans KEY_EXCH ; tests de clés directionnelles, NUL terminal, aller/retour, altération, rejeu, désordre, downgrade des flags et fermeture.
- Aucun branchement à TSRequest.pubKeyAuth/authInfo n'est fait dans cet incrément ; pas de dialogue CredSSP/SPNEGO complet, aucun credential transmis et runtime RDP toujours désactivé.

Validation :
- make build vet test : PASS.
- go test ./pkg/rdp/... -count=1 : PASS.
- go test -race ./pkg/rdp/... -count=1 : PASS.
- make proto-lint : PASS.
- GOTOOLCHAIN=go1.27.3 make vuln : PASS ; aucune vulnérabilité atteignable détectée, quelques avis subsistent dans des modules requis mais non appelés ; npm audit : 0 vulnérabilité dans les deux workspaces UI.
- make test-integration : PASS (247.583 s). Les tests PostgreSQL sont ignorés lorsque TEST_DATABASE_URL n'est pas défini. Les tests Compose restent réservés à GitHub Actions.
- git diff --check : PASS.
- Tests de mutation : retirer la comparaison HMAC fait échouer le test d'altération ; retirer l'incrément de séquence fait échouer le test de compteur. Les mutations ont été restaurées, puis les tests et la race suite sont repassés.

Nettoyage de l'environnement :
- go clean -cache, nettoyage Conda/npm et purge BuildKit ont libéré les caches régénérables.
- docker builder prune --all --force a récupéré 750.8 MB ; aucun volume Docker n'a été supprimé.
- overlay : 94 % utilisés avant nettoyage, 84 % après le nettoyage Docker (4.8 GB disponibles). Le build et les tests ont ramené l'usage à environ 86 % (4.2 GB disponibles).


## 2026-11-04 — ADR-0071, incrément 14 : raccordement TSRequest pubKeyAuth

- `pkg/rdp/credssp_exchange.go` ajoute `NewCredSSPClientBindingRequest` : v5/v6 uniquement, dernier jeton SPNEGO fourni par l'appelant, hash client→serveur scellé via NTLMSSP GSS_Wrap, `pubKeyAuth` et `clientNonce` dans le même TSRequest. L'appel consomme une séquence sortante et la requête ne doit être envoyée qu'une fois.
- `VerifyCredSSPServerBindingResponse` n'accepte qu'une réponse TSRequest avec les champs `version` et `pubKeyAuth`, vérifie la version, déroule le flux serveur→client, valide la signature/la séquence GSS_Wrap et compare le hash attendu en temps constant. Toute erreur ferme le contexte.
- Tests couvrent l'aller-retour client/serveur, le dernier jeton, le nonce, l'absence du hash en clair, les champs supplémentaires, la version, le hash faux, la signature altérée et le rejeu.
- Limites : pas de transport TLS ni de machine d'état SPNEGO/CredSSP ; le dernier jeton est fourni par l'appelant. `authInfo`, MCS/GCC, affichage et entrée restent à faire. Aucun credential n'est transmis et RDP reste désactivé.

Validation de l'incrément 14 :
- `make build vet test` : PASS.
- `go test -race ./pkg/rdp/... -count=1` : PASS.
- `make proto-lint` : PASS.
- `GOTOOLCHAIN=go1.27.3 make vuln` : PASS ; aucune vulnérabilité atteignable, quelques avis dans des modules requis mais non appelés ; `npm audit` : zéro vulnérabilité dans les deux workspaces UI.
- `make test-integration` : PASS (222.858 s) ; PostgreSQL ignoré faute de `TEST_DATABASE_URL`. Les tests Compose restent réservés à GitHub Actions.
- `git diff --check` : PASS.


## 2026-11-04 — ADR-0071, incrément 15 : machine d'état CredSSP/SPNEGO sur TLS

- Branche : `feat/rdp-credssp-spnego-state-machine`, créée depuis `main` synchronisé sur le merge PR #28 (`30103b5`).
- `pkg/rdp/spnego_marshal.go` encode les jetons SPNEGO client `NegTokenInit` (NTLM uniquement + NTLMSSP NEGOTIATE) et `NegTokenResp` final (NTLMSSP AUTHENTICATE).
- `pkg/rdp/credssp_client.go` ajoute `Transport.EstablishCredSSP` : TSRequest initial, validation de la réponse SPNEGO `accept-incomplete`/NTLM, challenge NTLMSSP strict, preuve NTLMv2 + MIC, AV_PAIR TargetName/ChannelBindings issus du TLS épinglé, AUTHENTICATE + `pubKeyAuth` + nonce dans le dernier TSRequest, puis vérification de la réponse `pubKeyAuth` serveur.
- Négociation de version bornée au minimum entre version client et serveur, v5/v6 seulement. Lecture d'un TSRequest à la fois, longueur DER canonique et borne 64 Kio ; délai par défaut 10 s, annulation de contexte, fermeture du transport sur tout échec ou état incertain. Le contexte NTLMSSP est remis dans `CredSSPClientSession` et doit être fermé explicitement.
- Le test bout en bout TLS factice vérifie la preuve NTLMv2, le MIC du transcript, les AV_PAIR client et `MIC_PRESENT`, le binding client→serveur, le retour serveur scellé, l'absence du mot de passe en clair sur le fil, ainsi que la négociation descendante v6→v5. Tests dédiés couvrent les encodages SPNEGO, les longueurs DER et l'annulation avant émission.
- `authInfo`/`TSCredentials` n'est pas construit ni transmis ; le mot de passe sert seulement à calculer NTProof et n'est jamais sérialisé. Kerberos, `request-mic`/`mechListMIC`, CredSSP hors v5/v6 et Remote Guard restent refusés. Pas d'interopérabilité Windows réelle revendiquée ; MCS/GCC, capacités, affichage et entrée restent absents. Le runtime et la route RDP restent désactivés.

Vérifications ciblées pendant l'implémentation : `go test ./pkg/rdp/... -count=1` et `git diff --check` passent. Les résultats des gates complètes sont consignés ci-dessous.

Validation finale de l'incrément 15 :
- `go test ./pkg/rdp/... -count=1` : PASS (5,0 s).
- `make build vet test` : PASS sur tous les packages (56,32 s).
- `go test -race ./pkg/rdp/... -count=1` : PASS (22,25 s).
- `make proto-lint` (`buf lint` + `buf generate`) : PASS.
- `GOTOOLCHAIN=go1.27.3 make vuln` : PASS ; zéro vulnérabilité atteignable détectée. Des avis subsistent dans quelques modules requis mais non appelés ; `npm audit` retourne zéro vulnérabilité dans `web/admin-ui` et `web/openbastion-icons`.
- `make test-integration` : PASS (237,746 s pour `test/integration`). Les tests PostgreSQL sont ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose n'a été lancé localement ; ils restent réservés à GitHub Actions.
- `gofmt -l` ne retourne aucun fichier ; `git diff --check` : PASS.
- Espace disque après les validations : 4,2 Go disponibles (87 % utilisés). Aucun nettoyage destructif n'a été nécessaire.


## 2026-11-04 — ADR-0071, incrément 16 : TSCredentials / authInfo

- `pkg/rdp/credssp_credentials.go` encode `TSCredentials` type 1 et `TSPasswordCreds` en DER, avec `domainName`, `userName` et `password` UTF-16LE. Domaine vide accepté ; username/password obligatoires ; UTF-8 invalide et tailles > 256/256/1024 octets (domain/username/password) refusés, alignées sur les bornes NTLMv2. Les buffers UTF-16LE et les assemblages DER temporaires sont effacés après copie.
- `Transport.EstablishCredSSP` envoie maintenant `authInfo` uniquement après validation du `pubKeyAuth` serveur. `authInfo` est le résultat de `NTLMSSPClientSecurityContext.WrapClientToServer(TSCredentials)` ; la signature GSS_Wrap précède le ciphertext. Le TSRequest final n'accepte/émet que `version` + `authInfo`.
- La séquence sortante GSS_Wrap reste continue : `pubKeyAuth` client utilise le compteur 0, `authInfo` utilise le compteur 1. Le contexte NTLMSSP est fermé immédiatement après l'envoi ; le TLS vérifié reste possédé par `CredSSPClientSession` jusqu'à `Close`.
- Envoi unique, pas de retry après erreur/écriture incertaine ; toute erreur après début de négociation ferme le transport. Le buffer Password fourni par l'appelant est emprunté en lecture seule et n'est pas effacé par la bibliothèque ; l'appelant doit le purger.
- Le faux serveur TLS vérifie l'authInfo réellement reçu : forme TSRequest stricte, absence de texte mot de passe UTF-8/UTF-16LE en clair, déchiffrement et vérification du type TSCredentials + des trois valeurs. Les tests unitaires couvrent Unicode BMP et hors BMP, domaine vide, champs invalides/surdimensionnés, champ authInfo exclusif et altération de signature avec empoisonnement de séquence. Le faux serveur TLS vérifie aussi qu’un hash `pubKeyAuth` serveur invalide entraîne la fermeture sans aucun octet `authInfo` envoyé.
- Limites : mot de passe seulement ; carte à puce et Remote Guard refusés. Aucune validation Windows/RDS réelle. Kerberos/SPNEGO MIC, MCS/GCC, capacités, affichage et entrée restent à faire. Le runtime et la route RDP restent désactivés.

Validation finale de l'incrément 16 :
- `make build vet test` : PASS sur tous les modules (38,35 s).
- `go test ./pkg/rdp/... -count=1` : PASS ; 76 tests de premier niveau mesurés avec `go test -v ./pkg/rdp/... -count=1 | grep -c '^--- PASS'`.
- `go test -race ./pkg/rdp/... -count=1` : PASS (6,10 s).
- `make proto-lint` (`buf lint` + `buf generate`) : PASS.
- `GOTOOLCHAIN=go1.27.3 make vuln` : PASS ; zéro vulnérabilité atteignable détectée. Certains modules requis contiennent des avis non appelés ; `npm audit` : zéro vulnérabilité dans `web/admin-ui` et `web/openbastion-icons`.
- `make test-integration` : PASS (252,780 s). Les tests PostgreSQL sont ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose n'a été lancé localement ; ils restent réservés à GitHub Actions.
- Trois mutations de sécurité tuées sur trois : suppression de GSS_Wrap détectée par le faux serveur TLS ; acceptation de champs TSRequest inattendus détectée par le validateur strict ; omission de la vérification `pubKeyAuth` serveur détectée parce que le client délègue alors des credentials sur un binding invalide.
- `gofmt` ne retourne aucun fichier ; `git diff --check` : PASS.
- Espace disque après les validations : 4,2 Go disponibles (87 % utilisés).
- Rouge sur le commit précédent : non applicable directement, car les tests de cette tranche ciblent le nouveau contrat `authInfo` et les API de sérialisation/protection qui n'existaient pas avant l'incrément.


## 2026-11-04 — ADR-0071, incrément 17 : Basic Settings Exchange MCS/GCC

- Branche : `feat/rdp-mcs-gcc-connection`, créée depuis `main` après fusion de la PR #30.
- `pkg/rdp/mcs_gcc.go` encode le MCS Connect-Initial BER [APPLICATION 101] et le GCC Conference-Create-Request PER/T.124, avec `Duca`, DomainParameters, `CS_CORE` 32 bpp + `PROTOCOL_HYBRID` et `CS_SECURITY` avec une capacité 128 bits valide (champ standard ou extension de locale française). HYBRID reste obligatoire, donc ces capacités ne sont pas utilisées ; le serveur doit confirmer `SC_SECURITY` none/none. Aucun canal virtuel n'est demandé ; `CS_NET` est donc omis.
- `CredSSPClientSession.ConnectMCS` enchaîne après l'envoi réussi de `authInfo`, avec deadline, annulation, transition à usage unique et fermeture terminale en cas d'erreur. Le contexte est revalidé après acquisition du verrou et avant toute écriture ; un faux serveur TLS vérifie la fermeture terminale en cas d'annulation pendant la lecture de la réponse. Un faux serveur TLS vérifie aussi qu'aucun MCS n'est envoyé avant la délégation des credentials.
- Le parseur de réponse vérifie MCS Connect-Response [APPLICATION 102], la structure des DomainParameters BER (valeurs ignorées conformément au protocole), GCC Conference-Create-Response et `McDn`, puis `SC_CORE`, `SC_SECURITY` et `SC_NET`. Il accepte l'absence du champ optionnel `earlyCapabilityFlags`. Seul le profil HYBRID, chiffrement RDP standard désactivé, canal global 1003 et zéro canal virtuel est accepté. Les longueurs BER/PER, blocs inconnus/dupliqués et versions serveur sont bornés.
- Validation : `make build vet test proto-lint` PASS (Go 1.27.1) ; `go test ./pkg/rdp/... -count=1` PASS ; `go test -race ./pkg/rdp/... -count=1` PASS ; 88 tests RDP de premier niveau mesurés ; fuzz `FuzzParseMCSConnectResponse` PASS (63 234 exécutions en 5 s, 0 nouvelle entrée intéressante) ; `GOTOOLCHAIN=go1.27.3 make vuln` PASS, aucune vulnérabilité atteignable ; certains modules requis ont des avis non appelés ; `npm audit` zéro vulnérabilité dans les deux workspaces UI.
- `make test-integration` avec BuildKit a échoué sur deux extractions de couches Debian (`content digest ... not found`) dans les tests LDAP. `DOCKER_BUILDKIT=0 make test-integration` : PASS (252,405 s), y compris les deux parcours LDAP. PostgreSQL ignoré faute de `TEST_DATABASE_URL` ; tests Compose non lancés localement, réservés à GitHub Actions.
- Rouge mesuré sur `origin/main` (`8c8accf`) : les tests de l'incrément ne compilent pas avant l'ajout de l'API MCS/GCC. Quatre mutations tuées sur quatre : protocole, chiffrement RDP, canal virtuel et clé H.221.
- `gofmt` et `git diff --check` passent. Espace disque après validation : 3,5 Go disponibles (89 % utilisés), aucun nettoyage destructif.
- Limites : pas encore d'Erect Domain, Attach User, Channel Join, capacités, Client Info, affichage ni entrée ; aucune interopérabilité Windows/RDS réelle ; runtime et route RDP restent désactivés.


## 2026-11-04 — ADR-0071, incrément 18 : MCS Channel Connection

- `pkg/rdp/mcs_channel.go` encode Erect Domain Request, Attach User Request et Channel Join Request. Le premier est conforme au vecteur normatif `04 01 00 01 00` ; l'Attach User Confirm décode l'identifiant utilisateur PER avec son offset 1001. Les Channel Join Requests encodent l'initiateur de la même manière et les IDs de canal directement.
- `CredSSPClientSession.ConnectMCSChannels` s'exécute uniquement après `ConnectMCS`, rejoint dans l'ordre le canal utilisateur puis le canal I/O 1003, et exige pour chaque confirmation un résultat réussi et une correspondance stricte des trois identifiants. La session conserve l'ID utilisateur et l'état de connexion des canaux. Aucun canal statique n'est demandé ni accepté.
- Toute erreur, réponse mal formée, substitution de canal ou annulation après le début de l'échange ferme le TLS. L'opération est à usage unique, verrouillée et soumise à deadline/context.
- Tests : faux serveur TLS pour le parcours complet, rejet Attach User, mauvais Channel Join Confirm, annulation, séquence exacte, transitions à usage unique ; fuzzers sur Attach User Confirm et Channel Join Confirm.
- Rouge mesuré sur le commit précédent `4fb3546` dans un worktree détaché : les nouveaux tests échouent à compiler faute des API de l'incrément.
- Validation finale :
  - `make build vet test proto-lint` : PASS (42,4 s), compilation, `go vet`, tests de tous les modules et `buf lint`.
  - `go test ./pkg/rdp/... -count=1` : PASS ; 98 tests de premier niveau mesurés avec `go test -v ./pkg/rdp/... -count=1 | grep -c '^--- PASS'`.
  - `go test -race ./pkg/rdp/... -count=1` : PASS.
  - Fuzz `FuzzParseMCSAttachUserConfirm` : PASS, 39 466 exécutions en 3 s, 5 entrées intéressantes nouvelles ; `FuzzParseMCSChannelJoinConfirm` : PASS, 39 427 exécutions en 3 s, 5 entrées intéressantes nouvelles.
  - `GOTOOLCHAIN=go1.27.3 make vuln` : PASS ; aucune vulnérabilité atteignable dans les packages analysés, quelques avis restent dans des modules requis mais non appelés ; `npm audit` : zéro vulnérabilité dans `web/admin-ui` et `web/openbastion-icons`.
  - `DOCKER_BUILDKIT=0 make test-integration` : PASS (225,956 s). Les tests d'intégration à processus réels ont passé ; les scénarios PostgreSQL sont ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose n'a été lancé localement : ils restent réservés à GitHub Actions.
  - Trois mutations de sécurité tuées sur trois : ignorer le résultat du Channel Join Confirm, accepter un canal confirmé substitué et ne pas fermer le transport sur réponse invalide font échouer les tests.
  - Rouge mesuré sur le commit précédent `4fb3546` dans un worktree détaché : les nouveaux tests échouent à compiler en l'absence des API Channel Connection.
  - `gofmt` ne retourne aucun fichier ; `git diff --check` : PASS.
  - Aucun test d'interopérabilité Windows/RDS réel n'a été exécuté ; le runtime et la route RDP restent désactivés.
- Limites : capacités, Client Info/licensing, affichage et entrée restent absents ; aucune interopérabilité Windows/RDS réelle ; runtime et route RDP toujours désactivés.


## 2026-11-04 — ADR-0071, incrément 19 : RDP Mandatory Capability Exchange

`pkg/rdp/mcs_capabilities.go` ajoute `CredSSPClientSession.ExchangeCapabilities`, appelable une seule fois après CredSSP, MCS Connect-Initial/Response et Channel Connection. Le client lit un MCS Send Data Indication sur le canal I/O 1003, exige l'initiateur serveur (1002), le PDU de segmentation complet et un Demand Active dont le Share Control Header, le Share ID, la source et toutes les longueurs sont cohérents. La phase Licensing précède normalement Demand Active ; elle n'est pas encore implémentée et le test injecte donc Demand Active directement après les Channel Joins.

Le parseur borne 32 Capability Sets, 2 Kio par bloc et le TPKT total ; il refuse les doublons, les longueurs invalides, les dimensions hors limites, tout profil autre que 32 bpp, l'absence des indicateurs Bitmap obligatoires, les flags d'entrée inconnus et l'absence des capacités General, Bitmap, Order, Pointer ou Input. Les champs que MS-RDPBCGR demande d'ignorer (padding, profondeurs bitmap legacy, caches pointer) restent ignorés. Les autres types sont conservés comme identifiants uniquement après validation de leur enveloppe ; leurs contenus ne sont pas interprétés ni activés.

Le Confirm Active utilise le Share ID serveur et l'identifiant de canal utilisateur attribué. Il annonce les cinq capacités minimales conformes : General, Bitmap 32 bpp sans négocier la réception de bitmaps compressés, avec rectangles multiples, Order niveau 1 mais sans ordre primaire, Pointer avec le flag Color Pointer obligatoire et sans cache, Input limité aux scancodes. Aucun fast-path, Unicode, événement souris étendu ou ordre primaire n'est annoncé. Le décodeur bitmap RAW 32 bpp est livré à l’incrément 23 ; les bitmaps compressés et les consommateurs pointer/input restent à implémenter avant l’activation du runtime. Le transport reste sous TLS HYBRID ; aucune sécurité RDP standard n'est activée. La transition est à usage unique, bornée par contexte/deadline et terminale en cas de réponse invalide ou d'écriture incertaine.

Le faux serveur TLS teste la séquence MCS Connect-Initial/Response, Erect Domain, Attach User, les deux Channel Joins, Demand Active et Confirm Active. Les tests couvrent les champs MCS substitués, les longueurs, les doublons, les capacités manquantes, les dimensions et les booléens. Un fuzzer couvre le parseur Demand Active.

**Limites restantes :** Licensing et Client Info ne sont pas implémentés ; aucune interopérabilité Windows/RDS n'est démontrée. Le décodage bitmap/ordres, l'entrée, le runtime et la route RDP restent désactivés. Les capacités client Order/Pointer/Input sont volontairement à zéro jusqu'à l'implémentation de leurs moteurs.

Validation finale de l'incrément 19 :
- `make build vet test proto-lint` : PASS (tous les modules, `go vet`, tests et `buf lint`).
- `go test ./pkg/rdp/... -count=1` : PASS ; 105 tests de premier niveau mesurés.
- `go test -race ./pkg/rdp/... -count=1` : PASS.
- Fuzz `FuzzParseRDPDemandActive` : 80 789 exécutions en 6 s, 2 entrées intéressantes nouvelles (7 au total).
- Six mutations de sécurité tuées sur six : doublon, fermeture terminale, limite de pixels, compression bitmap obligatoire, rectangles multiples obligatoires et SCANCODES obligatoire.
- Rouge sur le commit de base `456a1aff` dans un worktree détaché : échec de compilation des tests en l'absence de l'API nouvelle.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable dans les packages analysés ; quelques avis subsistent dans des modules requis mais non appelés. `npm audit` : zéro vulnérabilité dans Admin UI et openbastion-icons.
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (217,088 s) ; scénarios PostgreSQL ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose local, conformément à la consigne : GitHub Actions les exécute.
- `gofmt` et `git diff --check` : PASS. Pas de test Windows/RDS réel ; route/runtime RDP désactivés.


## 2026-11-04 — ADR-0071, incrément 20 : Client Info

Le package pkg/rdp/mcs_client_info.go construit le CLIENT_INFO_PDU après CredSSP et Channel Connection. Il utilise un MCS Send Data Request sur le canal global I/O 1003, avec le User Channel ID comme initiator, un Basic Security Header SEC_INFO_PKT et un TS_INFO_PACKET Unicode UTF-16LE. Les flags INFO_AUTOLOGON et INFO_FORCE_ENCRYPTED_CS_PDU sont activés. Le domaine, le nom d'utilisateur et le mot de passe ont un terminateur NUL obligatoire ; AlternateShell et WorkingDir restent vides.

Le mot de passe est transmis une seconde fois dans le champ Password du TS_INFO_PACKET, conformément à l'ouverture automatique d'une session RDP classique. Il a déjà été délégué dans authInfo CredSSP scellé ; les deux transmissions sont protégées par CredSSP/GSS_Wrap et TLS HYBRID. Le secret n'est ni conservé dans CredSSPClientSession, ni écrit dans les journaux ou l'audit. RDPClientInfo.Password est une tranche empruntée en lecture seule ; les buffers temporaires d'encodage sont effacés, et l'appelant doit effacer sa tranche après la transition. Les champs cb* excluent le terminateur et sont bornés à 510 octets UTF-16 (512 avec NUL). L'encodeur rejette UTF-8 invalide, NUL et caractères de contrôle pour l'identité ; les mots de passe peuvent contenir des contrôles non NUL. SendClientInfo est une transition unique, limitée au contexte/deadline et autorisée uniquement après CredSSP, MCS et les deux Channel Joins. Toute erreur de transport ou écriture incertaine ferme le TLS ; une entrée locale invalide laisse la session intacte. ExchangeCapabilities exige Client Info et licensingComplete=true. Aucun handler de Licensing ne peut encore positionner cet état en production ; après Client Info, la session reste bloquée sans consommer de PDU serveur. Les tests de capacités positionnent explicitement cet état de façon synthétique pour isoler le codec post-Licensing.

**Ce que cela ne fait PAS :** aucun PDU de Licensing n'est encore traité. Si un serveur envoie Server License Request ou Licensing Error Alert, aucun parseur ne le consomme encore. La session reste bloquée après Client Info ; ExchangeCapabilities refuse toute lecture tant que licensingComplete est faux. Le fixture du test de capacités simule un état post-Licensing, sans implémenter ni valider le protocole de licence. Aucun CAL n'est lu, stocké, émis ou renouvelé. Pas de validation Windows/RDS réelle, de finalisation, d'affichage, d'entrée ni d'activation de la route RDP.

Validation finale de l'incrément 20 :
- make build vet test proto-lint : PASS sur tous les modules Go, go vet, tests unitaires et buf lint.
- go test ./pkg/rdp/... -count=1 : PASS ; 112 tests de premier niveau mesurés.
- go test -race ./pkg/rdp/... -count=1 : PASS.
- Fuzz FuzzMarshalRDPClientInfo : 38 738 exécutions en 6 s, 31 entrées intéressantes nouvelles (34 au total).
- 17 mutations de sécurité tuées sur 17 : flags Unicode/auto-logon/TLS, SEC_INFO_PKT, longueurs cbDomain/cbPassword, contenu Password, canal MCS, initiator, séquencement, émission unique, identité/secret obligatoires, borne UTF-16, NUL, contrôles et UTF-8.
- Rouge mesuré sur le commit de base 97a5934 dans un worktree détaché : échec de compilation en l'absence des nouvelles API.
- GOTOOLCHAIN=go1.27.3 make vuln : aucune vulnérabilité atteignable dans les packages analysés ; quelques avis subsistent dans des modules requis mais non appelés. npm audit : zéro vulnérabilité dans Admin UI et openbastion-icons.
- DOCKER_BUILDKIT=0 make test-integration : PASS (291,076 s) ; scénarios PostgreSQL ignorés faute de TEST_DATABASE_URL. Aucun test Compose local, conformément à la consigne : GitHub Actions les exécute.
- gofmt, validation YAML par Ruby/Psych et git diff --check : PASS.
- Aucun test Windows/RDS réel ; Licensing, finalisation, affichage, entrée, runtime et route RDP restent à faire/désactivés.

## 2026-11-04 — ADR-0071, incrément 21 : Licensing Personal Terminal Server

Le client RDP ne saute plus l'étape Licensing. CredSSPClientSession.CompleteLicensing lit un SERVER_LICENSE_REQUEST sur le canal MCS global I/O, valide le MCS Send Data Indication, le canal serveur, le Security Header SEC_LICENSE_PKT, le préambule, ProductInfo, KeyExchangeList RSA, le certificat et les scopes. Il répond avec un CLIENT_NEW_LICENSE_REQUEST : ClientRandom aléatoire, premaster 48 octets chiffré RSA PKCS#1 v1.5, username ASCII imprimable et ClientName CS_CORE comme machine name. Le certificat RSA de Licensing peut être extrait d'une chaîne X.509 version 2 transportée dans le TLS authentifié ; si le BLOB est vide, la clé RSA du certificat TLS est utilisée. Clés inférieures à 1024 bits, certificats legacy propriétaires et clés non-RSA sont refusés.

Seul le ERROR_ALERT exact STATUS_VALID_CLIENT + ST_NO_TRANSITION + BB_ERROR_BLOB vide termine Licensing. PLATFORM_CHALLENGE, NEW_LICENSE, UPGRADE_LICENSE, toute erreur ou toute réponse inattendue ferment le TLS. licensingAttempted empêche les reprises ; licensingComplete n'est positionné qu'après validation de la réponse et restauration de la deadline. Le nom d'utilisateur est mémorisé pour le seul BLOB Licensing (jamais le mot de passe). Les buffers aléatoires, premaster, ciphertext et PDU temporaires sont effacés.

Le faux serveur TLS teste Client Info → Server License Request X.509 → New License Request (et déchiffre le premaster côté serveur) → STATUS_VALID_CLIENT → Demand Active/Confirm Active. Les parseurs ont des tests négatifs et des fuzzers dédiés. Le périmètre est volontairement Personal Terminal Server : aucun CAL, aucune émission/mise à niveau de licence ni Platform Challenge ; les noms d'utilisateur Licensing non ASCII et les certificats propriétaires legacy sont refusés. Aucun test Windows/RDS réel ; runtime et route RDP restent désactivés.


## 2026-11-04 — ADR-0071, incrément 22 : finalisation de la connexion RDP

`pkg/rdp/mcs_finalization.go` ajoute `CredSSPClientSession.FinalizeConnection`, accessible uniquement après CredSSP, MCS Channel Connection, Client Info, Licensing réellement validé et Demand Active/Confirm Active. Le client émet dans l’ordre strict les quatre PDU de finalisation : Synchronize (targetUser = canal serveur 1002), Control/Cooperate, Control/Request Control puis Font List vide (`FIRST|LAST`, entrée de 50 octets). Chaque message est encapsulé dans un MCS Send Data Request sur le canal global I/O 1003, avec l’identifiant utilisateur attribué et le Share ID reçu du serveur. Aucun en-tête de sécurité RDP standard n’est ajouté : le profil reste HYBRID/TLS, avec chiffrement RDP standard désactivé.

Le client attend et valide ensuite, dans l’ordre, Server Synchronize (targetUser = 0, comme recommandé par MS-RDPBCGR), Server Control/Cooperate, Server Control/Granted Control et Server Font Map. Le parseur vérifie TPKT/X.224, MCS Send Data Indication, initiateur serveur 1002, canal 1003, segmentation complète, Share Control/Data headers, Share ID, source, type de PDU, flux, longueurs et champs utiles. Le Font Map du profil minimal doit annoncer zéro entrée, `FIRST|LAST` et `entrySize=4`. Cooperate conserve grantId/controlId à zéro ; Granted Control doit retourner grantId=User Channel ID et controlId=canal serveur 1002. Le Server Synchronize accepte STREAM_UNDEFINED ou STREAM_LOW, le premier étant observé dans certaines implémentations. Une réponse inattendue, réordonnée, compressée, tronquée ou incohérente ferme TLS et rend la session terminale. `connectionFinalized` n’est posé qu’après validation des quatre réponses et restauration de la deadline.

Les échanges client→serveur sont envoyés en lot, dans l’ordre requis, avant la lecture des réponses : MS-RDPBCGR §1.3.1.1 précise que les PDU client de finalisation n’ont pas de dépendance sur les réponses serveur et peuvent être envoyés ensemble si leur ordre est respecté. Le serveur répond dans l’ordre Synchronize, Cooperate, Granted Control, Font Map ; Font Map clôt la séquence de connexion.

Tests : encodeurs des quatre PDU client, tests négatifs des en-têtes et champs serveur, faux serveur TLS vérifiant le lot client puis renvoyant les quatre réponses, contrôle des prérequis et de l’usage unique, fuzzer du parseur de finalisation. Aucun moteur graphique ou d’entrée n’est activé ; aucune route RDP n’est exposée.

**Limites restantes :** pas de magasin CAL ni de flux New/Upgrade License ou Platform Challenge ; certificats Licensing propriétaires legacy et noms Licensing non ASCII refusés ; pas d’interopérabilité Windows/RDS réelle. La finalisation protocolaire est exercée sur un faux serveur TLS, pas sur Windows/RDS. Le décodage bitmap compressé, les ordres graphiques, le pointeur, le clavier/la souris, le runtime RDP et sa route restent désactivés.

Références normatives : [MS-RDPBCGR §1.3.1.1 — Connection Sequence](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee), [§2.2.1.14 — Client Synchronize](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e0027486-f99a-4f0f-991c-eda3963521c2), [§2.2.1.16 — Client Request Control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4f94e123-970b-4242-8cf6-39820d8e3d35), [§2.2.1.19 — Server Synchronize](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5186005a-36f5-4f5d-8c06-968f28e2d992), [§2.2.1.21 — Server Granted Control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ff7bae0e-cd13-4776-83b2-ef1f45e1fc41), [§2.2.1.18 — Client Font List](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7067da0d-e318-4464-88e8-b11509cf0bd9), [§2.2.1.22 — Server Font Map](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7ba6ba81-e4f4-46a7-9062-2d57a821be26).


Validation finale de l’incrément 22 :
- `make build vet test proto-lint` : PASS sur tous les modules, compilation, `go vet`, tests unitaires et `buf lint`.
- `go test -race ./pkg/rdp/... -count=1` : PASS.
- `FuzzParseRDPFinalizationResponse` : PASS, 65 410 exécutions en 5 s, 1 entrée intéressante nouvelle (12 au total).
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (290,401 s) ; les tests de processus réels passent. Les scénarios PostgreSQL ont été ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose n’a été lancé localement ; ils restent réservés à GitHub Actions.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable dans les packages analysés ; quelques avis restent dans des modules requis mais non appelés. `npm audit` : zéro vulnérabilité dans `web/admin-ui` et `web/openbastion-icons`.
- `git diff --check` : PASS. Aucun test d’interopérabilité Windows/RDS réel ; runtime et route RDP restent désactivés.


## 2026-11-04 — ADR-0071, incrément 23 : RDP Bitmap Update RAW 32 bpp

`pkg/rdp/mcs_bitmap.go` décode un MCS Send Data Indication complet sur le canal I/O global 1003, avec initiateur serveur 1002, puis valide le Share Data PDU `UPDATE` et le sous-type `UPDATE_BITMAP`. Le parseur contrôle TPKT/X.224, PER length, Share ID, source, stream, flags de compression et toutes les longueurs avant toute allocation. Il borne les rectangles à 64 et le cumul de pixels à 16 777 216 ; chaque rectangle doit être non vide, avoir des coordonnées inclusives cohérentes, rester dans le bureau négocié, être en 32 bpp non compressé et avoir exactement `width × height × 4` octets.

Les pixels TS_BITMAP_DATA bottom-up/BGRX sont convertis en RGBA top-down, alpha forcé à 255. Les données compressées (BITMAP_COMPRESSION et NO_BITMAP_COMPRESSION_HDR), les profondeurs non-32 bpp, les flags inconnus, les longueurs invalides et les données résiduelles sont refusés. Le Confirm Active n’annonce plus la capacité de réception de bitmaps compressés : aucun serveur conforme ne doit donc choisir un format que le client ne sait pas décoder. Le serveur peut néanmoins annoncer sa propre capacité de compression dans Demand Active ; cela ne vaut pas activation de la réception compressée côté client.

Tests : rectangle 2×2 avec vérification de l’inversion verticale et de la conversion BGRX→RGBA ; plusieurs rectangles ; cas négatifs sur TPKT, initiateur, canal, segmentation, Share Data Header, Share ID, stream, type d’update, compression, profondeur, nombre de rectangles, coordonnées, limites du bureau, tailles et données résiduelles ; fuzz du parseur. Le parseur traite un TPKT unique plafonné à 4096 octets ; le réassemblage MCS multi-segments et les grands rectangles restent à implémenter. Aucun ordre graphique, bitmap compressé, pointeur, clavier/souris ou runtime n’est activé ; ce parseur n’est pas encore raccordé à `CredSSPClientSession` ni à `proxycore.ScreenCodec`.

Références normatives : [MS-RDPBCGR §2.2.9.1.1.3.1.2 — Bitmap Update](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/cf8fed19-573e-4bc3-bd87-66d45d2a8af0), [§2.2.9.1.1.3.1.2.2 — Bitmap Data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/84a3d4d2-5523-4e49-9a48-33952c559485), [§2.2.7.1.2 — Bitmap Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/76670547-e35c-4b95-a242-5729a21b83f6).

Validation de l’incrément 23 :
- `make build vet test proto-lint` : PASS sur tous les modules Go, `go vet`, tests unitaires et `buf lint`.
- `go test ./pkg/rdp/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... -count=1` : PASS.
- `FuzzParseRDPBitmapUpdate` : PASS, 79 488 exécutions en 5 s, 13 entrées intéressantes nouvelles (15 au total).
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (213,421 s) ; les tests de processus réels passent. Les scénarios PostgreSQL ont été ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose local, conformément à la consigne : GitHub Actions les exécute.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable ; certains avis subsistent dans des modules requis mais non appelés. `npm audit` : zéro vulnérabilité dans `web/admin-ui` et `web/openbastion-icons`.
- `git diff --check` : PASS. Aucun test d’interopérabilité Windows/RDS réel ; le parseur n’est pas encore raccordé au runtime/ScreenCodec et la route RDP reste désactivée.


## 2026-11-04 — ADR-0071, incrément 24 : MCS Bitmap Receive Path borné

`readTPKTPacket` permet une limite TPKT propre à chaque chemin : le contrôle reste à 4 Kio et le lecteur bitmap est plafonné à 16 383 octets. Ce plafond entier est conservateur par rapport à la limite normative de 16 383 octets des MCS Send Data Request/Indication (MS-RDPBCGR §2.2). Il évite de relever globalement les limites de toutes les phases RDP.

`CredSSPClientSession.ReadBitmapUpdate` lit un seul Bitmap Update sur le TLS épinglé, après `FinalizeConnection` et `Demand Active` validés. Il applique deadline et cancellation, décode les pixels via le parseur RAW de l'incrément 23 et rend le transport terminal sur tout échec de lecture ou de protocole. Un TPKT de 63×63 pixels dépassant 4 Kio est testé sur faux serveur TLS ; le dépassement du plafond est refusé.

À l’incrément 24, seul un SDIN complet (`0x70`) par TPKT était accepté. Le réassemblage multi-segments est livré à l’incrément 25. Aucun bitmap compressé, ordre graphique, pointeur, entrée, adaptateur `proxycore.ScreenCodec`, runtime ou route RDP n’est activé ; aucune interopérabilité Windows/RDS réelle n’a été prouvée.

Validation de l’incrément 24 :
- `make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et `buf lint`.
- `go test ./pkg/rdp/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... -count=1` : PASS.
- `FuzzParseRDPBitmapUpdate` : PASS, 58 161 exécutions en 5 s, 1 entrée intéressante nouvelle (16 au total).
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (210,248 s). Les tests PostgreSQL dépendant de `TEST_DATABASE_URL` ont été ignorés car la variable n’est pas définie. Aucun test Compose local, conformément à la consigne.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable ; quelques avis subsistent dans des modules requis mais non appelés.
- `npm audit --audit-level=low` : zéro vulnérabilité dans `web/admin-ui` et `web/openbastion-icons`.
- `git diff --check` : PASS. Aucun test d’interopérabilité Windows/RDS réel ; réassemblage MCS multi-segments, bitmaps compressés, adaptateur ScreenCodec, runtime et route RDP restent non implémentés/désactivés.


## 2026-11-04 — ADR-0071, incrément 25 : réassemblage MCS multi-segments des bitmaps

`ReadBitmapUpdate` accepte maintenant les MCS Send Data Indication segmentés sur le canal global I/O 1003. Chaque TPKT est toujours lu avec la limite stricte de 16 383 octets. Le lecteur valide séparément l’initiateur serveur, le canal, la priorité HIGH, les bits de padding réservés et le PER length de chaque fragment avant de toucher au buffer d’assemblage.

Le champ MCS `segmentation` est interprété comme un état de flux : `begin` seul ouvre un assemblage, zéro désigne un fragment intermédiaire, `end` seul clôt l’assemblage, et `begin|end` transporte un message complet non fragmenté. Les séquences sans `begin`, avec un second `begin`, avec un message complet au milieu ou avec des flags réservés sont rejetées. La session lit les fragments sous le même verrou, le même contexte et la même deadline ; une interruption, un dépassement ou une séquence invalide ferme le transport TLS et efface le buffer temporaire.

Les bornes sont explicites : cinq fragments au maximum, 16 383 octets par TPKT et 65 535 octets pour le Share Data PDU réassemblé (champ `totalLength` 16 bits). Ce lecteur mono-flux n’entrelace pas d’autres PDUs MCS et refuse l’extension T.125 `totalDataSize` V3 ; ces formes ne sont pas requises par le profil RDP pris en charge. L’assemblage est validé ensuite par le parseur Share Data/Bitmap existant ; aucune taille de bitmap n’est acceptée sur la seule base des fragments. Les pixels décodés restent indépendants du buffer réseau, lequel est effacé après traitement.

Tests : reconstitution d’un bitmap RAW 32 bpp de 120×120 pixels sur cinq fragments TLS ; validation des pixels après conversion BGRX→RGBA ; rejet d’une séquence répétant `begin` et fermeture terminale du transport. Les tests existants du chemin non fragmenté, des limites, des états et du fuzzer restent applicables.

Références normatives : [MS-RDPBCGR §2.2 — Message Syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b61e1c76-5d7c-4285-b61a-b69f85e4a0e2) (borne MCS Send Data à 16 383 octets) ; [MS-RDPBCGR — spécification complète](https://winprotocoldoc.z19.web.core.windows.net/MS-RDPBCGR/%5BMS-RDPBCGR%5D-220903.pdf), qui décrit les bits `begin` et `end` du champ MCS `Segmentation`.

**Limites restantes :** le parseur accepte uniquement les bitmaps RAW 32 bpp non compressés. Les ordres graphiques, les bitmaps compressés, le pointeur, le clavier/souris et l’adaptateur `proxycore.ScreenCodec` ne sont pas implémentés. Le runtime et la route RDP restent désactivés ; aucun test d’interopérabilité Windows/RDS réelle n’est revendiqué.

Validation de l’incrément 25 :
- `go test ./pkg/rdp/... -count=1` : PASS ; `go test -race ./pkg/rdp/... -count=1` : PASS.
- `make build vet test proto-lint` : PASS sur les packages Go, `go vet`, les tests et Buf lint.
- `FuzzParseRDPBitmapUpdate` : PASS, 64 507 exécutions en 5 s, 16 entrées intéressantes au total.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable détectée ; quelques avis subsistent dans des modules requis mais non appelés.
- `npm audit --audit-level=low` dans `web/admin-ui` et `web/openbastion-icons` : zéro vulnérabilité.
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (218,635 s). Les scénarios PostgreSQL ont été ignorés faute de `TEST_DATABASE_URL`. Aucun test Compose local n’a été lancé.
- `git diff --check` : PASS. Aucun test d’interopérabilité Windows/RDS réel ; le runtime et la route RDP restent désactivés.


## 2026-11-04 — ADR-0071, incrément 26 : RDP framebuffer / ScreenStream

`pkg/rdp/RDPFramebuffer` applique les rectangles RGBA RAW du décodeur RDP dans un framebuffer complet à dimensions fixes (noir opaque à l’initialisation) et émet une trame PNG conforme au contrat `screenstream.Message`. Les rectangles partiels préservent les pixels précédents. Dimensions et pixels sont bornés ; chaque rectangle est validé avant mutation ; les zones précédentes sont restaurées si l'encodage ou la validation finale échoue. La séquence n'avance qu'après succès.

Cette brique est un adaptateur de format, pas encore un `proxycore.ScreenCodec` complet : elle ne réalise ni `Open`, ni lecture réseau, ni boucle `Frames`, ni entrée. Les bitmaps compressés, ordres graphiques, pointeur et clavier/souris restent non supportés. Les trames PNG supérieures à 4 Mio sont refusées conformément au contrat ScreenStream v1. Runtime et route RDP restent désactivés.

Validation de l’incrément 26 :
- `make build vet test proto-lint` : PASS sur l'ensemble des modules, `go vet`, tests et Buf lint.
- `go test ./pkg/rdp/... -count=1` : PASS, y compris la restauration du framebuffer après refus d'une PNG dépassant 4 Mio.
- `go test -race ./pkg/rdp/... -count=1` : PASS après les derniers changements.
- `FuzzParseRDPBitmapUpdate` : PASS, 60 275 exécutions en 5 s.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable détectée ; des avis subsistent dans quelques modules requis mais non appelés.
- `npm audit --audit-level=low` dans `web/admin-ui` et `web/openbastion-icons` : zéro vulnérabilité.
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (203,567 s). Les tests PostgreSQL nécessitant `TEST_DATABASE_URL` sont ignorés car la variable n'est pas définie.
- `git diff --check` : PASS. `scripts/check-architecture-deps.sh` absent du dépôt ; aucun gate d'architecture de ce nom n'a donc été exécuté.
- Aucun test Compose local ni test d'interopérabilité Windows/RDS réel. Runtime et route RDP toujours désactivés.


## 2026-11-04 — ADR-0071, incrément 27 : RDP ScreenCodec et cycle des frames

`services/proxy/rdp-vnc-proxy/internal/engine.RDPCodec` relie le moteur RDP existant au contrat `proxycore.ScreenCodec`. L’ouverture exige un pool de racines explicite et les métadonnées Vault d’adresse, utilisateur, nom TLS et empreinte SHA-256. Le client déroule X.224/HYBRID + TLS épinglé, CredSSP NTLMv2 v6, MCS/GCC, Channel Connection, Client Info, Licensing, Capabilities et Finalization. La dimension du bureau retenue provient des capacités réellement négociées par le serveur, et non de la taille demandée au client.

La boucle de lecture récupère les `RDPBitmapUpdate`, les applique à `RDPFramebuffer` et publie les PNG complets sur `ScreenSession.Frames()`. L’annulation du contexte provoque la sortie de la lecture TLS ; `Close` ferme le transport et attend l’arrêt du lecteur. Le secret n’est pas copié dans un stockage persistant du codec : il est emprunté depuis `proxycore.Credential`, dont le cycle de vie assure la purge. Les erreurs de pin TLS et de négociation sont converties en codes `ScreenFailure` stables.

Tests : refus avant connexion lorsque les métadonnées TLS sont incomplètes ou que le pool de racines est absent ; mapping stable de l’erreur de pin ; boucle framebuffer avec un bureau simulé 2×1 (différent de la résolution demandée), vérification d’une trame ScreenStream valide, fermeture du client cible et fin sans erreur lors de l’annulation.

**Limites :** `Input` refuse explicitement les événements avec `screenstream.ErrUnsupported`. L’encodage RDP Input PDU et l’écriture concurrente sécurisée face à la lecture restent à faire ; bitmaps compressés et ordres graphiques restent refusés. Le `RDPCodec` n’est pas sélectionné par le binaire, le runtime et la route RDP restent désactivés. Le champ Vault `TargetDomain` est utilisé comme nom TLS cible ; le domaine AD distinct n’est pas transmis. Aucun test d’interopérabilité Windows/RDS réelle ni E2E avec le Video Recorder n’est revendiqué.

Validation de l’incrément 27 :
- `go test ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./services/proxy/rdp-vnc-proxy/internal/engine ./pkg/rdp/... -count=1` : PASS.
- `make build vet test proto-lint` : PASS.
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (249,495 s). Les tests PostgreSQL nécessitant `TEST_DATABASE_URL` sont ignorés ; aucun test Compose local.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable ; avis résiduels dans quelques modules requis mais non appelés.
- `npm audit --audit-level=low` dans Admin UI et icons : zéro vulnérabilité.
- `git diff --check` : PASS ; aucun test Windows/RDS réel ni E2E RDP/Video Recorder. Runtime et route RDP restent désactivés.


## 2026-11-04 — ADR-0071, incrément 28 : RDP Input PDU

Ajout de `pkg/rdp/mcs_input.go` : `CredSSPClientSession.SendInput` émet des `TS_INPUT_PDU` slow-path dans un Share Data PDU, encapsulé en MCS Send Data Request sur le canal I/O négocié. Types pris en charge : scan code Set-1 (DOWN/RELEASE, E0 extended), souris déplacement, boutons primaires gauche/milieu/droit et molette ±120 par cran. Le masque partagé ScreenStream/RFB (gauche, milieu, droit) est remappé aux flags RDP BUTTON1, BUTTON3, BUTTON2 ; les bits wheel-up/wheel-down sont aussi convertis en impulsions RDP sur front montant. Les lots sont limités à 128 événements. Les keysyms seuls, souris étendue et flags invalides sont refusés.

Le verrou de lecture et le verrou d’écriture TLS sont indépendants. `ReadBitmapUpdate` utilise `SetReadDeadline`, `SendInput` utilise `SetWriteDeadline`, et le verrou d’état n’est pas détenu pendant un read réseau bloquant. Un seul écrivain TLS est autorisé à la fois. Les erreurs/annulations d’écriture ferment le transport. L’adaptateur `RDPCodec.Input` suit les touches/boutons actifs et envoie leurs relâchements sur `InputReleaseAll` et à la fermeture avec un timeout de 2 secondes. L’état n’est mis à jour qu’après l’envoi réussi.

Tests : décodage structurel des PDU, scan codes normaux et étendus, key-up/down, boutons, molette, validation stricte, limites de lot, faux serveur TLS qui reçoit une entrée alors que la lecture bitmap est bloquée, tests engine de traduction et relâchement sur fermeture.

Limites : pas de keysyms/XKB, Unicode/fast-path, boutons souris étendus, synchronisation LED/clavier ou presse-papiers ; bitmaps compressés et ordres graphiques absents. Aucun test Windows/RDS réel. Runtime et route RDP restent désactivés.

Validation de l’incrément 28 :
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` et `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `make build vet test proto-lint` : PASS.
- `FuzzMarshalRDPInput` : PASS, 62 618 exécutions en 5 s.
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (284,562 s). PostgreSQL ignoré sans `TEST_DATABASE_URL` ; Compose ignoré sans `COMPOSE_TEST`.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable ; avis résiduels dans des modules requis mais non appelés.
- `npm audit --audit-level=low` Admin UI et icons : zéro vulnérabilité. `git diff --check` : PASS.
- Aucun test d’interopérabilité Windows/RDS réel ni E2E avec Video Recorder. Runtime et route RDP restent désactivés.


## 2026-11-05 — Incrément 29 : profil RDP6 ARGB à plans bruts

Le parseur `TS_BITMAP_DATA` accepte maintenant le flag `BITMAP_COMPRESSION` sur les rectangles 32 bpp. Le décodeur vérifie le `TS_CD_HEADER` (longueur exacte, `cbCompFirstRowSize=0`, scan width alignée sur 4 et taille décompressée cohérente), puis traite le `RDP6_BITMAP_STREAM` en format ARGB (`CLL=0`), sans subsampling ni RLE des plans. Les plans A (facultatif), R, G, B sont lus bottom-up puis normalisés en RGBA top-down ; sans alpha, celui-ci vaut 255. Un octet de padding final est accepté.

RLE des plans, AYCoCg, chroma subsampling, profondeurs autres que 32 bpp et toutes formes ambiguës restent refusés. Les bornes pixels/rectangles/TPKT/bitmapLength existantes sont conservées. Il s'agit d'un premier profil RDP6, pas de la prise en charge complète de la compression RDP. Le `bitmapCompressionFlag` du Confirm Active reste à zéro : cette capacité n'est pas négociée avec les serveurs tant que tous les profils nécessaires ne sont pas implémentés. Les ordres graphiques ne sont pas implémentés ; runtime et route RDP restent désactivés.

Tests ajoutés : décodage ARGB sans alpha, décodage avec alpha et padding, intégration Bitmap Update, cas négatifs du header et des modes non pris en charge, fuzzer `FuzzDecodeRDP6BitmapWithHeader`.


Validation de l’incrément 29 :
- `go test ./pkg/rdp/... -count=1` : PASS, y compris les lignes bottom-up du RDP6.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `make build vet test proto-lint` : PASS.
- `FuzzDecodeRDP6BitmapWithHeader` : PASS, 61 383 exécutions en 5 s.
- `DOCKER_BUILDKIT=0 make test-integration` : PASS (267,706 s). Les tests PostgreSQL nécessitant `TEST_DATABASE_URL` sont ignorés ; aucun test Compose local n’a été lancé.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable ; quelques avis demeurent dans des modules requis mais non appelés.
- `npm audit --audit-level=low` Admin UI et icons : zéro vulnérabilité. `git diff --check` : PASS.
- Aucun test Windows/RDS réel ni E2E RDP avec Video Recorder. Le `bitmapCompressionFlag` reste à zéro, runtime et route RDP désactivés.


## 2026-11-05 — Incrément 30 : RDP6 RLE des plans ARGB

Le bit RLE du FormatHeader est désormais accepté pour le seul profil ARGB CLL=0, sans chroma subsampling. Le décodeur traite indépendamment les plans alpha (facultatif), rouge, vert et bleu. Chaque plan est parcouru ligne par ligne avec des segments RAW/RUN ; le nibble haut du control byte indique le nombre de valeurs RAW et le nibble bas la longueur RUN. Les runs étendus 16+n et 32+n, les segments sans RAW (valeur de base zéro), ainsi que les deltas zig-zag signés des lignes suivantes sont gérés. Les valeurs reconstruites utilisent l'arithmétique octet modulo 256.

Les limites de sécurité restent strictes : segments bornés à la largeur de ligne, plan borné à width×height, longueur exacte du TS_CD_HEADER, consommation exacte de chaque plan et rejet des contrôles nuls, données tronquées, dépassements, segments vides et octets résiduels. Le padding optionnel reste limité au profil non RLE. Les plans sont recombinés en RGBA top-down. AYCoCg, chroma subsampling, perte de couleur et bits réservés restent refusés ; bitmapCompressionFlag reste à zéro dans Confirm Active.

Tests : vecteur normatif MS-RDPEGDI 3.1.9.2.3 (6×3), runs RAW/RUN et runs étendus, base zéro, deltas multi-lignes, quatre plans ARGB avec alpha et trois plans sans alpha, ordre bottom-up, entrées malformées, intégration Bitmap Update et fuzz dédié.

Validation :
- go test ./pkg/rdp/... -count=1 : PASS.
- go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1 : PASS.
- make build vet test proto-lint : PASS.
- FuzzDecodeRDP6RLEPlane : 63 458 exécutions en 5 s, PASS.
- Intégration processus réels : PASS (224,177 s). Les tests PostgreSQL sont ignorés faute de TEST_DATABASE_URL. Aucun test Compose local.
- GOTOOLCHAIN=go1.27.3 make vuln : aucune vulnérabilité atteignable ; npm audit : zéro vulnérabilité dans les deux workspaces UI.
- git diff --check : PASS. Le script scripts/check-architecture-deps.sh est absent du dépôt.

Aucune interopérabilité Windows/RDS réelle ; AYCoCg/subsampling, ordres graphiques, runtime et route RDP toujours désactivés.

Références : MS-RDPEGDI §2.2.2.5.1.2, §3.1.9.2 et §3.1.9.2.3.


## ADR-0071 — incrément 31 : Fast-Path Bitmap Update

Le lecteur RDP reconnaît désormais le framing Fast-Path directement sur TLS et le distingue du TPKT slow-path sans surconsommer le flux. Les longueurs à un ou deux octets sont validées avant allocation, avec un plafond conservateur de 16 383 octets. Le TPKT garde sa borne et son réassemblage MCS existants.

Le décodeur accepte un seul événement Fast-Path Bitmap Update non fragmenté et non compressé ; le corps bitmap réutilise le même parseur de rectangles RAW/RDP6 ARGB RAW/RLE que le slow-path. Un test TLS avec serveur factice traverse le lecteur de session complet. Le fuzzer Fast-Path couvre les entrées arbitraires.

La capacité FASTPATH_OUTPUT_SUPPORTED n'est pas annoncée au serveur. La fragmentation, la compression, les paquets contenant plusieurs événements, les ordres et événements pointeur Fast-Path restent refusés/non supportés. Aucune interopérabilité Windows/RDS réelle n'est revendiquée ; runtime et route RDP restent désactivés.


## 2026-11-05 — Incrément 32 : RDP6 AYCoCg avec CLL, sans subsampling

Le décodeur RDP6 traite désormais `CLL=1..7` comme le profil AYCoCg, conserve `CLL=0` pour ARGB et refuse toujours `CS=1`. Les plans sont interprétés comme A/Y/Co/Cg (alpha facultatif), avec Co/Cg signés et restauration par le niveau CLL avant la transformation inverse vers RGB. La transformation conserve l'alpha et borne les canaux RGB à 8 bits. Les modes RAW et RLE réutilisent les mêmes contrôles de longueur et de consommation exacte.

Tests ajoutés : AYCoCg CLL=1, chroma positive et négative, clamp de sortie, plan alpha absent, RLE AYCoCg et refus du chroma subsampling. Le `bitmapCompressionFlag` reste à zéro ; aucun test Windows/RDS réel, runtime ou route RDP activée.


Validation de l'incrément 32 :
- `go test ./pkg/rdp/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `make build vet test proto-lint` : PASS sur tous les modules Go, `go vet`, tests unitaires et Buf lint.
- `FuzzDecodeRDP6BitmapWithHeader` : PASS, 65 038 exécutions en 5 s, avec seed AYCoCg.
- `GOTOOLCHAIN=go1.27.3 make vuln` : aucune vulnérabilité atteignable ; quelques avis subsistent dans des modules requis mais non appelés.
- `npm audit --audit-level=low` dans `web/admin-ui` et `web/openbastion-icons` : zéro vulnérabilité.
- `gofmt` et `git diff --check` : PASS. Aucun test Windows/RDS réel ; le `bitmapCompressionFlag` reste à zéro, runtime et route RDP restent désactivés.

## 2026-11-05 — Incrément 33 : RDP6 AYCoCg avec chroma subsampling

Le décodeur accepte désormais `CS=1` pour les profils AYCoCg (`CLL=1..7`). Les plans alpha et luma conservent la résolution bitmap ; les plans Co/Cg sont lus à `ceil(width/2) × ceil(height/2)`, en RAW ou RLE indépendant. La reconstruction réplique chaque échantillon chroma sur son bloc 2×2, en tronquant les blocs de bord pour les dimensions impaires. L'ordre bottom-up des plans est conservé jusqu'à la conversion RGBA top-down.

Le `TS_CD_HEADER.cbScanWidth` reste strictement vérifié et la largeur bitmap reste multiple de quatre, conformément à MS-RDPBCGR ; les hauteurs impaires sont prises en charge. `CS=1` avec `CLL=0` est refusé, comme tout bit réservé, plan tronqué, RLE hors dimensions, consommation inexacte ou octet résiduel ambigu. Les allocations restent bornées par les plafonds de pixels et `cbUncompressedSize`. Le `bitmapCompressionFlag` reste à zéro : le serveur n'est pas invité à émettre des profils compressés tant que les capacités RDP complètes et l'interopérabilité ne sont pas établies.

Tests : reconstruction RAW avec hauteur impaire et passage par Bitmap Update ; alpha pleine résolution ; RLE des plans Y/Co/Cg à leurs dimensions respectives ; rejet d'un plan chroma RLE tronqué et de `CS=1` en ARGB ; seeds RAW/RLE du fuzzer de conteneur.

Référence normative : [MS-RDPEGDI §3.1.9.1.3 — Chroma Subsampling and Super-Sampling](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/57507b94-41e6-41ff-a35e-c00211945ceb) et [§2.2.2.5.1 — RDP6_BITMAP_STREAM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/9b422f69-8e05-4c6d-b6fb-fa02ef75a8f2).

Validation de l'incrément 33 :
- `make build vet test proto-lint` : PASS sur tous les modules Go, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... -count=1` : PASS ; 167 résultats `--- PASS` mesurés.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `FuzzDecodeRDP6BitmapWithHeader` : PASS, 49 267 exécutions en 5 s.
- Contre-épreuves : 3 mutations tuées sur 3 (acceptation de CS avec CLL=0, index chroma horizontal sans facteur 2, décodage RLE des chromas à la résolution pleine) ; fichiers restaurés et `cmp` PASS.
- `.agents/settings/project.yaml` : parse YAML PASS ; `gofmt` et `git diff --check` : PASS.
- Aucun test Compose local, aucune interopérabilité Windows/RDS réelle ni E2E avec Video Recorder. Le `bitmapCompressionFlag` reste à zéro, le runtime et la route RDP restent désactivés.

## 2026-11-05 — Incrément 34 : premier ordre graphique RDP OpaqueRect

Le parseur slow-path `TS_UPDATE_ORDERS` prend en charge un profil primaire volontairement étroit : `TS_ENC_OPAQUERECT_ORDER` (0x0A). Il exige `TS_STANDARD`, un changement explicite vers OpaqueRect lorsque le type courant ne l'est pas, un unique octet `fieldFlags=0x7f` (les sept champs explicites), des coordonnées absolues signées 16 bits, une largeur et une hauteur strictement positives, et un rectangle entièrement inclus dans le bureau. Le triplet RGB est converti en pixels RGBA opaques et renvoyé sous forme de `RDPBitmapRectangle`, directement consommable par le framebuffer existant.

Le type d'ordre primaire courant est conservé entre les mises à jour TLS successives et n'est validé/commis qu'après le décodage complet de la mise à jour. Les comptes d'ordres sont bornés à 1 024 ; l'aire cumulée des rectangles ne dépasse pas `maxRDPDesktopArea`. Les PDU secondaires/alternatifs, autres types d'ordre, coordonnées delta, clipping bounds, champs omis, flux tronqués, comptes nuls/excessifs et octets résiduels sont refusés. Une mise à jour malformée ne retourne aucun rectangle et ne modifie pas l'état d'ordre. Le lecteur de session refuse également tout `TS_UPDATE_ORDERS` tant que le slot de capacité partagé n'a pas été négocié ; ce garde reste fermé dans le profil actuel.

**Ce que cela ne fait PAS :** aucun `PatBlt`, aucun autre ordre primaire, secondaire ou alternatif, aucun bounds/delta, aucun `TS_FP_UPDATE_ORDERS`, aucun état de champ omis. L'index de négociation `TS_NEG_PATBLT_INDEX` (0x01) représente à la fois PatBlt et OpaqueRect ; il reste donc entièrement à zéro dans Confirm Active. Ce parseur ne rend pas les ordres disponibles aux serveurs et ne justifie aucune activation du codec/runtime RDP. Les événements Fast-Path autres que Bitmap Update restent hors périmètre.

Tests : décodage de plusieurs OpaqueRect dans une mise à jour ; persistance du type entre deux PDU TLS ; rendu PNG via `RDPFramebuffer` ; rejet sur TLS des ordres non négociés ; rejets des drapeaux, ordres, champs, dimensions et données invalides ; fuzz du parseur ; état inchangé après erreur.

Références normatives : [MS-RDPBCGR §2.2.9.1.1.3.1 — Slow-Path Graphics Update](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd3c4df4-87b9-43dd-88cb-ce5b24698e19), [MS-RDPEGDI §2.2.2.1 — Orders Update](https://learn.microsoft.com/mt-mt/openspecs/windows_protocols/ms-rdpegdi/ef7c27f5-0977-46fe-a50e-f9a51d6ab90b), [MS-RDPEGDI §2.2.2.2.1.1.2 — Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272) et [MS-RDPEGDI — PatBlt et slot de négociation partagé](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/bd4bf5e7-b988-45f9-8201-3b22cc9aeeb8).

Validation de l'incrément 34 :
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 174 résultats `--- PASS` mesurés.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `FuzzParseRDPOrdersUpdate` : PASS, 48 233 exécutions en 5 s.
- Contre-épreuves : 6 mutations compilantes tuées sur 6 (bornes bureau, drapeaux de contrôle, masque des champs, type initial, persistance du type entre PDU, garde de négociation) ; restauration et `cmp` PASS pour chaque fichier.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; le slot de négociation reste désactivé et le runtime/route RDP restent désactivés.


## 2026-11-05 — ADR-0071, incrément 35 : PatBlt slow-path

Le décodeur des ordres slow-path prend en charge `PatBlt` uniquement pour le ROP `PATCOPY` (`0xF0`) et une brosse non mise en cache `BS_SOLID` (`0x00`). Le masque de champs est exactement `0x027f` (quatre coordonnées absolues, ROP, `BackColor`, `ForeColor`, `BrushStyle`) ; la couleur du rectangle provient de `ForeColor`. Le type primaire initial implicite PatBlt et les changements de type restent conservés entre PDU TLS. Le rendu est réutilisé par `RDPFramebuffer`.

Les ROP autres que PATCOPY, brushes null/hachées/pattern/cachées, coordonnées delta, bounds, champs omis, brush hatch/extra, autres ordres primaires/secondaires/alternatifs et Fast-Path Orders restent refusés. Le slot de négociation PatBlt/OpaqueRect reste désactivé : les profils stricts ne représentent pas encore le support complet que cette capacité annoncerait. Runtime et route RDP restent désactivés ; aucune interopérabilité Windows/RDS réelle n'est revendiquée.

Références : [MS-RDPEGDI PatBlt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/bd4bf5e7-b988-45f9-8201-3b22cc9aeeb8), [Coord Field](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/870b982c-9abe-40cb-99d0-2c3f0cc5fb74), [Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272), [Order Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9f409c29-480c-4751-9665-510b8ffff294).

Validation de l’incrément 35 :
- Test rouge avant implémentation : `TestParseRDPOrdersUpdateDecodesSolidPatBlt` échoue sur le commit précédent (`ErrMCSConnection`), puis passe après ajout du décodeur.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 178 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 49 161 exécutions en 5 s.
- Contre-épreuves : 5 mutations compilantes tuées sur 5 (ROP, style de brosse, masque de champs, bornes du rectangle, garde de négociation) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; le slot de négociation reste désactivé et le runtime/route RDP restent désactivés.


## 2026-11-05 — ADR-0071, incrément 36 : DstBlt slow-path

Ajout du profil DstBlt strict : `orderType=0x00`, masque de champs `0x1f`, quatre coordonnées absolues signées 16 bits et ROP explicite. Seuls BLACKNESS (`0x00`) et WHITENESS (`0xff`) sont convertis en rectangles RGBA opaques. Les ROP destination-dépendants restent refusés à ce stade.

Le type initial reste PatBlt, DstBlt doit être sélectionné explicitement par TS_TYPE_CHANGE. La session conserve les familles d'ordres rencontrées et refuse le flux si `dstBltEnabled` (index 0) ou `patBltOpaqueRectEnabled` (index partagé 1) n'est pas vrai, même si les ordres primaires sont globalement activés. Confirm Active ne déclare toujours aucun ordre ; DstBlt index 0 et PatBlt/OpaqueRect index 1 restent désactivés. Le runtime/route RDP restent désactivés.

Références : [MS-RDPEGDI DstBlt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/87ea30df-59d6-438e-a735-83f0225fbf91), [Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272), [ROP3 Operation Index](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a9a85075-e796-45eb-b84a-f399324a1109).

Validation de l’incrément 36 :
- Test rouge avant implémentation : le décodeur refuse initialement DstBlt ; BLACKNESS/WHITENESS passent après ajout du profil strict.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 181 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 50 276 exécutions en 5 s.
- Contre-épreuves : 7 mutations compilantes tuées sur 7 (ROP, masque, bornes, négociation DstBlt, négociation PatBlt/OpaqueRect, garde globale, type initial) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; les capacités DstBlt et PatBlt/OpaqueRect restent non annoncées, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 37 : DstBlt DSTINVERT stateful

DSTINVERT (`0x55`) est désormais accepté comme opération destination-only typée sans buffer RGBA de remplacement. `RDPFramebuffer.Apply` inverse RGB dans la zone existante et préserve l'alpha ; les pixels précédents sont sauvegardés pour rollback en cas d'échec d'encodage PNG. Les ROP source/pattern dépendants et les autres ROP non implémentés restent refusés. Le garde de négociation DstBlt index 0 reste obligatoire ; Confirm Active, runtime et route RDP restent désactivés.

Test de bout en bout du framebuffer : PATCOPY peint une zone, DSTINVERT inverse les pixels et le PNG confirme les valeurs RGB inversées et alpha 255. Le fuzzer reçoit aussi un seed DSTINVERT.

Références : [MS-RDPEGDI DstBlt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/87ea30df-59d6-438e-a735-83f0225fbf91), [ROP3 Operation Index](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a9a85075-e796-45eb-b84a-f399324a1109).

Validation de l’incrément 37 :
- Test rouge avant implémentation : le parseur rejette DSTINVERT et le framebuffer refuse l'opération sans pixels de remplacement ; les tests passent après ajout du chemin stateful.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 186 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 48 183 exécutions en 5 s.
- Contre-épreuves : 7 mutations compilantes tuées sur 7 (mode DSTINVERT, canaux rouge/bleu, payload de remplacement, opération inconnue, rollback PNG, limite cumulative de pixels) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; aucune capacité graphique n'est annoncée, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 38 : PatBlt PATINVERT

PatBlt accepte désormais `PATINVERT` (`0x5a`) avec `BS_SOLID`. Le motif `ForeColor` est transmis sous forme de pixels RGBA bornés, puis le framebuffer applique un XOR sur les canaux RGB en préservant alpha. Le payload motif doit correspondre exactement à la surface du rectangle. Les autres ROP et brushes restent refusés ; le slot PatBlt/OpaqueRect reste non annoncé et la route/runtime RDP reste désactivée.

Référence : [MS-RDPEGDI ROP3 Operation Index — PATINVERT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a9a85075-e796-45eb-b84a-f399324a1109).

Validation de l'incrément 38 :
- Test rouge avant implémentation : PATINVERT est rejeté par le parseur ; le test framebuffer échoue avant le chemin XOR.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 189 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 52 474 exécutions en 5 s.
- Contre-épreuves : 8 mutations compilantes tuées sur 8 (mode PATINVERT, XOR rouge/vert/bleu, alpha, longueur exacte du motif, BS_SOLID, ROP non supporté) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; le slot PatBlt/OpaqueRect reste non annoncé, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 39 : PatBlt PATAND/PATOR

PatBlt accepte désormais `PATAND` (`0xA0`, D AND P) et `PATOR` (`0xFA`, D OR P) avec `BS_SOLID`. Le motif `ForeColor` est borné et validé avant mutation ; le framebuffer applique AND/OR sur RGB et préserve alpha. Les autres ROP, brushes et profils restent refusés. Le slot PatBlt/OpaqueRect n'est toujours pas annoncé et le runtime/route RDP restent désactivés.

Référence : [MS-RDPEGDI ROP3 Operation Index](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a9a85075-e796-45eb-b84a-f399324a1109).

Validation de l'incrément 39 :
- Test rouge avant implémentation : les tests de décodage et de rendu PATAND/PATOR échouent sur le commit précédent (`ErrMCSConnection`), puis passent après ajout des deux ROP.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 193 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 51 468 exécutions en 5 s.
- Contre-épreuves : 8 mutations compilantes tuées sur 8 (mapping PATAND/PATOR, opérateurs AND/OR, préservation alpha, longueur exacte du motif, BS_SOLID, refus des ROP non supportés) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; le slot PatBlt/OpaqueRect reste non annoncé, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 40 : PatBlt NOTPATCOPY

PatBlt accepte désormais `NOTPATCOPY` (`0x0F`, `Pn`) avec `BS_SOLID`. Le parseur inverse les trois canaux de `ForeColor`, puis réutilise le remplacement RGBA opaque ; le résultat ne dépend donc pas des pixels précédents. Les autres ROP et brushes restent refusés ; le slot PatBlt/OpaqueRect reste non annoncé et runtime/route RDP désactivés.

Référence : [MS-RDPEGDI ROP3 Operation Index](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a9a85075-e796-45eb-b84a-f399324a1109).

Validation de l'incrément 40 :
- Test rouge avant implémentation : les tests de décodage et de rendu NOTPATCOPY échouent sur le commit précédent (`ErrMCSConnection`), puis passent après ajout du ROP.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 195 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 50 994 exécutions en 5 s.
- Contre-épreuves : 8 mutations compilantes tuées sur 8 (remplacement indépendant de la destination, inversion des trois canaux, index ROP, BS_SOLID, refus des ROP non supportés) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; le slot PatBlt/OpaqueRect reste non annoncé, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 41 : ScrBlt SRCCOPY

Le sous-ensemble ScrBlt accepte `SRCCOPY` (`0xCC`) avec sept champs explicites. Source et destination doivent être entièrement dans le bureau ; les autres ROP, coordonnées delta, clipping et champs omis sont refusés. Le framebuffer copie une photographie de la source avant l'écriture pour préserver le comportement des rectangles chevauchants, avec rollback de destination en cas d'échec PNG. Le lecteur de session exige l'index de négociation ScrBlt 2 ; Confirm Active ne l'annonce toujours pas, et runtime/route RDP restent désactivés.

Références : [MS-RDPEGDI ScrBlt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/a4e322b0-cd64-4dfc-8e1a-f24dc0edc99d) et [Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272).

Validation de l'incrément 41 :
- Test rouge avant implémentation : le parseur rejette ScrBlt ; le test passe après ajout du profil SRCCOPY.
- `GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, compilation, `go vet`, tests unitaires et Buf lint.
- `go test ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 199 résultats `--- PASS` mesurés.
- `FuzzParseRDPOrdersUpdate` : PASS, 50 319 exécutions en 5 s.
- Contre-épreuves : 10 mutations compilantes tuées sur 10 (ROP SRCCOPY, limites source/destination, field mask, origine de copie, payload, état et garde de négociation) ; tous les fichiers restaurés octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; l'index ScrBlt 2 reste non annoncé, runtime/route RDP désactivés.

## 2026-11-05 — ADR-0071, incrément 42 : MultiDstBlt

`pkg/rdp/mcs_bitmap.go` décode maintenant le profil primaire MultiDstBlt destination-only : `fieldFlags=0x7F`, coordonnées d'ordre explicites, 1 à 45 rectangles dans un `VARIABLE2_FIELD` de longueur bornée et ROP limité à BLACKNESS, WHITENESS ou DSTINVERT. Seuls les rectangles de la liste delta sont rendus. Les deltas `left`/`top` s'accumulent ; `width`/`height` sont des dimensions absolues, répétées lorsque leur zero-bit est positionné. Les entiers signés empaquetés 7/15 bits sont contrôlés, et chaque rectangle passe par les bornes de bureau et les budgets communs de framebuffer.

Le slot de négociation 15 est indépendant et contrôlé par `ReadBitmapUpdate`, mais reste désactivé en production : Confirm Active n'annonce aucun ordre graphique. Le runtime et la route RDP restent désactivés. Aucun test Compose local ni interopérabilité Windows/RDS réelle n'est revendiqué.

Validation de l'incrément 42 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS (génération Buf, build, vet de tous les modules, tests unitaires complets et `buf lint`).
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 206 tests `--- PASS`.
- `FuzzParseRDPOrdersUpdate` : PASS, 103 750 exécutions en 5 s (4 workers).
- Contre-épreuves : 12 mutations compilantes tuées sur 12 (accumulation width/height, rectangle de tête, signes 7/15 bits, whitelist ROP, dimensions nulles, payload résiduel, zeroBits inutilisés, limite 45 rectangles, garde de négociation et field mask) ; sources restaurées octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; l'index MultiDstBlt 15 reste non annoncé, runtime/route RDP désactivés.


## ADR-0071, incrément 43 — MultiOpaqueRect

`MultiOpaqueRect` (`orderType=0x12`) accepte un profil strict à neuf champs : coordonnées absolues, RGB opaque et 1 à 45 rectangles delta bornés. Seule la liste delta est peinte ; le rectangle de tête n'est pas rendu. L'index de négociation 18 est vérifié indépendamment et n'est pas annoncé. Les champs omis, les deltas de coordonnées, les listes invalides et les rectangles hors bureau restent refusés. Runtime/route RDP désactivés ; aucune interopérabilité Windows/RDS réelle revendiquée.

Validation de l’incrément 43 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS (génération Buf, build, vet de tous les modules, tests unitaires complets et `buf lint`).
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 210 tests `--- PASS`.
- `FuzzParseRDPOrdersUpdate` : PASS, 76 670 exécutions en 5 s (4 workers).
- Contre-épreuves : 7 mutations compilantes tuées sur 7 (mapping RGB, liste delta seule, masque neuf champs, état de l'ordre, garde index 18, limite 46 rectangles et coordonnées négatives) ; source restaurée octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; l'index MultiOpaqueRect 18 reste non annoncé, runtime/route RDP désactivés.


## ADR-0071, incrément 44 — MultiPatBlt

`MultiPatBlt` (`orderType=0x10`) accepte un profil strict à quatorze champs explicites. Brosse `BS_SOLID` uniquement, origine nulle, hatch et sept octets BrushExtra nuls ; ROP restreint à PATCOPY/PATINVERT/PATAND/PATOR/NOTPATCOPY. Les rectangles rendus proviennent exclusivement de la liste delta bornée (1 à 45). L'index de négociation 16 est vérifié indépendamment et n'est pas annoncé. Runtime/route RDP désactivés ; aucune interopérabilité Windows/RDS réelle revendiquée.

Validation de l’incrément 44 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS (génération Buf, build, vet de tous les modules, tests unitaires complets et `buf lint`).
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 214 tests `--- PASS`.
- `FuzzParseRDPOrdersUpdate` : PASS, 94 425 exécutions en 5 s (4 workers).
- Contre-épreuves : 10 mutations compilantes tuées sur 10 (mapping ForeColor, whitelist ROP, field mask, origine/style/BrushExtra, rectangles delta, état, garde index 16 et limite 46 rectangles) ; source restaurée octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; l'index MultiPatBlt 16 reste non annoncé, runtime/route RDP désactivés.


## ADR-0071, incrément 45 — MultiScrBlt

`MultiScrBlt` (`orderType=0x11`) accepte les neuf champs explicites et le seul ROP `SRCCOPY`. Les rectangles delta déterminent les destinations ; les origines sources sont calculées relativement à l'ancre de l'ordre. Les bornes source et destination sont strictes, sans clipping. L'index de négociation 17 est vérifié indépendamment et n'est pas annoncé. Runtime/route RDP désactivés ; aucune interopérabilité Windows/RDS réelle revendiquée.

Validation de l’incrément 45 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS (génération Buf, build, vet de tous les modules, tests unitaires complets et `buf lint`).
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 217 tests `--- PASS`.
- `FuzzParseRDPOrdersUpdate` : PASS, 116 071 exécutions en 5 s (4 workers).
- Contre-épreuves : 9 mutations compilantes tuées sur 9 (field mask, SRCCOPY, calcul d'offset source, bornes source/destination, liste delta seule, état, garde index 17 et limite 46 rectangles) ; source restaurée octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; l'index MultiScrBlt 17 reste non annoncé, runtime/route RDP désactivés.


## ADR-0071, incrément 46 — LineTo

`LineTo` (`orderType=0x09`) accepte dix champs explicites, `BackMode=TRANSPARENT`, `R2_COPYPEN`, plume solide d'un pixel et coordonnées absolues. Le tracé Bresenham GDI (endpoint exclu) est borné au bureau et à 32 768 points. L'index de négociation 8 est vérifié indépendamment et n'est pas annoncé. Runtime/route RDP désactivés ; aucune interopérabilité Windows/RDS réelle revendiquée.

Validation de l’incrément 46 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS (génération Buf, build, vet de tous les modules, tests unitaires complets et `buf lint`).
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 221 tests principaux `--- PASS` (669 succès en comptant les sous-tests et seeds).
- `FuzzParseRDPOrdersUpdate` : PASS, 112 213 exécutions en 5 s (4 workers).
- Contre-épreuves : 11 mutations compilantes tuées sur 11 (masque, BackMode, ROP2, style/largeur de plume, BackColor, bornes, Bresenham, état, garde index 8 et rendu framebuffer) ; sources restaurées octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; l'index LineTo 8 reste non annoncé, runtime/route RDP désactivés.


## ADR-0071, incrément 47 — Polyline

Polyline (orderType=0x16) accepte sept champs explicites, R2_COPYPEN et une entrée de cache de brosse nulle. DELTA_PTS_FIELD décode deux deltas signés par point depuis l'ancre précédente. Profil borné à 34 points et 148 octets au total pour CodedDeltaList (octet cbData inclus, 147 octets de données maximum), rasterisation Bresenham GDI avec endpoint exclu. L'index de négociation 22 est vérifié indépendamment et n'est pas annoncé. Runtime/route RDP désactivés ; aucune interopérabilité Windows/RDS réelle revendiquée.

Validation de l'incrément 47 :
- Test rouge sur `a257183` : le profil Polyline est refusé (`ErrMCSConnection`), puis accepté après implémentation.
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 226 tests principaux `--- PASS`.
- `FuzzParseRDPOrdersUpdate` : PASS, 60 208 exécutions en 5 s (4 workers).
- Contre-épreuves : 7 mutations compilantes tuées sur 7 (bits de zéro, plafond de points, ROP2, cache, field mask, négociation et couleur de plume).
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; index 22 non annoncé, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 48 : PolygonSC

Le parseur slow-path accepte PolygonSC (`orderType=0x14`) avec les sept champs explicites, coordonnées absolues signées 16 bits, `R2_COPYPEN`, `FillMode=ALTERNATE`, BrushColor RGB et `DELTA_PTS_FIELD`. Le profil local borne à 34 deltas/147 octets de données (148 avec `cbData`), sans clipping. Le rasteriseur pair/impair convertit les intersections aux centres des pixels en spans horizontaux ; le framebuffer garde l'ordre des opérations et restaure les spans en cas d'échec PNG. `cbData` délimite exactement la liste de deltas, y compris lorsque plusieurs ordres primaires partagent le même PDU ; le découpage Polyline est corrigé de la même façon. L'index de négociation 20 est indépendant et non annoncé ; runtime/route RDP désactivés.

Référence normative : [MS-RDPEGDI §2.2.2.2.1.1.2.16 — PolygonSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/22e1117f-d40d-41df-9709-59389ac1f8dc), [Delta-Encoded Points](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/6c7b2a52-103c-4a7d-a2a9-997416d4a475).

Validation de l'incrément 48 :
- Test rouge sur `8c9efa7` : le profil PolygonSC est refusé (`ErrMCSConnection`) avant implémentation, puis accepté après.
- `make build vet test proto-lint` : PASS ; `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- 237 tests RDP principaux `--- PASS` ; fuzz `FuzzParseRDPOrdersUpdate` : 209 241 exécutions en 5 s (4 workers).
- Contre-épreuves : 12 mutations compilantes tuées sur 12, incluant FillMode, ROP2, points, masque, zero-bits, négociation, couleur, arrondi et frontières/slicing `cbData` pour Polyline et PolygonSC.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose local ni interopérabilité Windows/RDS réelle ; index 20 non annoncé, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 49 : EllipseSC

Le parseur slow-path accepte EllipseSC (`orderType=0x19`) avec les sept champs explicites : coordonnées absolues signées 16 bits, rectangle inclusif, `R2_COPYPEN`, `FillMode=ALTERNATE` et couleur RGB. Le profil rejette NOFILLL/WINDING, les coordonnées négatives/inversées et les rectangles hors bureau. Le rasteriseur entier produit des spans aux centres des pixels ; le framebuffer applique les spans dans l’ordre et restaure les pixels si le PNG dépasse sa limite. La parité pixel-à-pixel avec GDI reste à vérifier par interopérabilité Windows/RDS. L’index de négociation 25 est indépendant et non annoncé ; runtime/route RDP désactivés.

Référence normative : [MS-RDPEGDI §2.2.2.2.1.1.2.19 — EllipseSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/5146fab3-c43f-44d7-b541-04666a80e33b), [Coord Field](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/870b982c-9abe-40cb-99d0-2c3f0cc5fb74) et [Fill Mode](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/06dc7074-71cd-41cf-9028-964877875dfc).

Validation de l'incrément 49 :
- Test rouge sur `f8a073c` : EllipseSC est refusé (`ErrMCSConnection`) avant implémentation, puis accepté après.
- `make build vet test proto-lint` : PASS ; `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- 246 tests RDP principaux `--- PASS` ; fuzz `FuzzParseRDPOrdersUpdate` : 179 553 exécutions en 5 s (4 workers).
- Contre-épreuves : 12 mutations compilantes tuées sur 12, incluant ROP2, FillMode, masque, bornes inclusives, centre/racine entière, négociation, couleur, état, consommation des champs et rollback PNG.
- `gofmt` et `git diff --check` : PASS. Pas de test Compose local ni d'interopérabilité Windows/RDS ; parité GDI pixel-à-pixel non vérifiée. Index 25 non annoncé, runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 50 : R2_NOT

PolygonSC et EllipseSC acceptent `R2_NOT` (`0x06`, `Dn`) en plus de `R2_COPYPEN` (`0x0d`). Le framebuffer inverse les trois canaux RGB de destination et conserve l’alpha opaque ; la couleur de brosse reste exigée dans le flux mais ignorée pour `R2_NOT`. Les autres ROP2 sont rejetés. Index 20/25 non annoncés, runtime/route RDP désactivés.

Référence : [MS-RDPEGDI — ROP2_OPERATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/34e554e4-2e7c-4f1f-a8a6-e7b319bf6fe1).

Validation de l'incrément 50 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, génération Buf, compilation, `go vet`, tests unitaires complets et `buf lint`.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test -v ./pkg/rdp/... -count=1` : 250 tests principaux `--- PASS`.
- `FuzzParseRDPOrdersUpdate` : PASS, 102 090 exécutions en 5 s (4 workers).
- Contre-épreuves : 2 mutations compilantes tuées sur 2 : suppression de l'inversion RGB (les deux rendus échouent) et rejet de `R2_NOT` dans les parseurs PolygonSC/EllipseSC (les deux tests de décodage échouent) ; sources restaurées et comparées octet pour octet.
- `gofmt` et `git diff --check` : PASS. Le contrôle d'architecture historique `scripts/check-architecture-deps.sh` n'existe pas dans ce dépôt. Aucun test Compose ni interopérabilité Windows/RDS réelle ; index 20/25 non annoncés et runtime/route RDP désactivés.


## 2026-11-05 — ADR-0071, incrément 51 : R2_XORPEN

PolygonSC et EllipseSC acceptent `R2_XORPEN` (`0x07`, `DPx`) en plus de `R2_COPYPEN` et `R2_NOT`. Le framebuffer applique le XOR bit à bit entre RGB de destination et couleur de plume/brosse, en conservant l’alpha opaque. Les autres ROP2 restent refusés. Les index 20/25 restent indépendants et non annoncés ; runtime/route RDP désactivés.

Référence normative : [MS-RDPEGDI — ROP2_OPERATION](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/34e554e4-2e7c-4f1f-a8a6-e7b319bf6fe1).

Validation de l'incrément 51 :
- `PATH=/tmp/openbastion-tools:$PATH GOTOOLCHAIN=go1.27.3 GOWORK=$PWD/go.work make build vet test proto-lint` : PASS sur tous les modules Go, génération Buf, compilation, `go vet`, tests unitaires complets et `buf lint`.
- `go test -race ./pkg/rdp/... ./services/proxy/rdp-vnc-proxy/... -count=1` : PASS.
- `go test ./pkg/rdp -run '^$' -fuzz '^FuzzParseRDPOrdersUpdate$' -fuzztime=5s -parallel=4` : PASS, 69 393 exécutions.
- `go test -v ./pkg/rdp/... -count=1` : 252 tests principaux `--- PASS`.
- Contre-épreuves : 2 mutations compilantes tuées sur 2 (XOR remplacé par OR dans le framebuffer ; `R2_XORPEN` retiré des parseurs PolygonSC/EllipseSC), les deux formes échouent pour chaque mutation ; sources restaurées octet pour octet.
- `gofmt` et `git diff --check` : PASS. Aucun test Compose ni interopérabilité Windows/RDS réelle ; index 20/25 non annoncés et runtime/route RDP désactivés.
