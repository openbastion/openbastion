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

`privileged_accounts` (doc 06 §3) ne porte pas de champ `username` distinct de `name`/`target_host` — or authentifier une session SSH vers la cible exige un nom d'utilisateur. `EstablishSessionRequest` (doc 07 §4) n'a pas non plus ce champ. Contournement documenté dans le code (`ssh-proxy/internal/interfaces/http.go`, `EstablishSessionRequest.TargetUser`) : threading explicite du champ jusqu'à ce que le modèle de données et le contrat proto soient mis à jour formellement — pas une omission silencieuse.

## API Gateway et Authentication Service

**Nouveau service : `services/access/authentication`.** Mots de passe hachés en Argon2id réel (`golang.org/x/crypto/argon2`, même contournement replace que pour `x/crypto/ssh`), format PHC auto-porteur (salt + paramètres + hash dans une seule chaîne, pas de colonne salt séparée). Jetons signés HMAC-SHA256 — **volontairement pas un vrai JWT** : aucune bibliothèque JWT externe n'a été ajoutée, cohérent avec le parti pris de ce projet de préférer la bibliothèque standard pour le code sensible (AES-GCM dans le Vault, SHA-256 pour le chaînage d'audit). La forme encodée (payload base64 + signature base64, séparés par un point) est volontairement proche d'un JWT pour que la bascule vers une vraie bibliothèque JWT, une fois `google.golang.org` joignable, reste un changement contenu à `infrastructure/token.go` — `application.TokenIssuer` n'expose aucun détail d'encodage dans sa signature.

**Écart documenté plutôt que masqué** : `doc06` modélise `user_roles` comme table de jointure séparée contre une table `roles` autonome. Cet incrément simplifie en portant les noms de rôles directement sur `User` — `Authorization` possède déjà ce qu'un rôle peut *faire* (les politiques) ; `Authentication` possède quels rôles un utilisateur *a*. Séparer l'assignation de rôle dans sa propre table est un raffinement v1.0 direct, qui ne changerait aucun appelant de ce package.

**Nouveau service : `services/access/api-gateway`.** Point d'entrée public unique (doc 00 §4.1) : `POST /auth/login` (public, limité en débit spécifiquement — 5/minute par IP, plus strict que le reste), puis tout le reste sous `Authorization: Bearer <token>`, vérifié à chaque requête auprès du vrai `Authentication Service`. **L'injection de contexte d'identité est la pièce la plus importante** : sur `POST /sessions`, la Gateway écrase systématiquement `requestedBy` et `actorRoles` du corps de requête avec l'identité qu'elle vient de vérifier — quoi que le client ait pu revendiquer. Testé explicitement, à deux niveaux : au niveau HTTP unitaire (`TestHandleSessionsCollection_InjectsVerifiedIdentityOverridingClientClaims`, avec un faux Session Broker qui capture ce qu'il reçoit réellement) et en inter-processus réel (`gateway_flow_test.go`, où le client revendique explicitly `attacker-controlled-id` et le rôle `admin`, et où seule l'identité vérifiée par le vrai Authentication Service traverse jusqu'au vrai Session Broker).

**Portée volontairement limitée de cet incrément** : la Gateway route `POST /auth/login` et le cycle de vie complet de `/sessions/*` — le parcours MVP central. Les surfaces d'administration (`/vault/accounts/*`, `/policies`) restent accessibles directement sur leurs services respectifs, pas encore routées à travers la Gateway — un ajout direct suivant exactement le même patron (`forwardJSON`/passthrough) une fois nécessaire. Autre écart existant, non introduit par cet incrément mais rendu visible par lui : `Password Vault` n'impose aucune vérification RBAC sur ses propres opérations d'écriture (`onboard-account`, `rotate`) — seule la création de session le fait, via `Authorization.CheckAccess`. Une gestion de compte non gatée par rôle est un choix à corriger avant tout déploiement au-delà d'un pilote.

## Routage des surfaces d'administration à travers la Gateway

**Deux vrais manques comblés en routant, pas seulement un ajout de tuyauterie.**

1. **Rotation vraiment automatique.** `application.VaultService.Rotate` exigeait jusqu'ici un `newSecret` fourni explicitement — ce qui contredit l'exigence du doc 00 ("Rotation automatique") : un opérateur n'a jamais à inventer ni connaître la nouvelle valeur. `Rotate` génère désormais 32 octets aléatoires (`crypto/rand`) si `newSecret` est vide, testé explicitement (`TestRotate_AutoGeneratesSecretWhenNoneProvided`, `TestRotate_AutoGeneratesDifferentSecretsEachTime`) et vérifié en inter-processus réel (`admin_routes_test.go` : rotation via la Gateway, puis récupération directe du credential pour confirmer qu'il a réellement changé).
2. **Traduction REST publique ↔ contrat interne.** `POST /vault/accounts/{id}/rotate` (doc 05, id dans l'URL, pas de corps) ne correspond pas à `POST /vault/v1/rotate` de Password Vault (accountId dans le corps JSON, antérieur à ce travail de routage). La Gateway traduit — extrait l'id du chemin, construit le corps, ne transmet jamais de secret côté client — plutôt que de changer le contrat interne déjà testé de Password Vault pour coller à une forme REST qui n'avait jamais été exercée de bout en bout avant maintenant.

**Même principe d'injection d'identité qu'ailleurs, appliqué à `POST /policies`** : `createdBy` est systématiquement écrasé par le nom d'utilisateur que la Gateway vient de vérifier, jamais celui que le client revendique — testé au niveau HTTP unitaire (faux backend qui capture) et en inter-processus réel (la politique créée via la Gateway avec un `createdBy` falsifié est ensuite vérifiée comme *effectivement fonctionnelle* via un vrai `CheckAccess`).

**Ce que cet incrément ne fait toujours pas** : aucune de ces routes admin n'exige de rôle particulier (ex. `admin`) — un jeton valide suffit, quel que soit le rôle qu'il porte. C'est un vrai gap de sécurité pour un déploiement au-delà d'un pilote, distinct de (mais lié à) l'absence de vérification RBAC sur les écritures du Password Vault lui-même, déjà signalée. Les deux sont liés : imposer un rôle au niveau Gateway sans que Password Vault vérifie quoi que ce soit en interne resterait un contrôle en un seul point, contournable par quiconque atteint directement le port de Password Vault.

## Ce que le codec SSH couvre, et ce qu'il ne couvre pas encore

**Couvert et testé** (`services/proxy/ssh-proxy/internal/sshcodec/codec_relay_test.go`) : un vrai `ssh.Client` (l'opérateur) se connecte à travers un vrai serveur SSH (le proxy), qui authentifie la connexion via un ticket à usage unique, récupère le credential auprès du Vault, s'authentifie vers une vraie fausse cible SSH avec ce credential exact, et relaie un shell interactif dans les deux sens — avec capture de commande (`RecordingTap`) et purge mémoire du credential en fin de session.

**Câblage Session Broker ↔ ssh-proxy — fait.** `Session Broker` expose désormais le vrai `POST /sessions/{id}/connect` public (doc 05 §2) : il résout les métadonnées du compte via `GET /vault/v1/accounts/{id}` (nouvellement implémenté, métadonnées seules), obtient un scope Vault, puis appelle le vrai `ProxyControl.EstablishSession` de `ssh-proxy` — et ne renvoie que le `connection_ticket` du proxy, jamais le `scope_token` Vault (`session-broker/internal/application`, `Connect`, testé explicitement : `TestConnect_NeverReturnsTheScopeTokenItself`). `test/integration/broker_flow_test.go` prouve l'ensemble sur **cinq** processus réels séparés, jusqu'à une vraie connexion SSH d'opérateur simulée à travers la vraie API publique du Broker.

**Écart de modèle de données comblé en cours de route** : `PrivilegedAccount` a maintenant un champ `Username` (`services/vault/password-vault/internal/domain/account.go`) — la solution définitive à l'écart signalé dans l'incrément précédent, pas seulement un contournement supplémentaire.

**Convention introduite** : `target_host` inclut désormais le port (`10.0.4.12:22`, pas seulement `10.0.4.12`) — nécessaire pour que `ssh-proxy` puisse `net.Dial` directement. À formaliser dans `OpenBastion_06_Modele_Donnees.md` lors d'une prochaine révision.

**Non couvert par cet incrément** :
- Les sous-systèmes `exec` et SFTP/SCP (seul `shell` interactif est géré).
- Une clé hôte persistée pour `ssh-proxy` (générée à chaque démarrage de processus actuellement).
- Un registre de proxies par `proxyServiceID` — `Session Broker` n'a qu'un seul `ProxyClient` configuré (`SSH_PROXY_URL`), suffisant tant que MVP ne couvre qu'un seul protocole (doc 04 §2).

## Conséquences pour ce qui est implémenté ici

| Ce que dit la doc 07 | Ce qui est réellement codé dans ce sandbox | Pourquoi c'est un remplacement sûr |
|---|---|---|
| Transport interne en gRPC/Protobuf | HTTP/JSON, avec exactement les mêmes noms de champs que les messages `.proto` (`scope_token`, `calling_proxy_id`, `credential_material`, `actor_roles`, `decision_reason`, …) | `internal/interfaces/http.go` de chaque service est la seule couche concernée ; `internal/application` et `internal/domain` n'ont aucune dépendance à un transport |
| `POST /sessions/{id}/connect` retournant un `ConnectionTicket` (doc 05 §2) | `Session Broker` expose `POST /internal/v1/authorize-connection`, qui retourne le `scope_token` Vault directement — volontairement sous un chemin distinct, jamais exposé publiquement | Le vrai `connection_ticket` client-facing doit être émis par le proxy lui-même (`ProxyControl.EstablishSession`, doc 07 §4) — maintenant implémenté dans `services/proxy/ssh-proxy`, mais pas encore appelé par le Session Broker (qui appelle toujours son propre endpoint interne). Le câblage Broker → Proxy est le prochain incrément |

Rien dans `internal/domain` ou `internal/application` ne mentionne HTTP, JSON, ni aucun détail de transport — c'est exactement la séparation Clean Architecture posée dans `OpenBastion_02_Arborescence_Depot.md` §3 qui rend ce remplacement sans douleur.

## Ce qui reste vrai et testé malgré la contrainte

- La purge mémoire du credential, octet par octet (`pkg/proxycore`).
- Le chiffrement enveloppe AES-256-GCM et le versionnement des secrets (`password-vault`).
- Le scope à usage unique et son rejet strict par identité de proxy (`password-vault`, prouvé aussi en inter-processus par `test/integration`).
- Le chaînage de hash de l'audit et la détection de falsification, y compris quand l'attaquant recalcule le hash de l'événement modifié (`audit-service`).
- Le RBAC deny-by-default, avec un `deny` explicite qui l'emporte toujours sur un `allow`, quel que soit l'ordre de création des politiques (`authorization`).
- L'audit fail-closed : un échec d'émission d'événement d'audit empêche l'octroi de la session plutôt que de l'accorder silencieusement sans trace (`session-broker`, cohérent avec le Guide HA §1).
- Le fait que `VaultAuthorizer` (le port utilisé par le Session Broker) n'a structurellement aucune méthode `FetchCredential` — l'invariant ADR-0003 est encodé au niveau du système de types Go, pas seulement documenté.
- Un vrai protocole SSH de bout en bout — vrai client, vrai proxy, vraie cible — avec injection du credential exact récupéré au Vault, ticket de connexion à usage unique rejeté au niveau du handshake SSH lui-même s'il est invalide ou réutilisé, et capture de commande (`ssh-proxy`).
- Le flux complet AuthorizeScope → FetchCredential → purge → audit, entre deux vrais binaires séparés communiquant en HTTP réel (`test/integration/ssh_flow_test.go`).
- **Le flux complet de bout en bout — control plane ET data plane** — `CreateSession` (deny-by-default) → `POST /sessions/{id}/connect` réel (résolution de compte → scope Vault → `EstablishSession` sur le vrai `ssh-proxy`, ne renvoyant que le `connection_ticket`, jamais le `scope_token`) → vraie connexion SSH d'un opérateur simulé → vraie cible recevant le credential exact → chaîne d'audit intacte → session terminée ne peut plus se connecter — entre **cinq** vrais binaires séparés (`test/integration/broker_flow_test.go`).

## RBAC réel sur les écritures du Vault, et PostgreSQL réel

**Le dernier écart RBAC est comblé — les deux moitiés ensemble.** `application.VaultService.OnboardAccount` et `Rotate` appellent désormais un vrai `Authorization.CheckAccess`, fail-closed, avant toute écriture — exactement le même principe que l'audit fail-closed du Session Broker (Guide HA §1). La Gateway injecte les rôles vérifiés dans les requêtes qu'elle transmet, mais ne duplique pas la décision : c'est Password Vault lui-même qui refuse, qu'on l'atteigne via la Gateway ou directement sur son port. Testé à trois niveaux : unitaire (deny-by-default, fail-closed si Authorization injoignable, un rôle avec seulement les droits de création de session ne suffit pas à administrer un compte), HTTP (la Gateway écrase l'`actorRoles` revendiqué par le client), et inter-processus réel (`admin_routes_test.go` : refus 403 explicite avant toute politique, puis succès une fois la politique créée).

**Choix de conception** : un nouvel espace de ressource `vault:account-admin:<id>`, distinct de `vault:account:<id>` (vérifié pour la création de session). Le modèle de politiques (doc 06 §3) n'a pas de dimension action — avoir le droit de session sur un compte n'offre donc aucun droit d'administration dessus, et réciproquement. C'est la façon la plus simple de séparer ces deux privilèges sans étendre le modèle de politiques.

**PostgreSQL réel, vérifié avec une vraie base qui tourne.** `postgresql` et `postgresql-contrib` s'installent via `apt-get` (dépôts Ubuntu, déjà autorisés) dans ce sandbox. `github.com/lib/pq` — hébergé directement sur GitHub, aucun problème d'import vanity contrairement à `golang.org/x/*` — se résout normalement via `GOPROXY=direct`. `services/vault/password-vault/internal/infrastructure/postgres_store.go` implémente les trois mêmes interfaces de dépôt que `InMemoryStore` (`domain.AccountRepository`, `domain.SecretRepository`, `domain.ScopeRepository`) — exactement le bénéfice de la séparation Clean Architecture annoncé depuis le début : aucun changement à `internal/application` pour faire la bascule.

**Écarts assumés, documentés dans `migrations/001_init.sql`** : les identifiants sont des `TEXT` fournis par l'appelant, pas des UUID générés par PostgreSQL comme le DDL d'origine (doc 06 §3) le prévoyait — changer maintenant casserait tous les identifiants déjà utilisés partout ailleurs, pour un bénéfice marginal. Et `vault_scope_grants` n'existait pas dans le DDL du doc 06 — les scopes à usage unique devaient bien vivre quelque part une fois la persistance réelle posée ; ajoutée en cohérence avec `domain.ScopeGrant`, pas improvisée à la volée.

**Un avantage concret de PostgreSQL sur `InMemoryStore`, prouvé et pas seulement affirmé** : `ConsumeIfValid` (le cœur du caractère « à usage unique » des scopes, ADR-0003) utilise un `UPDATE ... RETURNING` atomique — qui tiendrait sous plusieurs répliques de Password Vault partageant une base, contrairement au mutex Go d'`InMemoryStore`, qui ne protège que l'intérieur d'un seul processus.

**Preuve de persistance réelle, pas seulement « compile contre l'interface »** : `test/integration/postgres_flow_test.go` onboarde un compte sur un premier processus `password-vault`, **tue ce processus**, démarre un second processus entièrement séparé pointé sur la même base, et vérifie que le compte — et après rotation, le nouveau secret — y est toujours. C'est exactement la propriété qu'`InMemoryStore` ne pourrait jamais avoir.

**Limite pratique de ce sandbox, pas du code** : le service `postgresql` ne persiste pas de façon fiable entre deux appels d'outil séparés dans cet environnement (contrairement au système de fichiers) — `service postgresql start` doit être relancé avant toute suite de tests qui en dépend. `make test-postgres` et `TEST_DATABASE_URL` existent justement pour que ce soit un geste explicite et isolé, jamais une dépendance silencieuse de `make test`.

## RBAC réel sur l'Authorization Service lui-même, et PostgreSQL pour ses policies

**Le dernier gap RBAC connu est comblé.** `POST /policies` (création de politique) acceptait n'importe quel appelant jusqu'ici — explicitement signalé comme tel dans le commentaire de package de l'API Gateway et dans la section précédente de ce document. `application.AuthorizationService.CreatePolicy` exige désormais un accès sur une ressource dédiée, `authz:policy-admin`, vérifié via `CheckAccess` — **en interne, sans appel réseau** : Authorization est sa propre autorité ici, contrairement à Password Vault qui appelle Authorization à travers le réseau (`AuthorizationClient`, `vault_service.go`). Une erreur du dépôt de politiques reste fail-closed (jamais traitée comme un `allow`).

**Le problème de l'œuf et la poule, et comment il est résolu.** Si la création d'une politique exige déjà une politique, qui crée la toute première ? `AuthorizationService.BootstrapAdminPolicy(ctx, role, createdBy)` contourne volontairement `requirePolicyAdmin`, mais **seulement** quand le dépôt de politiques est entièrement vide (`PolicyRepository.Count() == 0`) — jamais sinon, même pour un rôle différent, pour qu'un appelant ultérieur (y compris compromis) ne puisse jamais s'octroyer un nouveau rôle admin sur un système déjà initialisé. `cmd/authorization/main.go` l'appelle à chaque démarrage (variable `BOOTSTRAP_ADMIN_ROLE`, défaut `platform-admin`) — un no-op sur tout redémarrage d'un système déjà initialisé, exactement le même principe qu'un jeton root HashiCorp Vault ou qu'un compte admin de bootstrap Keycloak, mais exprimé ici comme une politique ordinaire plutôt qu'un type de credential à part. Testé à trois niveaux, comme pour le gap Vault précédent : unitaire (refusé sans accès, refusé si l'accès ne vient que d'un rôle sans rapport, bootstrap crée la première politique sur un dépôt vide, bootstrap est un no-op dès qu'une politique existe déjà — même pour un rôle différent —, fail-closed si le dépôt erre), HTTP (la Gateway écrase désormais `actorRoles` sur `POST /policies` exactement comme elle le fait déjà pour l'onboarding/la rotation du Vault), et inter-processus réel (`admin_routes_test.go` : refus 403 explicite avant toute politique-admin, succès une fois la politique créée par `platform-admin`).

**PostgreSQL pour les policies**, même patron que le Vault : `services/access/authorization/migrations/001_init.sql` (même écart assumé — identifiants `TEXT`, pas de table `roles` séparée puisque les rôles restent des attributs fédérés par l'IdP, pas une entité gérée localement en MVP), `postgres_store.go` implémentant `domain.PolicyRepository` (`Create`, `ForRoles` — via `pq.Array` pour couvrir tous les rôles de l'appelant en une seule requête —, `Count`, qui fonde `BootstrapAdminPolicy`), `cmd/authorization/main.go` bascule sur `DATABASE_URL` avec repli en mémoire. Preuve de persistance réelle inter-processus, même format que pour le Vault : `TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart` crée une politique sur un premier processus, le tue, démarre un second processus séparé sur la même base, et vérifie que la politique — et le fait que le bootstrap ne se relance jamais — survivent.

## Deux bugs réels trouvés en exerçant PostgreSQL pour de vrai, pas seulement « compile contre l'interface »

Les deux bugs suivants étaient invisibles avec `InMemoryStore` — rien n'y imposait les contraintes que PostgreSQL impose réellement — et seule l'exécution d'un vrai redémarrage de processus contre une vraie base les a fait apparaître. Les deux sont corrigés et chacun a désormais un test qui l'épingle indépendamment du moteur de stockage.

1. **Clé de chiffrement locale non stable entre redémarrages.** `infrastructure.NewLocalKMS()` générait une clé AES-256 aléatoire à chaque démarrage de processus, sans aucun moyen de la retrouver au redémarrage suivant — un `password-vault` redémarré ne pouvait donc **jamais** déchiffrer ce qu'un processus précédent avait scellé, ce qui défait entièrement l'intérêt de la persistance PostgreSQL pour les secrets. Corrigé par `NewLocalKMSFromHexKey(hexKey string)` : `cmd/password-vault/main.go` refuse désormais de démarrer si `DATABASE_URL` est défini sans `KMS_KEY_HEX` (fail-closed, pas un repli silencieux sur une clé aléatoire) — `openssl rand -hex 32` pour en générer une, à garder hors de la base, cohérent avec `encryption_key_id... référence la clé KMS/HSM, pas la clé elle-même` (doc 06 §3). `KMS_KEY_HEX` reste optionnel quand `DATABASE_URL` n'est pas défini (mémoire, tests). Testé dans `crypto_test.go` (deux instances construites avec la même clé hex peuvent déchiffrer l'une ce que l'autre a scellé ; deux instances aléatoires ne le peuvent pas) et dans `test/integration/postgres_flow_test.go` (`TestPasswordVaultMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex`, qui n'a pas besoin d'une vraie base — le refus intervient avant toute tentative de connexion).

2. **Le numéro de version suivant était calculé après la supersession, pas avant.** `VaultService` calculait le prochain numéro de version (`storeNewVersion`, désormais `storeVersion`) en relisant `CurrentVersion` **après** que `Rotate` avait déjà appelé `SupersedeCurrent` — qui efface `superseded_at` sur toute ligne existante. Résultat : la relecture ne trouvait plus jamais rien, et le numéro de version retombait systématiquement à 1, à **chaque** rotation, pas seulement la première. `InMemoryStore.AddVersion` se contente d'ajouter à une liste sans vérifier l'unicité — le bug y était invisible. La contrainte `UNIQUE (privileged_account_id, version)` de PostgreSQL, elle, l'a fait échouer net dès la première rotation exercée contre une vraie base (`TestPostgresFlow_AccountSurvivesPasswordVaultProcessRestart`, sous-test "rotation on the restarted process persists too" : `status 403`). Corrigé en déplaçant la lecture du prochain numéro de version **avant** l'appel à `SupersedeCurrent`. `TestRotate_IncrementsVersionNumberEachTime` épingle le comportement correct (versions 1 → 2 → 3 sur deux rotations successives) indépendamment du moteur de stockage, pour que ce bug ne puisse pas revenir silencieusement même si un futur dépôt en mémoire est ajouté.

## Prochains incréments qui lèveront cette limite

Dans un environnement de développement ou de CI avec accès réseau complet :

1. `buf generate` sur `proto/` produira le code gRPC réel ; les fichiers `internal/interfaces/http.go` seront remplacés par des serveurs gRPC générés, sans toucher `internal/application`.
2. Étendre la bascule PostgreSQL aux services à état restants (`audit-service`, `authentication`, `session-broker`) — le même patron (interfaces de dépôt déjà posées, implémentation Postgres satisfaisant les mêmes interfaces) s'applique directement ; Password Vault et Authorization l'ont déjà.
3. Ajouter `Username` au DDL PostgreSQL et à `proto/vault/v1/vault.proto`/`proto/proxy/v1/proxy_control.proto` — actuellement threadé au niveau du code Go uniquement.
4. Remplacer le jeton HMAC maison par un vrai JWT une fois `google.golang.org/*` (ou une bibliothèque JWT hébergée directement sur GitHub) accessible.
5. Remplacer `LocalKMS` par un vrai client KMS/HSM externe — `KMS_KEY_HEX` est une étape vers une clé stable, pas un KMS réel ; voir le commentaire de doc de `NewLocalKMS`.

## État des tests à la date de cet incrément

99 fonctions de test unitaires (dont 9 conditionnées à `TEST_DATABASE_URL` — 5 pour le Vault, 4 pour Authorization — qui se *skip*, pas échouent, sans elle), plus 7 tests d'intégration (dont 2 conditionnés à `TEST_DATABASE_URL`), `go vet` propre, sur les 9 modules du `go.work`. Tous les tests PostgreSQL dédiés et les deux tests de persistance inter-processus (Vault et Authorization) ont été vérifiés avec une vraie base PostgreSQL 16 qui tourne dans ce sandbox, base vidée (`TRUNCATE`) avant chaque exécution complète pour ne pas laisser d'anciennes lignes fausser `Count`/les contraintes d'unicité d'une exécution à l'autre.

```
pkg/proxycore                                                 9 tests
services/access/api-gateway/internal/application               3 tests
services/access/api-gateway/internal/interfaces                10 tests
services/access/authentication/internal/application             6 tests
services/access/authentication/internal/infrastructure          10 tests
services/access/authorization/internal/application              12 tests (dont 6 RBAC/bootstrap)
services/access/authorization/internal/infrastructure            4 tests PostgreSQL (TEST_DATABASE_URL)
services/access/session-broker/internal/application             10 tests
services/proxy/ssh-proxy/internal/infrastructure                 3 tests
services/proxy/ssh-proxy/internal/sshcodec                       2 tests (vrai protocole SSH, 3 participants)
services/vault/password-vault/internal/application               15 tests (dont 5 RBAC, 1 versionnement)
services/vault/password-vault/internal/infrastructure            11 tests (dont 5 PostgreSQL TEST_DATABASE_URL, 6 LocalKMS)
services/recording-audit/audit-service/internal/application       4 tests
test/integration                                                  7 tests (dont 2 TEST_DATABASE_URL)
```

Compte vérifié par `grep -c "^--- PASS"` sur la sortie `go test -v`, pas estimé.
