# OpenBastion

Plateforme PAM (Privileged Access Management) open source, cloud-native, écrite en Go. Licence Apache 2.0.

> **État du projet** : implémentation du MVP en cours. Ce dépôt contient actuellement le premier incrément vertical — la partie du système qui prouve l'invariant de sécurité fondateur — pas encore l'ensemble des services du périmètre MVP. Voir `docs/architecture/OpenBastion_04_Roadmap.md` pour la feuille de route complète.

## L'invariant

Un secret cible ne transite **jamais** par le control plane (Gateway, Session Broker, Workflow). Seul un proxy protocolaire, authentifié par mTLS, peut échanger un jeton de scope à usage unique contre un credential éphémère — directement auprès du Vault. Le control plane autorise ; il ne voit jamais le secret.

Documenté dans `docs/architecture/OpenBastion_03_ADR.md` (ADR-0003), et **prouvé en code** :

- `pkg/proxycore` — purge mémoire du credential, octet par octet, testée.
- `services/vault/password-vault` — scope à usage unique, rejet strict par identité de proxy appelante, chiffrement enveloppe AES-256-GCM.
- `services/recording-audit/audit-service` — journal d'audit chaîné par hash, falsification rétroactive détectable même quand l'attaquant recalcule le hash de l'événement modifié.
- `services/access/authorization` — RBAC deny-by-default, un `deny` explicite l'emporte toujours sur un `allow`.
- `services/access/session-broker` — orchestrateur dont le port vers le Vault (`VaultAuthorizer`) n'a **structurellement aucune méthode** pour récupérer un credential : l'invariant est encodé dans le système de types Go, pas seulement documenté. Audit fail-closed (Guide HA §1) : un échec d'audit empêche l'octroi de la session.
- `services/proxy/ssh-proxy` — **le premier protocole réel** : un vrai serveur SSH (`golang.org/x/crypto/ssh`) authentifie l'opérateur par ticket à usage unique, récupère le credential exact au Vault, s'authentifie vers la cible avec, et relaie un shell interactif — testé avec un vrai client, un vrai proxy et une vraie fausse cible SSH, trois participants au protocole, pas des mocks.
- **Le câblage Session Broker ↔ ssh-proxy est fait** : `POST /sessions/{id}/connect` (le vrai endpoint public du doc 05, plus de placeholder interne) résout le compte, obtient un scope Vault, appelle le vrai `ssh-proxy`, et ne renvoie que le ticket de connexion — jamais le scope token Vault, testé explicitement.
- `services/access/authentication` — mots de passe en Argon2id réel, jetons **JWT réels** (RFC 7519, HS256 via `github.com/golang-jwt/jwt`, hébergé directement sur GitHub) — double verrou contre l'« alg confusion » (RFC 8725), clé de signature stabilisée par `TOKEN_SIGNING_KEY_HEX`. Voir `NOTES_SANDBOX.md` pour ce que ce remplacement a changé (une seule couche) et n'a pas changé (tout le reste).
- `services/access/api-gateway` — point d'entrée public unique : `POST /auth/login` limité en débit, tout le reste sous jeton vérifié. **Écrase systématiquement l'identité revendiquée par le client** avec celle qu'elle vient de vérifier — sur `POST /sessions` (`requestedBy`/`actorRoles`) comme sur `POST /policies` (`createdBy`) — un client ne peut pas usurper un autre utilisateur ni s'auto-attribuer des rôles en éditant sa requête, prouvé au niveau HTTP unitaire *et* en inter-processus réel avec une identité falsifiée explicite. Route aussi les surfaces d'administration (`/vault/accounts/*`, `/policies`), avec traduction de la forme REST publique vers le contrat interne de Password Vault là où les deux divergent.
- **Rotation vraiment automatique** : `Rotate` génère désormais 32 octets aléatoires si aucun secret n'est fourni — un vrai manque comblé en routant `/vault/accounts/{id}/rotate`, pas juste un ajout de tuyauterie. Vérifié en inter-processus réel : rotation via la Gateway, puis confirmation que le credential a effectivement changé.
- `test/integration` — cinq scénarios de bout en bout sur des processus réels et séparés : le flux SSH bas niveau, le flux à cinq processus, **le flux complet à sept processus entièrement piloté par la Gateway**, le routage des surfaces d'administration, et la persistance PostgreSQL à travers un redémarrage de processus — ce dernier scénario prouve désormais la survie au redémarrage des **cinq** services à état (Vault, Authorization, Authentication, Audit, Session Broker), pas seulement les deux premiers.
- **Les deux écarts RBAC connus sont comblés** : `Password Vault` applique un vrai `Authorization.CheckAccess`, fail-closed, sur ses propres écritures (onboarding, rotation) — espace de ressource dédié `vault:account-admin:*`, distinct de celui des sessions. Et `Authorization` applique désormais la même discipline **sur lui-même** : `POST /policies` exige l'accès à `authz:policy-admin`, bootstrapé une seule fois au tout premier démarrage (`BOOTSTRAP_ADMIN_ROLE`, no-op sur tout système déjà initialisé — jamais un redémarrage ne peut créer un nouvel admin). Les deux refusent qu'on les atteigne via la Gateway ou directement sur leur port.
- **PostgreSQL réel pour les cinq services à état** : `password-vault`, `authorization`, `authentication`, `session-broker` et `audit-service` basculent tous sur une vraie base (`DATABASE_URL`) sans aucun changement à leur couche application — exactement le bénéfice de séparation Clean Architecture annoncé depuis le début. Prouvé par cinq tests qui onboardent un compte / créent une politique / un utilisateur / une session / un événement d'audit, **tuent le processus**, en démarrent un second sur la même base, et vérifient que tout a survécu — y compris, pour le Vault, une rotation ultérieure, et pour l'audit, que le second processus chaîne correctement son événement sur le dernier du premier.
- **Cinq bugs réels trouvés en exerçant PostgreSQL pour de vrai** (invisibles avec le stockage en mémoire, qui n'impose aucune des contraintes qu'une vraie base impose) : une clé de chiffrement locale non stable entre redémarrages de processus (corrigée par `KMS_KEY_HEX`, requis dès que `DATABASE_URL` l'est) ; un numéro de version de secret recalculé après — pas avant — la supersession de la version précédente, qui retombait systématiquement à 1 et violait la contrainte d'unicité PostgreSQL dès la première rotation ; un rôle `nil` sérialisé en `NULL` au lieu d'un tableau vide, violant la contrainte `NOT NULL` d'Authentication ; et un hash de chaînage d'audit calculé sur une précision nanoseconde que PostgreSQL ne conserve pas (microseconde), qui faisait échouer la vérification de chaîne sur tout événement ayant transité par une vraie base. Voir `NOTES_SANDBOX.md` pour le détail des cinq. La clé de signature des tokens d'Authentication (`TOKEN_SIGNING_KEY_HEX`) a elle été stabilisée par anticipation, avant qu'un test ne la révèle en défaut, par analogie directe avec `KMS_KEY_HEX`.

## Démarrage rapide

Prérequis : Go ≥ 1.22.

```sh
make build            # compile tous les modules implémentés
make vet               # go vet sur l'ensemble
make test              # tests unitaires (hermétique, sans PostgreSQL)
make test-integration  # tests de bout en bout, inter-processus réel
make test-postgres     # tests PostgreSQL réels (TEST_DATABASE_URL requis)
```

Lancer les services individuellement (dans des terminaux séparés, dans cet ordre) :

```sh
make run-vault           # :8081
make run-audit            # :8082
make run-authorization     # :8083
make run-authentication      # :8086
make run-ssh-proxy             # :2222 (SSH réel) + :8085 (API interne)
make run-broker                  # :8084 — appelle Authorization/Vault/Audit/ssh-proxy
make run-gateway                   # :8080 — point d'entrée public unique
```

## Une remarque avant de lire le code

Le transport inter-services documenté est gRPC (`docs/architecture/OpenBastion_07_Interfaces_Inter_Services.md`). Ce dépôt, construit dans un environnement au réseau restreint, expose HTTP/JSON à la place — avec exactement les mêmes noms de champs que les messages Protobuf, dans la seule couche `internal/interfaces/`. **Lire `NOTES_SANDBOX.md` avant de s'étonner de ce choix** : il explique précisément la contrainte rencontrée, comment `golang.org/x/crypto/ssh` et `golang.org/x/crypto/argon2` ont malgré tout pu être utilisés (un `replace` vers leur mirroir GitHub officiel), et l'historique du câblage Broker/ssh-proxy/Gateway.

## Structure

Voir `docs/architecture/OpenBastion_02_Arborescence_Depot.md` pour l'arborescence cible complète (~35 microservices). Ce qui existe aujourd'hui :

```
pkg/proxycore/                                   pipeline proxy partagé (ADR-0006)
services/access/authorization/                   décision RBAC (deny-by-default)
services/access/session-broker/                  orchestrateur de session
services/proxy/ssh-proxy/                        premier proxy protocolaire réel (SSH)
services/vault/password-vault/                   coffre-fort (comptes, secrets, scopes)
services/recording-audit/audit-service/          audit à chaînage de hash
test/integration/                                preuve inter-processus de l'invariant
proto/                                            contrats gRPC/Protobuf (doc 07)
docs/                                             les 14 documents d'architecture et guides
```

## Documentation

L'ensemble de la documentation d'architecture (architecture globale, C4, ADR, feuille de route, contrats OpenAPI, modèle de données, guides sécurité/HA/PRA-PCA, documentation développeur/administrateur/utilisateur) vit sous `docs/`.

## Licence

Apache License 2.0 — voir `LICENSE`.
