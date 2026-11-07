# Arborescence du dépôt

## 1. Décision structurante : monorepo

| Option | Avantages | Inconvénients |
|---|---|---|
| **Monorepo** (retenu) | Refactoring cross-service atomique pendant la phase pré-v0.0.1, contrats `proto/` partagés sans publication intermédiaire, CI unifiée, revue de code centralisée | Nécessite un outillage de build sélectif (changed-files) pour éviter de tout reconstruire à chaque commit |
| Multi-repo | Isolation forte, cycles de release indépendants par service | Coordination difficile des contrats inter-services tant que l'architecture bouge encore beaucoup |

🔖 **Sujet ADR** : ce choix sera formalisé en ADR (document suivant), avec le critère de bascule explicite — un service pourra être extrait en dépôt indépendant une fois son contrat gRPC/REST stabilisé en v0.0.1, sans réécriture (les modules Go sont déjà isolés, voir §3).

Le monorepo est organisé en **modules Go indépendants** (`go.work`), pas en un module unique — chaque microservice a son propre `go.mod`, ce qui préserve la possibilité d'extraction future.

## 2. Arborescence racine

```
openbastion/
├── services/                     # microservices backend, un dossier par domaine (§4 docs/architecture/system-overview.md)
│   ├── access/
│   │   ├── api-gateway/
│   │   ├── authentication/
│   │   ├── authorization/
│   │   └── session-broker/
│   ├── governance/
│   │   ├── workflow/
│   │   ├── approval-engine/
│   │   └── notification/
│   ├── security-intelligence/
│   │   ├── mfa/
│   │   └── risk-engine/
│   ├── proxy/
│   │   ├── ssh-proxy/
│   │   ├── rdp-vnc-proxy/
│   │   ├── telnet-serial-proxy/
│   │   ├── winrm-proxy/
│   │   ├── database-proxy/
│   │   ├── kubernetes-proxy/
│   │   ├── docker-proxy/
│   │   ├── hypervisor-console-proxy/
│   │   └── http-web-proxy/
│   ├── vault/
│   │   ├── password-vault/
│   │   └── secrets-manager/
│   ├── recording-audit/
│   │   ├── session-recorder/
│   │   ├── video-recorder/
│   │   ├── command-recorder/
│   │   ├── audit-service/
│   │   ├── search-engine/
│   │   └── reporting-service/
│   ├── identity-federation/
│   │   ├── ldap-connector/
│   │   ├── ad-connector/
│   │   ├── entra-id-connector/
│   │   ├── oidc-connector/
│   │   ├── saml-connector/
│   │   └── scim-provisioning/
│   └── platform/
│       └── scheduler/
│
├── proto/                        # contrats gRPC/Protobuf partagés (source de vérité inter-services)
│   ├── access/v1/
│   ├── proxy/v1/
│   ├── vault/v1/
│   ├── recording/v1/
│   ├── governance/v1/
│   ├── identity/v1/
│   └── common/v1/                # types partagés (erreurs, pagination, identité de requête)
│
├── pkg/                          # bibliothèques Go partagées, importées par les services
│   ├── proxycore/                # pipeline proxy commun (Connection Listener, Credential Fetcher, Codec, Tap, Terminator)
│   ├── rdp/                      # primitives de pinning du certificat cible ; moteur RDP à implémenter (ADR-0069/0071)
│   ├── mtls/                     # identité par certificat (SAN URI spiffe://<domaine>/<service>), garde d'appelants par route, rechargement à chaud (ADR-0010)
│   │   ├── pki/                  #   autorité et émission de certificats de service (dev, petits sites)
│   │   ├── mtlstest/             #   habille une requête en pair authentifié, pour tester les tables d'appelants
│   │   └── cmd/openbastion-pki/  #   CLI : init, issue, all
│   ├── telemetry/                # intégration OpenTelemetry commune
│   ├── auditlog/                 # émission d'événements d'audit signés
│   └── errors/                   # types d'erreurs partagés, mapping gRPC/HTTP
│
├── web/
│   ├── admin-ui/                 # React / TypeScript / Vite — interface opérateur
│   ├── user-portal/              # React / TypeScript / Vite — interface self-service
│   ├── openbastion-icons/        # package React/SVG des icônes OpenBastion
│   ├── packages/
│   │   ├── ui/                   # primitives UI génériques partagées
│   │   ├── design-tokens/        # tokens et thèmes partagés
│   │   ├── api-client/           # client de l'API publique Gateway
│   │   ├── contracts/            # types issus des contrats API publics
│   │   └── utilities/            # utilitaires frontend génériques
│   └── package.json              # orchestration et scripts frontend
│
├── desktop/
│   └── tauri-client/             # client natif RDP/SSH
│
├── cli/
│   └── openbastion-cli/          # Go
│
├── sdk/
│   ├── go/
│   ├── python/
│   ├── java/
│   └── javascript/
│
├── deploy/
│   ├── docker-compose/
│   │   ├── docker-compose.yml
│   │   └── docker-compose.dev.yml
│   ├── helm/
│   │   └── charts/                # un sous-dossier de chart par service, plus un chart "umbrella"
│   └── k8s/
│       ├── base/                  # manifestes Kustomize de base
│       └── overlays/
│           ├── dev/
│           ├── staging/
│           └── prod/
│
├── docs/
│   ├── architecture/              # cette séquence de documents (00, 01, 02, …)
│   ├── adr/                       # Architecture Decision Records
│   ├── api/                       # OpenAPI, collection Postman
│   ├── guides/                    # admin, développeur, utilisateur, sécurité, HA, PRA/PCA
│   └── diagrams/                  # sources Mermaid/SVG exportées
│
├── test/
│   ├── integration/                # tests croisant plusieurs services réels (Testcontainers)
│   ├── e2e/                        # scénarios bout-en-bout (Admin UI incluse)
│   ├── performance/                # k6 / Gatling — charge sur la couche proxy notamment
│   └── security/                   # tests de sécurité automatisés (SAST/DAST/fuzzing ciblé)
│
├── .github/workflows/               # CI GitHub Actions
├── .gitlab-ci.yml                   # CI GitLab (miroir, selon plateforme d'hébergement retenue)
├── go.work                          # workspace Go multi-module
├── Makefile                         # commandes de build/test agrégées
├── LICENSE                          # AGPL-3.0
└── README.md
```

## 3. Structure type d'un microservice Go

Chaque service suit la même ossature, inspirée de Clean Architecture / DDD léger — cohérence imposée pour que tout contributeur retrouve ses repères d'un service à l'autre.

```
services/proxy/ssh-proxy/
├── cmd/
│   └── ssh-proxy/
│       └── main.go              # point d'entrée, câblage des dépendances (wiring)
├── internal/
│   ├── domain/                  # entités métier et règles, sans dépendance externe
│   ├── application/             # cas d'usage, orchestration du domaine
│   ├── infrastructure/          # implémentations techniques : gRPC client Vault, mTLS, stockage
│   └── interfaces/              # handlers gRPC/HTTP exposés par CE service
├── go.mod
├── go.sum
├── Dockerfile
├── Makefile
└── README.md
```

Le dossier `internal/` empêche toute importation depuis l'extérieur du module — un service ne peut consommer un autre service que via son contrat `proto/`, jamais son code interne.

## 4. Cas particulier : `pkg/proxycore`

Les 9 proxies protocolaires partagent le pipeline détaillé au §4.2 des diagrammes C4 (Connection Listener, Credential Fetcher, Protocol Codec, Recording Tap, Session Terminator). Ce pipeline est factorisé en bibliothèque Go partagée (`pkg/proxycore`) plutôt que dupliqué neuf fois : chaque proxy protocolaire l'importe et ne réimplémente que son `Protocol Codec` spécifique (SSH, RDP, SQL, K8s API, …).

```
pkg/proxycore/
├── listener.go
├── credential_fetcher.go        # le seul point du système où un secret existe en mémoire
├── codec.go                     # interface à implémenter par chaque proxy
├── recording_tap.go
└── terminator.go
```

## 5. Frontend — `web/`

Le frontend est organisé en deux applications indépendantes et en packages partagés. Cette structure est la référence normative des incréments frontend (ADR-0036 et ADR-0075). Les dossiers métier restent dans leur application ; les packages partagés ne contiennent pas de logique métier.

```
web/
├── admin-ui/
│   ├── src/
│   └── ...
│
├── user-portal/
│   └── src/
│       ├── app/
│       │   ├── router/
│       │   ├── providers/
│       │   └── layouts/
│       │
│       ├── features/
│       │   ├── home/
│       │   ├── resources/
│       │   ├── access-requests/
│       │   ├── sessions/
│       │   ├── approvals/
│       │   ├── activity/
│       │   └── profile/
│       │
│       ├── components/
│       │   ├── navigation/
│       │   ├── resources/
│       │   ├── sessions/
│       │   └── feedback/
│       │
│       ├── services/
│       ├── hooks/
│       ├── stores/
│       ├── types/
│       └── test/
│
├── openbastion-icons/
│   ├── src/
│   └── ...
│
├── packages/
│   ├── ui/
│   ├── design-tokens/
│   ├── api-client/
│   ├── contracts/
│   └── utilities/
│
└── package.json
```

### Responsabilités

| Chemin | Responsabilité |
|---|---|
| `admin-ui/` | Interface opérateur et administration ; aucun parcours self-service propre au portail |
| `user-portal/` | Interface self-service : ressources, demandes, sessions, approbations conditionnelles, activité et profil |
| `openbastion-icons/` | Source commune des icônes de marque et fonctionnelles |
| `packages/ui/` | Primitives visuelles génériques, sans connaissance des domaines PAM |
| `packages/design-tokens/` | Tokens sémantiques et thèmes clair/sombre |
| `packages/api-client/` | Client HTTP de l'API publique Gateway uniquement |
| `packages/contracts/` | Types frontend issus des contrats API publics ; OpenAPI reste la source de vérité |
| `packages/utilities/` | Utilitaires frontend génériques et sans logique métier |
| `web/package.json` | Scripts et orchestration du frontend ; gestion des workspaces/lockfiles à faire évoluer sans rompre `npm ci` |

Règles de dépendance :

1. `admin-ui` et `user-portal` sont indépendants ; aucune importation directe entre leurs fonctionnalités ou leurs composants métier.
2. Les deux applications peuvent consommer `openbastion-icons` et les packages partagés via leurs interfaces publiques.
3. Les packages partagés ne dépendent d'aucune application ; les cycles de dépendances sont interdits.
4. Les composants réutilisés par plusieurs applications et réellement génériques vont dans `packages/ui/`. Un composant propre au portail reste dans `user-portal/src/components/` ou dans sa feature.
5. `packages/api-client/` ne contacte que l'API publique Gateway. Le navigateur n'accède jamais directement aux microservices, bases, bus, Redis, OpenSearch ou MinIO.
6. `packages/contracts/` est dérivé des contrats API publics versionnés ; il ne duplique pas les modèles internes ni les contrats gRPC privés.
7. Les secrets privilégiés ne sont jamais transmis aux applications web. Un lancement de session utilise uniquement le ticket éphémère borné émis par le Session Broker.
8. Chaque application conserve son build et ses tests. Le chemin de service Gateway du portail sera défini et vérifié avant son exposition ; aucune route `/portal/` n'est présumée existante par cette arborescence.

## 6. `deploy/` — portabilité on-prem / cloud

| Sous-dossier | Usage |
|---|---|
| `docker-compose/` | Développement local et petites installations on-premise |
| `helm/charts/` | Un chart par service + chart umbrella pour déploiement complet ; référence pour K8s, K3s, OpenShift |
| `k8s/base` + `overlays/` | Approche Kustomize pour les environnements (dev/staging/prod) sans divergence de manifeste |

## 7. `docs/` — une section par public, un sujet par fichier

```
docs/
├── README.md            plan, et table « ancien document → nouveau fichier »
├── roadmap.md
├── architecture/        vue d'ensemble, principes, C4, déploiement, modèle de données
├── adr/                 un fichier par ADR, index README.md, template.md
├── api/                 conventions.md, rest/openapi.yaml, grpc/README.md
├── security/            modèle de menace, une page par domaine, known-limitations.md
├── development/         prérequis, environnement local, arborescence, tests, contribution
├── deployment/          installation, configuration, mTLS, HA, sauvegarde, reprise, dépannage
├── administration/      comptes privilégiés, politiques, break-glass, enregistrement, audit
├── user-guide/          parcours de l'opérateur
├── operations/          index : pages prévues
└── compliance/          index : pages prévues
```

Une page n'existe que si son contenu décrit ce que fait le code ; ce qui est prévu est listé dans le `README.md` de la section, avec le point de la feuille de route qui le couvre.

## 8. Conventions de nommage

| Élément | Convention | Exemple |
|---|---|---|
| Module Go d'un service | `github.com/openbastion/openbastion/services/<domaine>/<service>` | `.../services/proxy/ssh-proxy` |
| Package proto | `openbastion.<domaine>.v1` | `openbastion.proxy.v1` |
| Chart Helm | identique au nom du dossier service, kebab-case | `ssh-proxy` |
| Image conteneur | `ghcr.io/openbastion/<service>` | `ghcr.io/openbastion/ssh-proxy` |
| Page de documentation | `docs/<section>/<sujet-kebab-case>.md` | `docs/security/threat-model.md` |
| ADR | `docs/adr/NNNN-titre-kebab-case.md` | `docs/adr/0002-organisation-en-monorepo-multi-module-go.md` |

## 9. CI/CD — aperçu

- **GitHub Actions** (`.github/workflows/`) : un workflow réutilisable par type de job (lint, test unitaire, build image, scan sécurité), déclenché sélectivement selon les chemins modifiés (`paths:` filter) pour ne pas reconstruire les 35 services à chaque commit.
- **GitLab CI** (`.gitlab-ci.yml`) : miroir fonctionnel, maintenu pour compatibilité selon la plateforme d'hébergement finale du projet.
- Les tests d'intégration/e2e/performance/sécurité (`test/`) tournent sur un sous-ensemble de la matrice CI, pas sur chaque commit de service isolé.

- `pkg/tlspin` : épinglage TLS des cibles, avec validation PKI conservée en production et chemin pin-only compilé uniquement avec `-tags development`.
