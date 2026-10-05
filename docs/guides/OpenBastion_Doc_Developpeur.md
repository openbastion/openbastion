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
