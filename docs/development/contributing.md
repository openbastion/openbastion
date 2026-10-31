# Contribuer

## Repères dans le monorepo

Rappel de l'arborescence complète : `docs/development/repository-structure.md`. Table de correspondance rapide pour une tâche donnée :

| Je veux… | Je vais dans… |
|---|---|
| Ajouter un endpoint REST public | `services/access/api-gateway/`, puis mettre à jour `docs/api/rest/openapi.yaml` |
| Modifier la logique d'octroi de session | `services/access/session-broker/internal/application/` |
| Ajouter un protocole de proxy | `services/proxy/<nouveau>/`, en réutilisant `pkg/proxycore/` (« Ajouter un nouveau protocole de proxy », ci-dessous) |
| Modifier un contrat gRPC interne | `proto/<domaine>/v1/`, puis `make proto-gen` |
| Ajouter une table ou une colonne | **nouvelle** migration numérotée `services/<domaine>/<service>/migrations/NNN_nom.sql` (jamais un fichier existant modifié, ADR-0030 ; additive par défaut, en transaction), mettre à jour `docs/architecture/data-architecture.md` |
| Toucher à l'Admin UI | `web/admin-ui/src/features/<domaine>/` |

## Structure d'un microservice — rappel

Chaque service suit le gabarit posé dans `docs/development/repository-structure.md` §3 : `cmd/`, `internal/{domain,application,infrastructure,interfaces}/`, `go.mod` propre. Le point à retenir en tant que contributeur : **`internal/` n'est jamais importable depuis un autre service**. Toute communication passe par le contrat `proto/` correspondant (`docs/api/grpc/README.md`) — si vous vous surprenez à vouloir importer le package interne d'un autre service, c'est le signal qu'il manque un RPC au contrat, pas une raison de contourner la règle.

## Ajouter un nouveau protocole de proxy

Les 9 proxies partagent `pkg/proxycore` (`docs/architecture/components.md`, ADR-0006). Ajouter un dixième protocole ne touche jamais au pipeline commun :

1. Créer `services/proxy/<nom>-proxy/`.
2. Implémenter l'interface `Codec` (`pkg/proxycore/codec.go`) — c'est la seule pièce spécifique au protocole.
3. Câbler `ProxyControl` (`proto/proxy/v1/proxy_control.proto`, `docs/api/grpc/README.md` §4) dans `cmd/<nom>-proxy/main.go`.
4. Écrire les tests de `test/security/` vérifiant la purge mémoire du credential (voir `docs/security/session-security.md`) — **obligatoire**, pas optionnel, avant toute revue de code sur un nouveau proxy.
5. Ajouter le chart Helm sous `deploy/helm/charts/<nom>-proxy/`.

## Travailler avec les contrats Protobuf

- Toute modification de `proto/` doit passer `buf lint` et `buf breaking` avant merge (`docs/api/grpc/README.md` §1) — la CI rejette automatiquement une rupture non justifiée.
- Le code généré n'est pas commité : `make proto-gen` le régénère localement et en CI. Ne jamais éditer un fichier `*.pb.go` à la main.
- Un champ retiré est marqué `reserved`, jamais réutilisé (`docs/api/grpc/README.md` §1) — même en développement local, avant toute publication.

## Processus de contribution

1. Ouvrir une issue décrivant le changement avant toute pull request substantielle — évite un travail rejeté pour désalignement architectural.
2. Une pull request ne touche idéalement qu'un seul service (ou `pkg/`, ou `proto/`) — cohérent avec le filtrage CI par chemins modifiés (`docs/development/repository-structure.md` §9).
3. CI bloquante : lint, tests unitaires du/des service(s) modifié(s), `buf breaking` si `proto/` est touché, `test-security` si la couche proxy ou le Vault est touchée.
4. Toute pull request touchant un ADR existant (`docs/adr/`) doit soit le respecter, soit proposer un nouvel ADR le remplaçant explicitement (« Remplacé par ADR-NNNN », `docs/adr/README.md`) — pas de dérive silencieuse.
