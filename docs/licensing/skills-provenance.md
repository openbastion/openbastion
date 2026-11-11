# Inventaire de provenance des Agent Skills

État vérifié le 10 novembre 2026 sur la branche de remédiation. Le dépôt contient **95 compétences** : **85 importées** et **10 originales OpenBastion**. Le manifeste machine-readable associé est [`skills-provenance.json`](skills-provenance.json).

## Résumé

| Origine | Nombre | Licence | Révision source contrôlée |
|---|---:|---|---|
| `samber/cc-skills-golang` | 46 | MIT | [`d68d80aec298`](https://github.com/samber/cc-skills-golang/tree/d68d80aec298e1b74b37c2a472c002b5217248b3) |
| `addyosmani/agent-skills` | 25 | MIT | [`301b02b12bff`](https://github.com/addyosmani/agent-skills/tree/301b02b12bff98e4688e6984af6556802322bbde) |
| `jakubkrehel/skills` | 14 | MIT | [`8b254eb75dad`](https://github.com/jakubkrehel/skills/tree/8b254eb75dadf3615a6abce87aed28e1b6e4d77c) |
| OpenBastion (interne) | 10 | AGPL-3.0-only | commits d’introduction dans le dépôt |

## Compétences tierces importées

Les 85 entrées du `skills-lock.json` ont été comparées aux répertoires amont aux révisions immuables ci-dessus. Les 85 fichiers `SKILL.md` sont identiques aux sources contrôlées. Les répertoires complets sont identiques pour 84 compétences. Pour `state-machine`, le fichier `switcher.md` contient un delta local documenté dans le manifeste (transition CSS et graisse de police de l’onglet actif), introduit par le commit `1f043c78`; il est conservé et n’est pas présenté comme du contenu amont.

Le lockfile est maintenu au format généré par le CLI Skills. Les révisions upstream et les écarts locaux sont conservés dans le manifeste adjacent afin de ne pas injecter de champs propriétaires dans le schéma du lockfile. Les hashes `computedHash` de version 1 sont vérifiés avec l’algorithme historique du CLI, et non recalculés avec le format version 2.

### `samber/cc-skills-golang`

`golang-benchmark`, `golang-cli`, `golang-code-style`, `golang-concurrency`, `golang-context`, `golang-continuous-integration`, `golang-data-structures`, `golang-database`, `golang-dependency-injection`, `golang-dependency-management`, `golang-design-patterns`, `golang-documentation`, `golang-error-handling`, `golang-google-wire`, `golang-gopls`, `golang-graphql`, `golang-grpc`, `golang-how-to`, `golang-lint`, `golang-modernize`, `golang-naming`, `golang-observability`, `golang-performance`, `golang-pkg-go-dev`, `golang-popular-libraries`, `golang-project-layout`, `golang-refactoring`, `golang-safety`, `golang-samber-do`, `golang-samber-hot`, `golang-samber-lo`, `golang-samber-mo`, `golang-samber-oops`, `golang-samber-ro`, `golang-samber-slog`, `golang-security`, `golang-spf13-cobra`, `golang-spf13-viper`, `golang-stay-updated`, `golang-stretchr-testify`, `golang-structs-interfaces`, `golang-swagger`, `golang-testing`, `golang-troubleshooting`, `golang-uber-dig`, `golang-uber-fx`.

### `addyosmani/agent-skills`

`api-and-interface-design`, `browser-testing-with-devtools`, `ci-cd-and-automation`, `code-review-and-quality`, `code-simplification`, `constraint-driven-development`, `context-engineering`, `debugging-and-error-recovery`, `deprecation-and-migration`, `documentation-and-adrs`, `doubt-driven-development`, `frontend-ui-engineering`, `git-workflow-and-versioning`, `idea-refine`, `incremental-implementation`, `interview-me`, `observability-and-instrumentation`, `performance-optimization`, `planning-and-task-breakdown`, `security-and-hardening`, `shipping-and-launch`, `source-driven-development`, `spec-driven-development`, `test-driven-development`, `using-agent-skills`.

### `jakubkrehel/skills`

`better-accessibility`, `better-colors`, `better-interface`, `better-layout`, `better-typography`, `better-ui`, `better-writing`, `break`, `build-design`, `explain-interface`, `interface-review`, `state-machine`, `teardown`, `variant`.

## Compétences originales OpenBastion

Ces compétences ne figurent pas dans le lockfile des imports tiers. Leur provenance est rattachée au commit d’introduction, à l’auteur Git et au co-auteur présent dans le commit. Elles restent sous AGPL-3.0-only avec le reste du contenu original du projet.

- `devsecops-ci-cd` — commit [`4d1b5a5d170c`](https://github.com/openbastion/openbastion/commit/4d1b5a5d170c0ef0caba8c9f22cefce585ffbf21), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `distributed-systems-resilience` — commit [`d93c5789d328`](https://github.com/openbastion/openbastion/commit/d93c5789d328254c39d7ec728ac3e4dc0cefb5ab), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `frontend-testing-accessibility` — commit [`8d76787cb943`](https://github.com/openbastion/openbastion/commit/8d76787cb943e9c115f7cf63fba356e26f142d2d), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `go-api-security` — commit [`8d76787cb943`](https://github.com/openbastion/openbastion/commit/8d76787cb943e9c115f7cf63fba356e26f142d2d), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `go-production-engineering` — commit [`4d1b5a5d170c`](https://github.com/openbastion/openbastion/commit/4d1b5a5d170c0ef0caba8c9f22cefce585ffbf21), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `go-reliability-testing` — commit [`8d76787cb943`](https://github.com/openbastion/openbastion/commit/8d76787cb943e9c115f7cf63fba356e26f142d2d), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `postgresql-data-engineering` — commit [`8d76787cb943`](https://github.com/openbastion/openbastion/commit/8d76787cb943e9c115f7cf63fba356e26f142d2d), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `react-typescript-architecture` — commit [`4d1b5a5d170c`](https://github.com/openbastion/openbastion/commit/4d1b5a5d170c0ef0caba8c9f22cefce585ffbf21), Patrick Luzolo, co-auteur : Claude Opus 5.5.
- `ui-ux-design-system` — commit [`2aea00831c50`](https://github.com/openbastion/openbastion/commit/2aea00831c504c378865c38951700a2d2fd90ea3), Patrick Luzolo, co-auteur : GitHub Copilot.
- `web-application-security` — commit [`8d76787cb943`](https://github.com/openbastion/openbastion/commit/8d76787cb943e9c115f7cf63fba356e26f142d2d), Patrick Luzolo, co-auteur : Claude Opus 5.5.

## Méthode et limites

- Les révisions tierces sont les HEAD upstream relevés pendant l’audit et les contenus ont été comparés à ces commits ; les fichiers de licence MIT ont été lus à ces mêmes révisions.
- `skillMdSha256` protège le fichier `SKILL.md` local ; `lockComputedHash` conserve le hash de dossier produit par le lockfile. Le contrôle automatisé vérifie les deux.
- Le manifeste décrit l’état observé au moment de l’audit ; toute mise à jour upstream doit réviser la source, les hashes, les notices si nécessaire et les contrôles associés.
- L’attribution par commit établit l’historique Git d’introduction ; elle ne remplace pas une vérification juridique individuelle des droits de chaque contribution.
