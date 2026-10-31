# Développement

Pour contribuer à OpenBastion : construire, tester, étendre. Le *pourquoi* des choix est dans [`../architecture/`](../architecture/README.md) et [`../adr/`](../adr/README.md).

| Page | Contenu |
|---|---|
| [`prerequisites.md`](prerequisites.md) | Les outils |
| [`local-environment.md`](local-environment.md) | Démarrer en local, mTLS ou non, essayer chaque fonctionnalité |
| [`repository-structure.md`](repository-structure.md) | L'arborescence du monorepo, la structure d'un service, les conventions de nommage |
| [`testing.md`](testing.md) | Les niveaux de tests |
| [`debugging.md`](debugging.md) | L'observabilité en développement |
| [`contributing.md`](contributing.md) | Où faire quoi, ajouter un protocole, travailler avec `proto/`, le processus de contribution |

Les commandes réellement disponibles sont celles du `Makefile` (`make build vet`, `make test`, `make test-integration`, `make test-postgres`, `make test-compose`, `make ui-test ui-build`, `make pki`, `make run-<service>`). Certaines pages citent encore des cibles de la conception initiale qui n'existent pas dans le `Makefile` ; c'est une limite connue de cette documentation.

## Pages prévues

| Page | État |
|---|---|
| `getting-started.md` | Couvert par [`prerequisites.md`](prerequisites.md) et [`local-environment.md`](local-environment.md). |
| `coding-standards.md` | Les normes appliquées au code vivent dans `.agents/rules/` (Go, PostgreSQL, frontend, contrats d'API). |
| `migrations.md` | La règle tient dans ADR-0030 et dans la table de [`contributing.md`](contributing.md) ; une page viendra avec un outil de migration. |
| `release-process.md` | Aucune release publiée ; la règle de livraison est dans `.agents/policies/release-management.md`. |
