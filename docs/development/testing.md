# Tests

| Niveau | Emplacement | Commande |
|---|---|---|
| Unitaire | à côté du code, `*_test.go` dans chaque `internal/` | `make test SERVICE=<nom>` |
| Intégration | `test/integration/` (Testcontainers) | `make test-integration` |
| End-to-end | `test/e2e/` | `make test-e2e` |
| Performance | `test/performance/` (k6) | `make test-perf` |
| Sécurité | `test/security/` | `make test-security` |

Les tests d'intégration actuels du dépôt (`test/integration/*_test.go`) tournent en mode `INTERNAL_TLS=disabled`, stipulé dans `buildEnv` ; `mtls_flow_test.go` et `mtls_lifecycle_test.go` font tourner les huit services sous mTLS requis avec une PKI générée par test (`mtls_helpers_test.go`), et attaquent le réseau avec des identités de toute sorte.

Un service qui touche à la couche proxy ou au Vault (`docs/development/contributing.md`, « Ajouter un nouveau protocole de proxy » ; `docs/security/secrets-management.md`, `docs/security/secure-development.md`, `docs/security/session-security.md`) n'est pas mergeable sans passage vert de `test-security` — ce n'est pas laissé à l'appréciation du relecteur.
