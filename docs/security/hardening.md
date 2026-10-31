# Durcissement du déploiement

- Images OCI minimales (distroless ou équivalent), sans shell ni outillage de débogage en production.
- `NetworkPolicy` Kubernetes restreignant chaque service aux flux strictement nécessaires (cohérent avec §8).
- Secrets de bootstrap de la plateforme elle-même (identifiants PostgreSQL, Keycloak admin, clés KMS) injectés via un mécanisme externe au dépôt (ex. Vault Agent Injector, External Secrets Operator) — jamais en clair dans les manifestes Helm versionnés.
- Scan de vulnérabilités des images et des dépendances en CI (`test/security/`, `docs/development/repository-structure.md` §9), avant toute publication d'image.
