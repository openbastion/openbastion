# Sécurité de l'autorisation

- **RBAC + ABAC combinés** (`docs/security/security-overview.md`) : le RBAC MVP (`docs/roadmap.md` §2) est complété par des attributs contextuels (heure, IP, score de risque) à partir de v1.0.
- **Principe du moindre privilège** : une politique (`policies`, `docs/architecture/data-architecture.md` §3) lie un rôle à un `resource_pattern` précis (ex. `vault:account:prod-*`), jamais un accès global par défaut.
- **Décision centralisée** : toute vérification passe par `Authorization.CheckAccess` (`docs/api/grpc/README.md` §8) — aucun service ne réimplémente sa propre logique d'autorisation.

**Point de vérification pour audit** : un rôle nouvellement créé sans politique associée ne doit donner accès à rien (deny-by-default).
