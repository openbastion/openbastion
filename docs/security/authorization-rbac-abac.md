# Sécurité de l'autorisation

- **RBAC + ABAC combinés** (`docs/security/security-overview.md`) : le RBAC MVP (`docs/roadmap.md` §2) est complété par des attributs contextuels (heure, IP, score de risque) à partir de v0.0.1.
- **Principe du moindre privilège** : une politique (`policies`, `docs/architecture/data-architecture.md` §3) lie un rôle à un `resource_pattern` et un `action_pattern` (ADR-0114). Les deux doivent correspondre ; une seule dimension correspondante ne donne aucun accès. Les motifs acceptent une valeur exacte ou un unique joker final `*`.
- **Décision centralisée** : toute vérification passe par `Authorization.CheckAccess` (`docs/api/grpc/README.md` §8) — aucun service ne réimplémente sa propre logique d'autorisation.

**Point de vérification pour audit** : un rôle nouvellement créé sans politique associée ne doit donner accès à rien (deny-by-default).

- **Compatibilité ADR-0114 :** la migration remplit `action_pattern=*` pour les politiques historiques et l’API HTTP accepte temporairement l’omission de `actionPattern` comme `*`. Ces politiques conservent leur ancienne portée large sur les actions ; les nouvelles permissions sensibles doivent déclarer une action explicite et les politiques historiques doivent être réduites progressivement.
