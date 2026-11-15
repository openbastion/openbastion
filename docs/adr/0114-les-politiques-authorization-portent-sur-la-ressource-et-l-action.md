# ADR-0114 — Les politiques Authorization portent sur la ressource et l'action

- **Statut :** Accepté
- **Date :** 15 novembre 2026
- **Contexte :** ADR-0003, ADR-0010, ADR-0043, ADR-0113
- **Licence :** AGPL-3.0

## Contexte

`Authorization.CheckAccess` reçoit depuis son origine deux dimensions (`resource` et `action`), notamment dans `proto/authz/v1/authorization.proto`. Jusqu'ici, le moteur ne comparait que `resource_pattern` : le champ `action` était ignoré. Une politique autorisant une ressource autorisait donc toutes les actions appelées sur cette ressource, ce qui rendait impossible une permission dédiée comme `audit:secret-injections:read` sur `audit:secret-injections:all` (ADR-0113).

Cette divergence est une faiblesse de sécurité : l'API donne l'apparence d'une décision ABAC/RBAC sur deux dimensions, alors que seule la ressource participe réellement à la décision.

## Décision

Chaque politique porte désormais deux motifs indépendants : `resource_pattern` et `action_pattern`. Une politique ne correspond que si **les deux** motifs correspondent à la ressource et à l'action demandées.

- Les motifs conservent la grammaire MVP existante : correspondance exacte ou un unique joker `*` final, qui signifie « tout suffixe ». Les jokers internes ou multiples ne sont pas interprétés comme des glob patterns.
- Le refus explicite l'emporte sur toute autorisation explicite, mais uniquement parmi les politiques dont les deux dimensions correspondent.
- L'absence de politique correspondant aux deux dimensions entraîne un refus (deny-by-default).
- Une ressource ou une action vide entraîne un refus.
- La politique de bootstrap `authz:policy-admin` est limitée à l'action `authz:policy:create`.
- La route de rapprochement ADR-0113 exige une politique explicite `resource_pattern=audit:secret-injections:all`, `action_pattern=audit:secret-injections:read`, `effect=allow`.

### Compatibilité des politiques existantes

Une migration additive `002_action_pattern.sql` ajoute `action_pattern TEXT NOT NULL DEFAULT '*'`. Les politiques déjà stockées conservent ainsi exactement leur portée historique sur les actions ; aucune ligne n'est supprimée ou réinterprétée silencieusement. La contrainte d'unicité devient `(role, resource_pattern, action_pattern, effect)`.

Pour les clients HTTP existants, l'omission de `actionPattern` est temporairement équivalente à `*`, afin de préserver les contrats et les déploiements déjà automatisés. Une valeur explicitement vide ou `null` est invalide et renvoie `400` : elle ne doit jamais être confondue avec une omission. Les nouveaux clients et les permissions sensibles doivent fournir une action explicite. L'API expose `actionPattern` et documente le défaut de compatibilité.

## Conséquences

- Les décisions d'accès sont enfin bornées par la ressource ET l'action réellement demandées.
- Les politiques historiques restent compatibles, mais demeurent volontairement larges sur les actions jusqu'à leur migration administrative vers des motifs explicites. La migration de schéma ne prétend pas réduire rétroactivement leurs privilèges.
- Les politiques de nouvelle génération doivent choisir une action précise ou un préfixe maîtrisé ; `*` doit être réservé aux rôles et usages qui nécessitent réellement une portée historique globale.
- La contrainte d'unicité autorise plusieurs politiques d'un même rôle et d'une même ressource lorsque les actions diffèrent.
- Les appels mTLS existants n'ont pas à changer : ils transmettaient déjà les deux dimensions. Les appels HTTP de création de politique peuvent omettre `actionPattern` uniquement pour compatibilité.
- Toute migration ultérieure vers des actions explicites doit être auditée et testée ; aucun élargissement de privilège ne doit être implicite.

## Alternatives envisagées

1. **Ajouter un contrôle d'action uniquement dans la Gateway.** Rejeté : cela dupliquerait l'autorisation dans un service appelant et laisserait les autres consommateurs de `CheckAccess` vulnérables.
2. **Encoder l'action dans `resource_pattern`.** Rejeté : cela fusionnerait deux dimensions distinctes, casserait les ressources existantes et rendrait la politique difficile à comprendre.
3. **Refuser immédiatement toute politique sans action explicite.** Rejeté pour cette migration : les politiques existantes et les clients de création seraient invalidés au déploiement. La compatibilité est conservée par `*`, avec un plan de réduction progressive documenté.
4. **Remplacer le matcher par un moteur glob/regex/ABAC complet.** Rejeté : hors périmètre et plus difficile à auditer. La grammaire exacte + joker final est conservée.

## Validation attendue

- Tests unitaires : ressource seule correspondante refusée, action seule correspondante refusée, double correspondance acceptée, joker final, action vide, refus explicite prioritaire.
- Tests HTTP : `actionPattern` est persisté ; omission legacy devient `*`.
- Tests PostgreSQL : lecture/écriture de `action_pattern`, unicité tenant compte de l'action, migration additive appliquée au démarrage.
- Tests Gateway ADR-0113 : la permission ne passe que si la politique correspond à la fois à `audit:secret-injections:all` et `audit:secret-injections:read` ; une autre action sur la même ressource est refusée.
- Vérifier les tests d'intégration existants et les contrats REST/OpenAPI.
