# ADR-0119 — La vérification de la chaîne d'audit reste réservée à admin-cli

- **Statut :** Retiré — la proposition initiale d'exposer le résultat de `verify-chain` à l'Admin UI est abandonnée.
- **Date :** 18 novembre 2026
- **Décision de référence :** ADR-0028, ADR-0112 et ADR-0113
- **Licence :** AGPL-3.0

## Contexte

Une première proposition envisageait d'exposer à l'Admin UI un statut de vérification de la chaîne d'audit, via une nouvelle route Gateway. Cette proposition confondait deux fonctions qui doivent rester distinctes :

- **Vérifier cryptographiquement la chaîne** (événements, liens, signatures/HMAC, ancres et checkpoints) est une opération d'administration sensible. `GET /audit/v1/verify-chain` reste exclusivement autorisé à l'identité mTLS `admin-cli` par `services/recording-audit/audit-service/internal/interfaces/callers.go`. La Gateway, l'Admin UI et les autres services ne doivent pas recevoir cette capacité.
- **Consulter une projection métier en lecture seule** de métadonnées issues de la chaîne peut être autorisé séparément. C'est déjà défini par ADR-0112 et ADR-0113 pour le rapprochement des injections Vault.

## Décision

1. Ne créer aucune route Gateway qui invoque ou relaie `GET /audit/v1/verify-chain`.
2. Ne pas exposer à l'Admin UI le verdict `verified`, `failed`, les diagnostics de vérification, les détails des ancres/checkpoints ou une preuve qui pourrait être interprétée comme une vérification récente de l'intégrité.
3. Conserver `verify-chain` exclusivement pour `admin-cli` par mTLS. Les tests de `CallerRules` doivent continuer à refuser explicitement `api-gateway` et les identités de services.
4. L'Admin UI peut consulter uniquement les projections de métadonnées explicitement définies par un ADR et protégées par une permission Authorization dédiée. Pour les injections Vault, la référence est ADR-0112/ADR-0113 : `GET /audit/secret-injections` via Gateway, permission `audit:secret-injections:read` sur `audit:secret-injections:all`, réponse sans credential, scope Vault, preuve MFA ni contenu de frappe.
5. La projection ADR-0113 ne constitue pas une preuve d'intégrité générale et ne doit pas être présentée comme telle. Elle fournit les résultats métier corrélés des injections, avec la couverture vérifiée prévue par ADR-0112.
6. Toute nouvelle projection de métadonnées d'audit doit avoir son propre contrat, sa propre analyse de divulgation et sa propre permission. Elle ne doit jamais donner accès indirectement à `verify-chain`.
7. Le Centre de sécurité peut afficher que la vérification de chaîne est réservée à l'outil d'administration, mais ne doit pas afficher un état de santé ou d'intégrité déduit de l'absence d'erreur, de la présence d'ancres ou des métadonnées d'injection.

## Conséquences

- (+) La frontière de confiance `admin-cli` / services / Gateway / navigateur reste explicite.
- (+) L'Admin UI conserve les seules vues de métadonnées dont l'exposition a été explicitement décidée (ADR-0113 pour les injections Vault).
- (+) Aucun nouveau chemin d'accès à la vérification cryptographique n'est créé.
- (−) L'Admin UI ne fournit pas de verdict de vérification de la chaîne ; l'opération reste à effectuer avec `admin-cli`.
- (−) Une future vue de posture devra afficher cette limite sans suggérer que les métadonnées visibles valent vérification cryptographique.

## Vérification du dépôt

Au 18 novembre 2026, les éléments suivants sont présents :

- `GET /audit/v1/verify-chain` et sa règle mTLS exclusivement `admin-cli` dans l'Audit Service ;
- tests `TestCallerRules` qui autorisent `admin-cli` et refusent notamment `api-gateway` pour `verify-chain` ;
- `GET /audit/v1/secret-injections`, accessible à `admin-cli` et `api-gateway` côté Audit Service ;
- façade Gateway `GET /audit/secret-injections`, qui authentifie l'utilisateur, vérifie `audit:secret-injections:read` sur `audit:secret-injections:all`, puis relaie uniquement `limit` et `before` ;
- composant Admin UI `SecretInjectionReconciliation.tsx`, qui consomme cette projection en lecture seule et ne reçoit que les métadonnées définies par ADR-0112.

Cette ADR retire donc la proposition initiale de nouvelle API d'intégrité pour l'Admin UI. Elle ne modifie pas les décisions acceptées ADR-0112 et ADR-0113.
