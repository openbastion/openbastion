---
name: go-api-security
description: Sécurité des API Go d'OpenBastion (identité par certificat et par jeton, CallerRules, fail-closed, codes honnêtes, secrets, audit avant l'action) — à utiliser pour toute route HTTP, interne ou publique, et tout chemin qui touche un secret.
---

# Sécurité des API Go

Policies : `policies/authorization.md`, `policies/secrets-management.md`, `policies/audit-logging.md`. Contrats : `rules/api-contracts.md`.

## Liste de contrôle d'une route

1. Qui l'appelle ? Règle dans `CallerRules()` + `callers_test.go` (autorisé, refusé, route inconnue).
2. D'où vient l'identité ? `mtls.CallerFrom(ctx)` ou l'identité ajoutée par la Gateway ; le corps ne la donne jamais.
3. Le corps est borné (`MaxBytesReader` / `LimitReader`), la méthode vérifiée, les identifiants validés.
4. L'autorisation est vérifiée par le service lui-même (`CheckAccess`), fail-closed.
5. L'audit qui conditionne l'action est écrit **avant** ; sans audit, rien ne change (`503`).
6. Les codes disent la vérité (`409` pour un état, `503` pour une dépendance) ; aucune cause interne dans la réponse.
7. Aucun secret dans la réponse, l'erreur ou le journal ; un secret en mémoire est purgé.

## Tests attendus

Un test d'attaque par point ci-dessus qui peut être forgé ; son rouge sur l'ancien code ; une mutation par garantie, tuée.
