# Ajouter ou modifier une route interne

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Le contrat : champs (`proto/` et doc 07, identiques ; OpenAPI si public), statut de chaque cas (`rules/api-contracts.md`).
2. Le cas d'usage et le handler ; l'identité de l'appelant vient de `mtls.CallerFrom(ctx)` ou de la Gateway, jamais du corps.
3. La règle dans `CallerRules()` (appelants **minimaux**) et dans `callers_test.go` : autorisé passe, au moins un refusé, route inconnue refusée.
4. Exposée par la Gateway : traduction public → interne dans la Gateway ; seule la partie qui revient au client est reprise de sa requête, l'identité est celle du jeton.
5. Test d'intégration d'attaque : une identité valide **mais fausse** reçoit `403` à la porte, et rien n'a eu lieu.
6. Mettre à jour OpenAPI / doc 07, guide Administrateur (dépannage), `architecture/service-identities.md`.
