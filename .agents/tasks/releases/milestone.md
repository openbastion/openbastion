# Livrer un jalon

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. `git status` : rien de sensible, rien d'inattendu, rien de ce que l'utilisateur a en cours.
2. Commit (`rules/git-workflow.md`), `git push origin main`, et vérifie que `main` et `origin/main` coïncident.
3. Dans le sandbox cloud : archive (`settings/environments/local.yaml`), `unzip -l … | grep -c '\.pem'` = 0, livrée.
4. Rapport (`rules/completion-gates.md` §2) : résultat, preuves mesurées, choix renversables, limites, **une** prochaine étape.
5. Tag, release ou PR : seulement sur demande (`policies/release-management.md`).
