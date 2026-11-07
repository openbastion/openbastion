# Livrer un jalon

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. `git status` : rien de sensible, rien d'inattendu, rien de ce que l'utilisateur a en cours.
2. Commit sur la branche du sujet (`rules/git-workflow.md`), `git push -u origin <branche>`, puis la pull request vers `main` ; vérifie que la branche distante porte ton dernier commit (`git status -sb`). Jamais de push direct sur `main`.
3. Dans le sandbox cloud : archive (`settings/environments/local.yaml`), `unzip -l … | grep -c '\.pem'` = 0, livrée.
4. Rapport (`rules/completion-gates.md` §2) : résultat, preuves mesurées, choix renversables, limites, **une** prochaine étape.
5. Fusion de la PR, tag ou release : seulement sur demande (`policies/release-management.md`).
