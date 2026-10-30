# Test de la pile docker-compose

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Lance-le quand `deploy/`, un `main.go`, une variable d'environnement, la démonstration ou le parcours du MVP change.
2. Dans le codespace, la règle de pare-feu temporaire (autorisée par l'utilisateur) se pose, puis se retire **dans la même commande**, que le test réussisse ou non (`settings/environments/local.yaml`).
3. `make test-compose` ; lis la sortie ; en cas d'échec, les journaux de la pile sont dans la sortie du test.
4. Vérifie après coup que la règle est retirée.
