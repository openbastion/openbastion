# Changer l'Admin UI

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Lis `rules/frontend.md` et le composant concerné ; vérifie que la route publique existe et ce qu'elle rend (OpenAPI).
2. Le composant, ses états (chargement, vide, refus avec code et motif, succès), ses libellés en français ; le geste dangereux dit ce qu'il engage avant d'agir.
3. Tests Vitest avec `fakeApi` : cas heureux, refus, et ce qui ne doit **pas** partir (un geste annulé n'envoie rien ; un secret n'est pas réaffiché).
4. `make ui-test ui-build` ; si la route publique change, son test Gateway et l'OpenAPI.
5. Pour voir l'UI tourner : la prévisualisation Base44 (`settings/environments/local.yaml`).
