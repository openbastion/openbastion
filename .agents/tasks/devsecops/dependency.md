# Ajouter ou modifier une dépendance

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. **Demande** (`policies/dependencies-and-supply-chain.md`) : besoin, licence, maintenance, alternative stdlib écartée, empreinte.
2. Vérifie qu'elle se résout dans l'environnement avant de t'engager ; sinon propose le contournement connu (`replace` vers le miroir GitHub) ou l'alternative.
3. Un module à la fois ; `go.sum` régénéré par l'outil (`GOWORK=off GOFLAGS=-mod=mod go mod tidy`) ; jamais dans un paquet stdlib seulement. Côté UI : `npm install --save-exact` puis lockfile commité.
4. Une dépendance de test reste dans le module de test.
