---
name: go-production-engineering
description: Écrire des services Go de production dans OpenBastion (patron hexagonal, configuration stricte, erreurs, concurrence, modules du go.work) — à utiliser pour tout code Go de services/, pkg/ ou cli/.
---

# Go en production

Règles : `rules/backend-go.md`, `rules/architecture.md`. Patron : `architecture/service-pattern.md`.

## Gestes du dépôt

- `export GOWORK=$PWD/go.work` ; `make build vet` ; les motifs `./...` ne traversent pas les modules : le `Makefile` les liste.
- Un nouveau port : dans `domain/` ; ses deux implémentations (mémoire, PostgreSQL) ; les fakes de test à la main.
- Une nouvelle variable : lue dans `main.go`, défaut strict, bornes, `log.Fatalf` hors bornes, annoncée au démarrage ; ajoutée à `settings/security.yaml` si elle touche la sécurité et au guide Administrateur.
- Une boucle de fond : `time.Ticker` borné, délai par passage (`context.WithTimeout`), arrêt sur le contexte du processus, journal d'une ligne par passage utile.
- `go.sum` : `GOWORK=off GOFLAGS=-mod=mod go mod tidy` dans le module, jamais à la main.

## Pièges déjà rencontrés

- Un magasin mémoire qui rend son propre enregistrement : lire l'ancienne valeur **avant** d'écrire (ADR-0039, journal du ré-épinglage).
- `pkill -f` tue le shell de l'agent : arrêter un processus par son PID.
- `gofmt -w` sur un dossier reformate des fichiers qui ne sont pas à toi.
