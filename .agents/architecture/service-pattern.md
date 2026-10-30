# Le patron d'un service (Clean Architecture)

Chaque service Go a la même forme. Les règles qui en découlent sont dans `rules/architecture.md`.

```
services/<domaine>/<service>/
  go.mod                         module propre (+ replace locaux vers pkg/…, voir `rules/architecture.md` §3)
  cmd/<service>/main.go          composition : lit l'environnement, construit les adaptateurs, démarre
  internal/
    domain/                      entités + PORTS (interfaces de dépôt/clients). Aucune dépendance externe.
    application/                 cas d'usage. Dépend du domaine seulement. Toute la logique métier est ici.
    infrastructure/              adaptateurs : magasin mémoire, magasin PostgreSQL (migrations par pkg/migrate),
                                 clients HTTP vers les autres services (champ Client *http.Client + orDefault)
    interfaces/
      http.go                    handlers HTTP/JSON (remplaçant de gRPC, voir §6) ; aucune règle métier
      callers.go                 CallerRules() : qui peut appeler quelle route (mTLS)
```

Règles de dépendance : `interfaces → application → domain` ; `infrastructure → domain` (elle implémente ses ports). `domain` n'importe rien du projet. `main.go` est le seul endroit qui connaît tout le monde. Une règle métier dans un handler HTTP ou dans un adaptateur est un défaut.
