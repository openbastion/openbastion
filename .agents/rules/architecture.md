# Règles d'architecture

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

## 1. Couches

La forme d'un service est décrite dans `architecture/service-pattern.md`. Les règles :

1. Dépendances : `interfaces → application → domain` ; `infrastructure → domain` (elle implémente ses ports). `domain` n'importe rien du projet. `cmd/<service>/main.go` est le seul endroit qui connaît tout le monde.
2. Une règle métier dans un handler HTTP ou dans un adaptateur est un défaut : elle va dans `application/`.
3. Ports **petits**, définis côté consommateur (dans `domain/`). Un port n'expose que ce dont le cas d'usage a besoin — l'absence d'une méthode peut être une garantie de sécurité.
4. Chaque magasin a une variante mémoire **et** une variante PostgreSQL, qui tiennent le même contrat ; `DATABASE_URL` choisit.
5. Les clients HTTP vers d'autres services vivent dans `infrastructure/` (champ `Client *http.Client` + `orDefault`), construits pour un pair déclaré (`mtls.Peer`).

## 2. Proxys

6. Le pipeline commun est `pkg/proxycore` (ADR-0006) ; un nouveau protocole n'implémente que son **codec**. Le proxy n'atteint la cible qu'avec un credential obtenu par scope à usage unique, et la clé d'hôte livrée avec (ADR-0039).

## 3. Modules Go et dépendances locales

7. Un module par composant, déclaré dans `go.work`. Un module qui importe `pkg/proxycore` ou `pkg/mtls` déclare `require … v0.0.0` **et** un `replace` explicite vers le chemin relatif (`../../../pkg/mtls`) avec un commentaire en français : en mode workspace, un module qui a aussi des dépendances externes sous `replace` ne résout pas les locaux sans lui.
8. Les motifs `./services/...` **ne traversent pas** les modules du `go.work` : le `Makefile` liste les modules un par un. Un nouveau module s'ajoute à `go.work`, aux listes `build`/`vet`/`test` du `Makefile`, aux `require`/`replace` nécessaires, et à `architecture/repository-layout.md`.

## 4. Décisions structurantes

9. Conçois avant de coder : une décision structurante a son ADR **avant** le code (`tasks/architecture/write-adr.md`).
10. Ajouter, supprimer ou fusionner un microservice, changer le langage d'un composant, rompre un contrat public : **demande** (`AGENTS.md`, « Quand demander »).
