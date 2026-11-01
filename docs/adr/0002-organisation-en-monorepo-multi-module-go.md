# ADR-0002 — Organisation en monorepo multi-module Go


**Contexte**
L'architecture comporte ~35 microservices dont les contrats gRPC bougeront fréquemment pendant la phase pré-v0.0.1. Un multi-repo imposerait une coordination de versions de contrats dès le premier jour.

**Décision**
Un seul dépôt Git, avec un `go.mod` par service (`go.work` en racine) — monorepo au niveau du dépôt, modules isolés au niveau Go.

**Conséquences**
- (+) Refactoring cross-service atomique (un commit peut modifier un contrat `proto/` et tous ses consommateurs).
- (+) CI et revue de code centralisées.
- (+) Extraction future d'un service vers un dépôt indépendant possible sans réécriture, grâce à l'isolation des modules Go.
- (−) Nécessite un outillage CI sélectif par chemins modifiés pour éviter de reconstruire les 35 services à chaque commit.

**Alternatives envisagées**
- *Multi-repo dès le départ* : rejeté pour la phase actuelle — coût de coordination des contrats jugé trop élevé tant que l'architecture n'est pas stabilisée en v0.0.1.
