# ADR-NNNN — Titre : la décision, dite comme une phrase

**Statut** `Proposé` · date · `Accepté` seulement avec le go du propriétaire du projet, cité avec sa date

**Contexte** — Ce qui ne va pas aujourd'hui, mesuré (le test rouge, le chiffre, le comportement observé). Les ADR et invariants que la décision touche.

**Décision**

1. Ce qui change, point par point : le comportement, les contrats (routes, messages, tables), les variables et leurs bornes.
2. Ce qui est refusé, et comment (fail-closed).

**Conséquences**

- (+) Ce qui est **mesuré** : avant (rouge), après (vert), contre-épreuves, mutations tuées.
- (−) **Toutes** les limites : ce que la décision ne fait pas, ce qui reste faux, le coût.

**Alternatives envisagées**

- **Alternative** : pourquoi elle est écartée.
