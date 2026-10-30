# Nouvelle fonctionnalité

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. **Explorer** : le code existant, les ADR liés, les docs 05/06/07 ; ce qui existe déjà (ne réinvente pas). La liste des invariants touchés (`architecture/invariants.md`).
2. **Concevoir avant de coder** : modèle d'attaque (qui peut abuser de quoi), contrats (OpenAPI, `proto/`, tables), **ADR** (`write-adr.md`) avec les alternatives écartées. Pas de code avant l'ADR.
3. **Tâches** : la liste, dernière tâche « vérifier ».
4. **Implémenter couche par couche** : domaine (entités, ports, erreurs) → application (cas d'usage) → infrastructure (magasin mémoire **et** PostgreSQL, clients) → interfaces (handlers, `callers.go`) → `main.go` (composition, variables d'environnement à défaut strict) → Gateway et Admin UI si exposé.
5. **Tester** : unitaires par couche ; chaque verrou isolément (un verrou manquant ⇒ refus) ; PostgreSQL (aller-retour + mise à niveau) ; **processus réels** pour le parcours complet et l'attaque.
6. **Rouge avant** : l'attaque mesurée sur le commit précédent (`git worktree`).
7. **Contre-épreuves** : mutations sur chaque garantie, toutes tuées (`rules/testing.md` §4).
8. **Documenter** (`rules/documentation.md` §3), y compris les fichiers de `.agents/` que le changement rend faux.
9. **Vérifier** : `../releases/full-verification.md`.
10. **Livrer** : `../releases/milestone.md`.
