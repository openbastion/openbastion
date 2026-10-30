# Portes de fin : « terminé » et rapport

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

## 1. Un travail est terminé quand tout ceci est vrai

1. Le code compile (`make build`), `go vet` est propre, les fichiers modifiés sont formatés ; l'UI touchée passe `make ui-test ui-build`.
2. Chaque comportement nouveau a un test ; chaque garantie de sécurité a un test d'attaque, un rouge mesuré sur l'ancien code quand c'est possible, et des mutations toutes tuées.
3. Les tests des modules touchés passent, `-race` propre ; avant un jalon, les suites complètes passent (`settings/quality-gates.yaml`).
4. La documentation est à jour **dans le même commit**, les chiffres mesurés (`rules/documentation.md`).
5. Les limites laissées sont écrites (`NOTES_SANDBOX.md`, Guide Sécurité §12).
6. Le commit est fait **et poussé** ; aucun fichier sensible ; rien de ce que l'utilisateur avait en cours n'y est entré sans demande.
7. Le rapport suit §2.

## 2. Le rapport à l'utilisateur

1. **BLUF** : première phrase = le résultat. Puis ce qui est prouvé (chiffres mesurés), les **choix renversables**, les **limites restantes**, **une** prochaine étape.
2. En français, prose concise ; une liste seulement quand le lecteur compare ou parcourt. Pas de récit chronologique, pas de recopie du code, pas d'émojis.
3. Ce que tu n'as pas fait ou pas pu vérifier est dit, avec la raison.
