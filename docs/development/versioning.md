# Versions (ADR-0063)

OpenBastion suit [Semantic Versioning 2.0.0](https://semver.org). La version que le code construit est dans le fichier [`VERSION`](../../VERSION), à la racine : une ligne, sans « v ».

| Jalon | Version | État |
|---|---|---|
| MVP | — (jamais étiqueté) | fait |
| v0.0.1 | `0.0.1` | en cours — `VERSION` vaut `0.0.1-dev` |
| v0.0.2 | `0.0.2` | à concevoir |

## Ce qu'un binaire dit de lui

```sh
make version                                   # la version qu'une construction estampille : 0.0.1-dev+<commit>
openbastion-cli version                        # celle de la CLI
docker run --rm --entrypoint /usr/local/bin/openbastion-cli openbastion:dev version   # celle d'une image
```

Chaque service l'écrit en **première ligne de son journal** (`authentication 0.0.1-dev+3f776b5c1a2b`). Elle n'est servie par aucune route.

## Publier une version

Le propriétaire du projet seul pose un tag. La CI vérifie qu'il nomme `VERSION`, sans pré-version :

```sh
printf '0.0.1\n' > VERSION && git commit -am "release: 0.0.1"   # avec les lignes d'attribution
git tag v0.0.1 && git push origin main v0.0.1                   # le workflow tourne sur le tag
printf '0.0.2-dev\n' > VERSION && git commit -am "chore: 0.0.2-dev"
```

`make version-check TAG=v0.0.1` fait la même vérification en local.
