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
openbastion-cli version                        # diagnostic complet de la CLI opérateur
openbastion-cli version --short                # version seule, pour les scripts
openbastion-cli --help                         # commandes et options disponibles
openbastion-pki version --short                # même contrat pour l'outil PKI
api-gateway version --short                    # même contrat pour chaque service
docker run --rm --entrypoint /usr/local/bin/openbastion-cli openbastion:dev version   # celle d'une image
```

Les douze exécutables de production (CLI opérateur, PKI et dix services) exposent `version` et `version --short`. Pour les dix services, l'absence de sous-commande démarre le service comme avant ; la commande `version` quitte avant toute initialisation réseau, base, mTLS, Vault ou Recorder. L'outil PKI conserve `init`, `issue`, `all` et les options historiques à tiret simple.

Chaque service l'écrit en **première ligne de son journal** (`authentication 0.0.1-dev+3f776b5c1a2b`). Elle n'est servie par aucune route.

## Publier une version

Le propriétaire du projet seul pose un tag. La CI vérifie qu'il nomme `VERSION`, sans pré-version :

```sh
printf '0.0.1\n' > VERSION && git commit -am "release: 0.0.1"   # avec les lignes d'attribution
git tag v0.0.1 && git push origin main v0.0.1                   # le workflow tourne sur le tag
printf '0.0.2-dev\n' > VERSION && git commit -am "chore: 0.0.2-dev"
```

`make version-check TAG=v0.0.1` fait la même vérification en local.
