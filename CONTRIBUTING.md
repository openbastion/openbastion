# Contribuer à OpenBastion

Merci de contribuer à OpenBastion. Ce projet est publié sous GNU AGPL-3.0-only. Toute contribution acceptée est proposée sous cette même licence, conformément aux conditions du dépôt.

## Developer Certificate of Origin (DCO)

OpenBastion applique le **Developer Certificate of Origin (DCO) version 1.1**. Le texte intégral est disponible dans [`DCO`](DCO) et sur <https://developercertificate.org/>.

Chaque commit d'une Pull Request doit contenir un trailer `Signed-off-by` attestant que son auteur est autorisé à soumettre cette contribution. Le nom et l'adresse e-mail du trailer doivent correspondre à l'identité d'auteur du commit. Le DCO n'est ni un CLA ni une cession de droits : vous conservez vos droits d'auteur.

### Configurer Git

Configurez l'identité que vous utilisez pour vos commits :

```sh
git config user.name "Prénom Nom"
git config user.email "adresse@example.org"
```

Utilisez ensuite `-s` pour ajouter automatiquement le trailer :

```sh
git commit -s -m "feat(component): describe the change"
```

Le message du commit doit se terminer par une ligne de cette forme :

```text
Signed-off-by: Prénom Nom <adresse@example.org>
```

### Vérifier les commits avant de pousser

Pour vérifier tous les commits de votre branche par rapport à `main` :

```sh
git fetch origin main
git log --format='%h %s%n%(trailers:key=Signed-off-by)' origin/main..HEAD
```

Chaque commit non-fusion doit afficher un trailer `Signed-off-by` correspondant à son auteur. La vérification DCO est exécutée sur chaque Pull Request par l'application DCO2. Pour rendre ce contrôle bloquant avant fusion, les propriétaires du dépôt doivent également rendre le statut DCO2 obligatoire dans les règles de protection de la branche `main`.

### Corriger un commit sans sign-off

Si le commit n'a pas encore été publié, vous pouvez le corriger sans créer un nouveau commit :

```sh
git commit --amend --signoff --no-edit
```

Si le commit a déjà été poussé ou partagé, évitez de réécrire l'historique sans coordination. L'application DCO2 autorise une remédiation individuelle : l'auteur du commit doit créer lui-même un commit de remédiation signé, en suivant le format indiqué par DCO2. Par exemple :

```text
DCO remediation commit for Prénom Nom <adresse@example.org>

I, Prénom Nom <adresse@example.org>, hereby add my Signed-off-by to this commit: <COMMIT_SHA>

Signed-off-by: Prénom Nom <adresse@example.org>
```

Un tiers ne peut pas signer à la place de l'auteur.

## Pull Requests

- Créez une branche dédiée à votre changement ; ne poussez pas directement sur `main`.
- Décrivez le problème traité, la solution retenue et les éventuelles conséquences de sécurité.
- Ajoutez ou adaptez les tests et la documentation pertinents.
- Exécutez les contrôles locaux adaptés au changement et indiquez clairement ceux qui n'ont pas pu être exécutés.
- Gardez les changements ciblés et évitez de mélanger refactoring sans rapport et correction fonctionnelle.
- N'incluez aucun secret, identifiant, donnée personnelle ou artefact de production.
- Signalez toute vulnérabilité de sécurité via le canal privé publié par les mainteneurs, plutôt que dans une issue publique.

## Licence des contributions

En soumettant une contribution, vous certifiez au moyen du DCO que vous avez le droit de la soumettre sous la licence du projet. Les contributions acceptées sont distribuées sous **GNU AGPL-3.0-only**. Les dépendances et contenus tiers conservent leurs licences et notices respectives.

Aucun Contributor License Agreement (CLA) n'est demandé. Aucune cession de droits d'auteur à OpenBastion n'est exigée.
