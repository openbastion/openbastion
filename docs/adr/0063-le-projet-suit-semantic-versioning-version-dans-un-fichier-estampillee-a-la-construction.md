# ADR-0063 — Le projet suit Semantic Versioning : un fichier `VERSION`, estampillé dans chaque binaire, vérifié par la CI, et un tag `vX.Y.Z` pour chaque release

**Statut** `Accepté` · 1ᵉʳ novembre 2026 · décision de Bony Kiss du 1ᵉʳ novembre 2026 (« renomme les numéros de version en Semantic Versioning : v1.0 → v0.0.1 et v2.0 → v0.0.2 ; intègre le versioning dans le workflow ci-cd ») ; la forme de l'intégration est renversable

**Contexte** — La feuille de route nommait ses jalons « v1.0 » et « v2.0 », mais rien dans le dépôt ne portait de version : pas de fichier, pas de tag (`git tag -l` : aucun), et un binaire ne disait pas ce qu'il était. Un PAM se déploie et s'audite : il faut savoir, d'un journal ou d'une image, quelle version tourne.

**Décision**

1. **Semantic Versioning 2.0.0** (semver.org). Les jalons deviennent : MVP (fait, jamais étiqueté) → **v0.0.1** (ex-« v1.0 », en cours) → **v0.0.2** (ex-« v2.0 »). Le renommage touche toute la documentation, les commentaires du code et des fichiers `proto` — **sauf** les commentaires de migrations déjà appliquées (`001_init.sql` du Broker et de l'Audit Service) : une migration appliquée ne change jamais, son empreinte est vérifiée (ADR-0030).
2. **Le fichier `VERSION`**, à la racine, une ligne, sans « v » : la version que le code construit. Aujourd'hui `0.0.1-dev` — une pré-version de 0.0.1, puisque la 0.0.1 n'est pas finie. `pkg/buildinfo` (stdlib) tient la grammaire de semver.org ; un test refuse un `VERSION` qui ne la suit pas.
3. **Estampillé à la construction** : `make build`, le `Dockerfile` (`ARG VERSION`) et la CI passent `-X github.com/openbastion/openbastion/pkg/buildinfo.Version=…`, qui vaut `VERSION+<commit>` (métadonnée de construction SemVer), ou `VERSION` seul pour une release. Sans estampille (`go run`, `go test`) : `dev`, et le commit que Go a enregistré.
4. **Ce que dit un binaire** : chaque service écrit sa version en **première ligne de son journal** ; `openbastion-cli version` l'affiche. Elle n'est **pas** servie par une route : la publier à qui n'est pas authentifié aiderait à viser une faille connue.
5. **La CI** : un job `version` vérifie `VERSION` à chaque commit ; le workflow tourne aussi sur les tags `v*`, et sur un tag le job exige que le tag soit `v` + `VERSION` **et** que ce soit une release (ni pré-version ni métadonnée) ; l'image construite par le job `images` porte alors la version de la release, et `make scan-images` vérifie que l'image dit bien la version qu'on lui a donnée.
6. **Un tag reste un geste du propriétaire** (policy de livraison, point 4) : le dépôt dit comment, la CI vérifie, personne d'autre n'en pose. Pour publier 0.0.1 : changer `VERSION` en `0.0.1`, commiter, puis `git tag v0.0.1 && git push origin v0.0.1` ; après la release, `VERSION` passe à `0.0.2-dev`.

**Conséquences**

- (+) **Mesuré** : `make version` → `0.0.1-dev+91e3a1ed269d` ; `make version-check` accepte `VERSION`, refuse un tag `v0.0.1` quand `VERSION` dit `0.0.1-dev`, refuse un tag de pré-version, accepte `v0.0.1` quand `VERSION` dit `0.0.1` ; l'image dit `0.0.1-dev+91e3a1ed269d` ; un service estampillé l'écrit en première ligne, la CLI l'affiche, un binaire sans estampille dit `dev`. La grammaire (`pkg/buildinfo`, 3 tests) : sept versions acceptées, treize refusées (dont `v0.0.1`, `0.0`, `01.0.0`, `0.0.1-01`).
- (−) **En 0.y.z, SemVer ne promet rien** (« anything MAY change at any time ») : la compatibilité des contrats reste tenue par leurs propres règles (`/api/v1`, test de contrat, ADR-0050), pas par le numéro.
- (−) Les jalons deviennent des versions de **correctif** (0.0.1, 0.0.2) : c'est le choix demandé ; la prochaine version mineure (0.1.0) n'a pas encore de sens attribué.
- (−) Pas de `CHANGELOG.md`, pas de release GitHub ni d'artefact publié par la CI : un tag est vérifié et construit, rien n'est publié. Les notes de version sont les messages de commit et les ADR.
- (−) Le module `pkg/buildinfo` est un module de plus dans `go.work` et dans neuf `go.mod` (le patron de `pkg/mtls`).
- (−) Les images du bac à sable Base44 (`go run`) disent `dev`.

**Alternatives envisagées**

- **La version tirée du dernier tag** (`git describe`) : aucun tag n'existe, et une construction sans `.git` (le contexte Docker l'exclut) ne saurait rien ; un fichier se lit partout.
- **Une route `GET /version`** : utile au support, mais un renseignement offert à qui n'est pas authentifié ; le journal et la CLI suffisent.
- **Une version par module Go** (`pkg/mtls/v0.x`) : les modules ne se publient pas séparément ; une seule version pour le produit.
- **Créer les releases dans la CI à chaque tag** (artefacts, notes) : publier est un geste du propriétaire ; à ajouter quand il le demandera.
