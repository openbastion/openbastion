# Contrats de confiance de la chaîne de livraison

**Référence :** ADR-0094 · **Version du contrat :** `1.2.0` · **Statut :** phase B en cours
**Portée :** contrat de phase B en cours d'implémentation ; les attestations GitHub ne seront émises que lors d'un tag de confiance. Aucun artefact OCI n'est publié et aucune vérification d'admission n'est activée.

Ce document fixe les contrats des phases B à E. La phase B utilise les attestations d'artefacts GitHub sur une archive Docker exportée (`docker save`) ; elle ne prétend pas attester un digest de manifeste OCI. Le digest OCI ne sera attesté qu'après une décision explicite de publication et l'existence d'un artefact OCI distribué. Les exemples sont des fragments illustratifs, jamais des preuves valides. Les valeurs entre chevrons sont des placeholders et doivent être remplacées par des valeurs observées et vérifiées ; elles ne doivent jamais être acceptées par un vérificateur.

## 1. Invariants

1. L'identité d'un artefact est son digest cryptographique, jamais son tag OCI seul.
2. Chaque attestation a un sujet `in-toto Statement` qui identifie exactement l'artefact auquel elle se rapporte.
3. Le commit source, le dépôt, le workflow appelant, le workflow réutilisable et le builder sont vérifiables et doivent correspondre à une politique de confiance explicite.
4. Les événements `pull_request`, `schedule`, `workflow_dispatch` et les builds de forks ne sont jamais des émetteurs de preuves de livraison de confiance.
5. Aucun secret, jeton, contenu de variable secrète, credential ou donnée sensible ne peut apparaître dans les paramètres, matériaux, sujets, attestations ou journaux.
6. Toute propriété requise absente, ambiguë, mal formée ou non vérifiable entraîne un refus (`fail-closed`).
7. Une signature valide ne rend pas un artefact conforme si sa provenance, son SBOM ou les politiques de vulnérabilités/licences échouent.
8. Ces contrats n'accordent aucune permission GitHub Actions et ne créent aucun droit de publication. ADR-0063 reste applicable.

## 2. Contrat de provenance in-toto / SLSA

### 2.1 Enveloppe et types

| Élément | Valeur contractuelle |
|---|---|
| Enveloppe | in-toto Statement v1 |
| `_type` | `https://in-toto.io/Statement/v1` |
| `predicateType` | `https://slsa.dev/provenance/v1` |
| Prédicat | SLSA Provenance v1.0 |
| Digest de sujet | `sha256` obligatoire ; digest de fichier pour l'archive Docker en phase B, digest de manifeste OCI uniquement pour un artefact OCI distribué dans une phase ultérieure |
| Encodage | JSON UTF-8 ; les clés et structures sont validées, pas seulement la syntaxe JSON |

### 2.2 Sujet (`subject`)

- Le tableau `subject` contient une entrée par artefact attesté.
- `name` est un nom stable et non ambigu de l'artefact (référence OCI canonique sans tag mutable, ou identifiant de distribution documenté).
- En phase B, `subject-path` désigne `openbastion-runtime-image.tar.gz`, archive produite par `docker save` puis compressée avec `gzip -n`. `digest.sha256` est le SHA-256 exact de ce fichier, calculé par l'action d'attestation.
- Le SBOM runtime CycloneDX décrit l'image contenue dans cette archive ; son attestation SBOM a pour sujet le même fichier archive.
- Les valeurs `sha256` doivent être des chaînes hexadécimales de 64 caractères minuscules.
- Le nom de sujet de phase B identifie explicitement une archive Docker et ne doit jamais être interprété comme une référence OCI ou un digest de manifeste.
- Un digest de config Docker, un digest de couche ou le digest de l'archive ne se substitue pas au digest du manifeste OCI lors d'une future distribution OCI. La phase C devra établir ce digest depuis le registre et signer/attester le manifeste exact.

### 2.3 Prédicat SLSA v1

Le vérificateur exige les champs suivants, selon les structures SLSA Provenance v1 :

| Chemin | Exigence |
|---|---|
| `buildDefinition.buildType` | URI stable identifiant le processus de build OpenBastion versionné ; la valeur exacte sera enregistrée avec l'implémentation B et ne pourra pas être changée silencieusement |
| `buildDefinition.externalParameters` | Événement, dépôt, référence/tag, SHA source et paramètres de build non secrets qui influencent le résultat |
| `buildDefinition.resolvedDependencies` | Dépendances/matériaux effectivement résolus, avec URI et digest quand disponibles ; inclure les images de base par digest et les fichiers de verrouillage pertinents |
| `runDetails.builder.id` | Identifiant stable du builder de confiance, pas un simple nom d'hôte de runner éphémère |
| `runDetails.metadata.invocationId` | Identifiant unique de l'exécution CI |
| `runDetails.metadata.startedOn` / `finishedOn` | Horodatages RFC 3339 cohérents, `finishedOn` postérieur à `startedOn` |
| `runDetails.byproducts` | Facultatif ; aucune donnée secrète ou sortie brute contenant des secrets |

Les paramètres internes du builder, lorsqu'ils existent, ne doivent pas être confondus avec des paramètres externes contrôlés par l'appelant. Les champs optionnels non requis par SLSA ne sont pas inventés. Le vérificateur valide la version de schéma et rejette les propriétés critiques inconnues si elles peuvent changer le sens d'une décision de confiance.

### 2.4 Provenance source et événements admissibles

Pour une preuve de livraison, les conditions cumulatives sont :

- dépôt canonique : `openbastion/openbastion` (`repository_id=1405264581`, `repository_owner_id=322037689`) ;
- workflow appelant : `.github/workflows/supply-chain-attestations.yml` ;
- événement GitHub : `push` d'un tag strict `vMAJOR.MINOR.PATCH` ;
- acteur du push : compte propriétaire `eldorplus` uniquement (contrôle explicite avant checkout et avant le job d'attestation) ;
- le job de validation exécute `make version-check TAG=...` et exige que le commit du tag soit ancêtre de `origin/main` ; le job de build réitère les contrôles du dépôt, des IDs, de l'événement, du format du tag et du chemin du workflow appelant avant toute attestation ;
- tag SemVer conforme à ADR-0063 et égal à la version du fichier `VERSION` ;
- commit tagué présent dans l'historique de `main` au moment de la vérification ;
- SHA source complet et identique entre le contexte GitHub, la provenance et le commit du tag ;
- workflow réutilisable qui construit et analyse l'image : `.github/workflows/containers.yml` ;
- `.github/workflows/ci.yml` continue d'exécuter les contrôles CI sur les tags, mais ne reçoit aucun droit OIDC ni droit d'attestation.
- les deux révisions de workflow sont identifiables ; le workflow réutilisable est lui aussi issu du dépôt canonique et de la révision attendue.

Un `push` sur `main` peut exécuter les contrôles CI, mais ne constitue pas à lui seul une source de preuve de livraison. Les builds PR, forks, exécutions planifiées et exécutions manuelles sont hors de la politique d'émission de livraison.

## 3. Contrat d'identité GitHub Actions / OIDC

### 3.1 Émetteur et identité

| Attribut | Valeur ou règle attendue |
|---|---|
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Audience | Audience attendue par GitHub Artifact Attestations/Sigstore ; sa valeur exacte doit être extraite du bundle réel et épinglée dans les tests de vérification ; jamais `*` |
| Dépôt | `openbastion/openbastion`, comparé aussi via `repository_id` (`1405264581`) et `repository_owner_id` (`322037689`), relevés sur le dépôt canonique pendant la phase A |
| Workflow appelant (`workflow_ref`) | `openbastion/openbastion/.github/workflows/supply-chain-attestations.yml@refs/tags/vX.Y.Z` |
| Workflow réutilisable (`job_workflow_ref`) | `openbastion/openbastion/.github/workflows/containers.yml@refs/tags/vX.Y.Z`, vérifié via les claims signés |
| Référence de confiance | `refs/tags/vMAJOR.MINOR.PATCH`, validée par SemVer et par l'historique `main` |
| Événement | `push` uniquement pour l'émission de preuves de livraison |
| Fork | Toujours refusé |

L'identité de certificat Sigstore/Cosign et les claims OIDC de GitHub sont deux contrôles complémentaires. Le vérificateur doit comparer l'identité de certificat exacte (issuer + identité SAN attendue) et les claims signés de l'attestation. Il ne doit pas déduire l'identité d'un simple nom de workflow fourni dans un champ libre.

### 3.2 Claims à contrôler

Les claims suivants doivent être vérifiés lorsqu'ils sont présents dans le certificat ou dans les extensions/attestations signées. Les identifiants numériques ont été relevés sur l'API du dépôt canonique le 10 novembre 2026 : `repository_id=1405264581` et `repository_owner_id=322037689`. Ils doivent être comparés à ces constantes dans la politique ; les noms seuls ne protègent pas contre un changement de propriétaire ou une réutilisation de nom. Toute migration de dépôt ou de propriétaire exige une révision explicite de la politique.

- `iss` : issuer exact ci-dessus ;
- `aud` : audience GitHub Artifact Attestations/Sigstore exacte, à relever dans le premier bundle et à épingler dans les tests ;
- `repository` : `openbastion/openbastion` ;
- `repository_id` : `1405264581` ;
- `repository_owner_id` : `322037689` ;
- `event_name` : `push` ;
- `ref` : tag `refs/tags/vX.Y.Z` ;
- `sha` : SHA complet du commit source ;
- `workflow_ref` et `workflow_sha` : identité et révision du workflow appelant ;
- `job_workflow_ref` et `job_workflow_sha` : claims complémentaires à contrôler s'ils sont présents ; ils ne sont pas exigés pour le job d'attestation, qui est un job normal du workflow appelant et non un job exécuté dans le workflow réutilisable ;
- `runner_environment` : information complémentaire de politique, jamais preuve suffisante à elle seule.

Le vérificateur échoue si un claim requis manque, a un format inattendu, ou contredit un autre claim. Il ne doit pas accepter de wildcard sur le dépôt, la référence, le chemin de workflow, l'émetteur ou l'audience.

### 3.3 Identité de certificat attendue

La valeur SAN exacte produite par Sigstore dépend du mécanisme d'émission retenu et de la façon dont GitHub représente le workflow appelant/réutilisable. La phase B devra capturer un certificat réel depuis un build de test autorisé et écrire sa valeur littérale dans les tests et la politique. Il est interdit de deviner cette chaîne ou d'utiliser une expression régulière large pour la remplacer. Les deux chemins de workflow (appelant et réutilisable) doivent rester vérifiables ; toute ambiguïté doit bloquer la migration.

## 4. Contrat SBOM CycloneDX

### 4.1 Format

- Format de référence : CycloneDX JSON.
- Le SBOM doit être valide selon le schéma CycloneDX correspondant à sa propriété `specVersion`. Le schéma officiel CycloneDX 1.7 est versionné localement sous `third_party/cyclonedx/1.7/`, avec sa révision amont, sa licence et son SHA-256, ainsi que les trois schémas auxquels il renvoie (`spdx`, `cryptography-defs`, `jsf-0.82`), de la même révision. Toute référence se résout depuis ces fichiers, jamais par le réseau : une référence à un autre schéma entraîne un refus. Le validateur applique d’abord les invariants OpenBastion, puis le JSON Schema Draft 7 complet avec contrôle des formats (`jsonschema[format]`). Toute erreur de schéma ou de format entraîne un refus.
- Trivy `0.76.1`, téléchargé et vérifié par SHA-256, a produit `specVersion: "1.7"` lors d'un scan source réel le 10 novembre 2026. La génération runtime n'a pas encore été exécutée sur un runner GitHub ; la CI doit vérifier explicitement `bomFormat`, `specVersion`, `serialNumber`, `version`, `metadata` et `components` avant l'attestation.
- La version de schéma contractuelle est `1.7`. Toute mise à jour de Trivy qui change ce champ exige une modification explicite du contrat et de ses tests.
- Le document doit inclure `bomFormat: "CycloneDX"`, `specVersion`, `serialNumber` et `version` conformément au schéma choisi.
- Le SBOM source et chaque SBOM runtime sont des objets distincts. Ils ne doivent pas être présentés comme interchangeables.

### 4.2 Liaison à l'artefact

Le SBOM runtime de phase B est transporté comme attestation in-toto dont :

- `subject` identifie le digest SHA-256 du fichier `openbastion-runtime-image.tar.gz` qui contient l'image runtime exportée ;
- `predicateType` utilise le type CycloneDX retenu par l'implémentation, `https://cyclonedx.org/bom` ;
- `predicate` contient le document CycloneDX complet ;
- l'attestation est authentifiée par la même chaîne de confiance que la provenance, ou par une identité explicitement autorisée et documentée.

Le vérificateur valide le schéma CycloneDX, le sujet, le type de prédicat et l'identité de l'émetteur. Il rejette les SBOM sans sujet, avec plusieurs sujets ambigus, ou dont le digest ne correspond pas au fichier archive demandé. Cette liaison prouve quel SBOM a été attesté avec quelle archive ; elle ne prouve pas encore l'identité d'un manifeste OCI publié.

Le SBOM source actuel n'est pas un SBOM runtime et n'est pas lié à un digest d'image. Il reste un rapport de composition du checkout jusqu'à ce qu'une décision d'implémentation précise son sujet (par exemple un artefact source archivé avec digest). Ne pas lui attribuer artificiellement le digest de l'image runtime.

## 5. Contrat de vérification

### 5.1 Entrées

Le vérificateur reçoit explicitement :

1. la référence OCI demandée et son digest attendu ;
2. la signature/bundle Sigstore associé au digest ;
3. l'attestation de provenance ;
4. l'attestation SBOM ;
5. la politique de confiance versionnée ;
6. les résultats ou attestations de contrôles vulnérabilités/licences correspondant au même artefact, selon le contrat d'implémentation.

Il ne découvre pas une identité de confiance par une recherche permissive sur le registre.

### 5.2 Ordre des décisions

1. Résoudre la référence en digest OCI immuable ; refuser les références tag-only à l'entrée de la politique d'admission.
2. Vérifier signature, bundle, certificat, issuer, audience et identité SAN exacte.
3. Vérifier l'enveloppe in-toto et le sujet : digest attendu exact.
4. Vérifier la provenance SLSA, le dépôt, les IDs de dépôt, le SHA, le tag, les workflows, leurs révisions, l'événement et les matériaux requis.
5. Vérifier le SBOM CycloneDX, son schéma et son sujet exact.
6. Vérifier les décisions vulnérabilités/licences et leurs durées de validité.
7. N'autoriser que si toutes les vérifications obligatoires réussissent.

Une preuve expirée, révoquée, indisponible, incomplète, non authentifiée ou non liée au digest entraîne un refus. Les règles de fraîcheur et de révocation détaillées (certificat, bundle, transparence, attestations) seront définies avant la phase C/D, sans affaiblir la décision fail-closed.

### 5.3 Résultat machine

Le vérificateur expose un résultat structuré, indépendant du moteur d'admission :

```json
{
  "decision": "allow | deny",
  "subject": {
    "name": "registry.example/openbastion@sha256:<64-hex>",
    "digest": "sha256:<64-hex>"
  },
  "policyVersion": "1.0.0",
  "checks": [
    { "id": "signature", "status": "pass | fail | error" },
    { "id": "identity", "status": "pass | fail | error" },
    { "id": "provenance", "status": "pass | fail | error" },
    { "id": "sbom", "status": "pass | fail | error" },
    { "id": "vulnerability-policy", "status": "pass | fail | error" },
    { "id": "license-policy", "status": "pass | fail | error" }
  ]
}
```

`allow` est possible uniquement si tous les contrôles requis sont `pass`. `error` n'est jamais assimilé à `pass`. Le résultat ne contient aucun secret ni contenu complet d'attestation.

## 6. Matrice minimale de tests négatifs

Les tests sont des fixtures synthétiques ou des preuves de test non productives. Les tests ne doivent pas utiliser de clés privées de production.

| ID | Mutation / scénario | Résultat attendu |
|---|---|---|
| SC-001 | Digest du sujet différent du digest demandé | Refus |
| SC-002 | Tag OCI identique mais manifeste/digest différent | Refus |
| SC-003 | Signature absente ou invalide | Refus |
| SC-004 | Issuer OIDC différent | Refus |
| SC-005 | Audience absente ou différente | Refus |
| SC-006 | Identité SAN issue d'un fork | Refus |
| SC-007 | Dépôt ou IDs dépôt/propriétaire différents | Refus |
| SC-008 | Workflow appelant non autorisé ou chemin modifié | Refus |
| SC-009 | Workflow réutilisable non autorisé ou révision non attendue | Refus |
| SC-010 | `event_name` égal à `pull_request`, `schedule` ou `workflow_dispatch` | Refus |
| SC-011 | Référence branche `main` au lieu d'un tag SemVer | Refus comme preuve de livraison |
| SC-012 | SHA de provenance différent du commit du tag | Refus |
| SC-013 | Tag absent de l'historique `main` ou VERSION incohérente | Refus |
| SC-014 | Matériau requis absent ou digest de base incohérent | Refus |
| SC-015 | Mauvais `predicateType` ou version de schéma non autorisée | Refus |
| SC-016 | JSON tronqué, champ obligatoire absent ou type incorrect | Refus |
| SC-017 | SBOM CycloneDX invalide selon son schéma | Refus |
| SC-018 | SBOM lié à un autre digest | Refus |
| SC-019 | Rapport de vulnérabilités ou licences absent, expiré ou en échec | Refus |
| SC-020 | Bundle/transparence requis indisponible ou non vérifiable | Refus |
| SC-021 | Claim requis manquant ou claims contradictoires | Refus |
| SC-022 | Paramètres ou attestation contenant une valeur secrète de fixture | Échec du contrôle de fuite ; aucune preuve publiée |
| SC-023 | Vérificateur renvoie `error` pour un contrôle obligatoire | Refus |
| SC-024 | Référence tag-only sans digest résolu | Refus |

Tests positifs complémentaires : artefact et digest concordants, signature émise par l'identité de confiance, provenance d'un tag valide issu de `main`, SBOM valide lié au même digest et politiques vulnérabilités/licences satisfaites. Les fixtures positives ne doivent pas dépendre d'une preuve active dans le registre public.

## 7. État observé du dépôt au début de la phase A et mise en œuvre B

- `.github/workflows/ci.yml` est le workflow appelant ; il déclenche CI sur `push` de `main`, `push` de tags `v*`, `pull_request` et `schedule`.
- `.github/workflows/containers.yml` est un workflow réutilisable (`workflow_call`) limité à `contents: read`. Il construit, analyse et téléverse les fichiers nécessaires. Le workflow tag dédié consomme cet artefact dans un job séparé qui possède seul `id-token: write`, `attestations: write` et `artifact-metadata: write`.
- `containers.yml` utilise Trivy `0.76.1`, vérifié par SHA-256, produit un SBOM source et un SBOM de l'image locale `openbastion:scan`, plus un inventaire de licences. Le SBOM source observé est CycloneDX `1.7` (validation locale sur Trivy `0.76.1`, le 10 novembre 2026) ; la même version est imposée au SBOM runtime par le validateur CI, mais reste à confirmer sur un vrai run GitHub.
- Les rapports sont téléversés comme artefacts GitHub pour 30 jours. Lorsqu'un tag de confiance déclenchera le nouveau workflow, l'archive runtime `docker save` sera ajoutée au même artefact ; un job séparé la téléchargera et l'attestera via GitHub Artifact Attestations.
- `make scan-images` construit localement l'image runtime `openbastion:scan` et l'image PostgreSQL `openbastion-postgres:scan`, les scanne, mais ne les publie pas dans un registre.
- Le workflow CI historique ne produit pas de digest de manifeste OCI destiné à la livraison. La phase B exporte l'image runtime vers une archive fichier et atteste son SHA-256 ; ce digest n'est pas un digest de manifeste OCI.
- Le SBOM PostgreSQL n'est pas actuellement généré dans `containers.yml`.

Ces observations sont un état initial, pas une promesse de comportement futur. La phase C devra définir précisément comment obtenir et attester le digest de manifeste OCI lorsqu'une publication sera explicitement autorisée.

## 8. Critères de sortie des phases A et B

- [x] Types de provenance et d'attestation définis.
- [x] Sujet et règles de digest définis.
- [x] Dépôt, événements et workflows de confiance identifiés.
- [x] Claims OIDC requis et limites de l'identité SAN documentés.
- [x] Format SBOM et règles de liaison au digest définis.
- [x] Décision fail-closed et format de résultat définis.
- [x] Jeux de tests négatifs documentés.
- [x] État réel des workflows et des SBOM de départ documenté.
- [x] Valeurs numériques `repository_id=1405264581` et `repository_owner_id=322037689` relevées sur le dépôt canonique et inscrites au contrat.
- [ ] Identité SAN réelle et exacte confirmée sur un build de test avant d'activer la vérification indépendante.
- [x] Version `specVersion` CycloneDX `1.7` observée sur le SBOM source réel Trivy `0.76.1`.
- [ ] Version `specVersion` `1.7` confirmée sur le SBOM runtime généré par `trivy image` dans GitHub Actions.
- [x] Phase B : workflow dédié aux tags SemVer, commit vérifié comme ancêtre de `main`, actions épinglées.
- [x] Phase B : export de l'archive Docker runtime et attestation par digest de fichier configurés, sans revendiquer un digest OCI.
- [x] Phase B : validateur des invariants CycloneDX `1.7` et tests positifs/négatifs ajoutés.
- [x] Phase B : validation complète du JSON Schema officiel CycloneDX `1.7` intégrée à la CI ; schéma amont épinglé par révision et SHA-256.
- [ ] Phase B : premier run tag de confiance ayant produit les deux attestations GitHub et permettant la capture de l'identité SAN et de l'audience réelles.
- [ ] Phase B : vérification indépendante réussie des attestations et des sujets à l'aide de GitHub CLI.

L'identité SAN exacte reste un prérequis de vérification indépendante et de la phase C ; elle sera capturée depuis le bundle réel produit par le premier run de phase B. La phase B n'active aucun droit OIDC dans le workflow CI générique : le workflow réutilisable de build conserve `contents: read` et téléverse l'archive ainsi que le SBOM runtime. Un job distinct du workflow tag télécharge cet artefact et reçoit seul `id-token: write`, `attestations: write` et `artifact-metadata: write`. Le workflow CI général ne délègue que `contents: read` au workflow réutilisable ; aucun job de build ne peut donc demander des permissions supérieures à celles de son appelant. Le job de validation refuse aussi tout tag dont l'acteur n'est pas `eldorplus`. Aucun droit `packages: write`, aucune publication OCI et aucune release ne sont ajoutés.
