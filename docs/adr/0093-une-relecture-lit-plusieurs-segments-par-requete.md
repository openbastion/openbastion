# ADR-0093 — Une relecture lit plusieurs segments par requête

**Statut** `Accepté` · 10 novembre 2026 · décision du propriétaire du projet (« C'est Accepté »). Cet ADR définit une architecture cible et ses étapes de migration ; son acceptation n'autorise ni publication, ni déploiement, ni changement immédiat des workflows.

## Contexte

La chaîne CI/CD a été auditée en lecture seule le 10 novembre 2026, après la fusion de la PR #117 (`934f235458bd72d4b56bcd01d5c2845872fa13e9`). Elle dispose déjà de contrôles utiles :

- les workflows ont des permissions minimales (`contents: read`), les actions sont épinglées par SHA complet et les checkouts utilisent `persist-credentials: false` ;
- les images de base sont épinglées par digest (ADR-0051) ;
- Trivy est téléchargé comme binaire et vérifié par SHA-256 (ADR-0060) ;
- le workflow conteneurs produit des SBOM CycloneDX source et runtime ainsi qu'un inventaire de licences ; les rapports sont conservés comme artefacts GitHub pendant 30 jours ;
- le ruleset `Main Protect` exige notamment DCO et les contrôles CI obligatoires ; DCO2 vérifie chaque commit d'une PR ;
- ADR-0063 fixe Semantic Versioning, le fichier `VERSION` et la vérification des tags `vX.Y.Z`.

L'audit a cependant relevé des preuves manquantes entre la source et un artefact déployable :

1. aucun document de provenance vérifiable ne relie un binaire ou une image à son commit, à son workflow et à ses matériaux de construction ;
2. les SBOM sont des rapports téléchargeables, mais ne sont pas encore attachés cryptographiquement à l'identité de l'artefact ;
3. aucune signature vérifiable des images n'est produite ;
4. aucun contrôle d'admission ne vérifie actuellement signature, digest, provenance et SBOM avant déploiement ;
5. les artefacts CI expirent après 30 jours et ne constituent pas une archive de preuves de livraison à long terme.

Ces constats ne signifient pas que les artefacts actuels sont compromis. Ils signifient que leur chaîne de fabrication et leur identité ne sont pas encore démontrables de bout en bout.

Les décisions existantes restent des invariants :

- **ADR-0047** : actions épinglées, permissions minimales et CI sans secrets inutiles ;
- **ADR-0051** : les images consommées sont épinglées par digest ;
- **ADR-0052** et **ADR-0060** : analyses de vulnérabilités et de conteneurs bloquantes selon les politiques déclarées ;
- **ADR-0063** : SemVer, tag créé par le propriétaire ; la CI vérifie et construit, mais ne publie pas automatiquement de release GitHub ni d'artefact ; publier reste un geste explicite du propriétaire ;
- **ADR-0030** : les migrations et les éléments historiques appliqués ne sont pas réécrits.

## Décision

Adopter une chaîne de confiance composée de six étapes indépendantes et vérifiables. La migration est progressive : aucune étape ne doit affaiblir les contrôles existants ni transformer une preuve absente en succès implicite. Les contrats techniques de la phase A sont définis dans [Contrats de confiance de la chaîne de livraison](../security/supply-chain-contracts.md) ; toute implémentation des phases suivantes doit respecter ce document ou faire l’objet d’une révision explicite de l’ADR.

### 1. Source : identité et intégrité du code

1. La source d'un artefact de livraison est un commit Git identifié par son SHA complet, dans le dépôt canonique `openbastion/openbastion`.
2. Les commits d'une PR doivent satisfaire le contrôle DCO2 obligatoire. Le build de livraison ne consomme jamais le contenu d'une PR non fusionnée comme source de release.
3. Une livraison versionnée est déclenchée par un tag SemVer `vX.Y.Z` conforme à ADR-0063. Le tag doit désigner un commit présent dans l'historique de `main` et la version doit correspondre au fichier `VERSION`.
4. Le tag reste créé et poussé par le propriétaire du projet. Le workflow de confiance vérifie l'acteur GitHub `eldorplus` avant checkout et avant tout job ayant des permissions d'attestation. Aucun bot, workflow ou agent ne crée de tag ou de release de sa propre initiative.
5. Les workflows de livraison doivent identifier explicitement le dépôt, le commit, le tag, le chemin du workflow et la révision du workflow qui a exécuté le build.

### 2. Build : provenance attestée

1. Produire une attestation de provenance au format **in-toto Statement**, avec un prédicat de provenance compatible **SLSA Provenance v1.0**.
2. La provenance décrit au minimum :
   - le sujet (nom et digest cryptographique de chaque artefact produit) ;
   - le dépôt source, le SHA du commit et le tag éventuel ;
   - l'identité du workflow et sa révision ;
   - le builder et l'environnement de construction ;
   - les matériaux déclarés (images de base par digest, dépendances et fichiers de verrouillage pertinents) ;
   - les paramètres non secrets qui influencent le résultat.
3. L'objectif initial est **SLSA Build L2**, sous réserve que le générateur de provenance et le service de build satisfassent effectivement les exigences du niveau. Le dépôt ne revendique jamais un niveau SLSA sur la seule présence d'un fichier JSON.
4. Les builds de livraison doivent s'exécuter depuis une référence protégée et un workflow de confiance. Les builds de PR ne reçoivent aucun droit OIDC de signature, d'attestation ou de publication.
5. Toute donnée secrète est exclue de la provenance, des paramètres sérialisés et des logs. Les secrets ne sont jamais utilisés comme matériaux ou arguments en clair.
6. Un niveau supérieur (notamment SLSA Build L3) nécessite une décision distincte démontrant l'isolation du builder, la résistance à la falsification et les garanties de construction hermétique. Il n'est pas revendiqué par cet ADR.

### 3. Analyse : SBOM et politiques de sécurité

1. Conserver **CycloneDX** comme format de SBOM de référence pour les composants source et runtime, en cohérence avec les rapports déjà produits.
2. Générer un SBOM pour chaque artefact livrable, après construction, et l'associer à son digest exact. Le SBOM d'une image runtime ne doit pas être présenté comme celui de l'image de build ou d'un autre digest.
3. Continuer les contrôles Trivy et les politiques de licences existantes. Les exceptions restent explicites, limitées à un composant ou chemin, motivées et expirables ; une attestation ne rend jamais acceptable une vulnérabilité interdite.
4. Attester le SBOM comme un objet lié au digest de l'artefact. La vérification doit rejeter un SBOM dont le sujet ne correspond pas exactement au digest déployé.
5. Préserver les rapports de scan et SBOM comme éléments d'audit. Leur présence n'est pas une preuve de provenance tant qu'ils ne sont pas authentifiés et liés au sujet.

### 4. Signature : identité de l'émetteur et intégrité des artefacts

1. Pour les artefacts publiés dans un registre OCI, utiliser **Cosign avec signature keyless Sigstore**, adossée à l'identité OIDC du workflow GitHub Actions et à la transparence Sigstore.
2. Ne pas introduire de clé privée de signature longue durée dans les secrets GitHub, les runners ou les images. L'identité du workflow, l'émetteur OIDC et les contraintes de confiance constituent la racine de vérification.
3. Signer le digest OCI immuable, jamais une étiquette mutable seule. Une signature valide pour un digest ne vaut pas pour un autre digest portant la même étiquette.
4. Signer ou attester séparément les binaires et archives distribués, avec leurs sommes de contrôle et leur provenance, si leur distribution est décidée.
5. Les identités autorisées à signer sont limitées au dépôt canonique, aux workflows de livraison nommément déclarés et aux références protégées prévues. Une identité d'un fork, d'une PR ou d'un workflow non autorisé doit échouer à la vérification.
6. Le vérificateur contrôle également l'identité de l'émetteur, l'audience OIDC attendue, le sujet, le digest et l'attestation de provenance ; la simple présence d'une signature cryptographiquement valide ne suffit pas.

### 5. Publication : geste explicite du propriétaire

1. **Aucune publication automatique n'est ajoutée par cet ADR.** Le choix d'ADR-0063 reste en vigueur : la CI vérifie et construit, mais ne crée pas de release GitHub et ne publie pas d'artefact sans décision explicite du propriétaire.
2. Toute future publication dans GHCR ou dans une release GitHub fera l'objet d'une décision et d'une procédure dédiées, avec validation humaine explicite, permissions minimales et traçabilité.
3. Lorsqu'une publication sera autorisée, les images seront référencées par digest ; signatures, provenance et SBOM seront publiés ou attachés de manière à rester récupérables par le vérificateur.
4. Les permissions `packages: write`, `contents: write`, `id-token: write`, `attestations: write` et `artifact-metadata: write` ne seront jamais accordées globalement. Elles seront limitées au job qui en a strictement besoin, sur une référence de confiance. Les workflows de PR ne les recevront pas.
5. Les artefacts de preuve nécessaires à une livraison devront être conservés au moins aussi longtemps que l'artefact auquel ils se rapportent. Une rétention GitHub de 30 jours ne suffit pas à constituer une conservation durable ; le stockage à long terme et sa politique de rétention feront l'objet d'une décision de mise en œuvre.

### 6. Déploiement : vérification obligatoire avant exécution

1. Tout déploiement d'une image OpenBastion doit référencer un digest OCI, et non une étiquette seule (ADR-0051).
2. Avant admission ou démarrage, le mécanisme de déploiement vérifie :
   - que le digest correspond à l'artefact demandé ;
   - qu'une signature valide est présente ;
   - que l'émetteur OIDC et l'identité du workflow appartiennent à la liste de confiance ;
   - que la provenance lie le digest au dépôt canonique, au commit et à une référence autorisée ;
   - que le SBOM attesté a le même digest comme sujet ;
   - que les politiques de vulnérabilités et de licences applicables sont satisfaites.
3. Le contrôle est **fail-closed** : preuve absente, expirée, invalide, non vérifiable ou incohérente entraîne le refus du déploiement. Aucun mode permissif n'est activé implicitement.
4. Un mode d'observation peut être utilisé pendant la migration uniquement sur des environnements non productifs ; il ne constitue pas une preuve de conformité et sa durée doit être bornée.
5. Une procédure de dérogation d'urgence, si elle devient nécessaire, devra être définie par un ADR séparé : identité de l'approbateur, motif, portée, durée, événement d'audit et révocation. Elle ne peut pas être un simple contournement permanent de la vérification.

### Séquence de migration

| Phase | Livrable | Critère de sortie |
|---|---|---|
| A — Inventaire et contrats | [Contrats de confiance version 1.2.0](../security/supply-chain-contracts.md) : schéma de provenance, identité des workflows, politique de vérification, SBOM et tests négatifs | Contrats versionnés ; prérequis d'implémentation identifiés ; aucune permission élargie |
| B — Attestation en CI | Provenance SLSA v1.0 et SBOM CycloneDX attestés pour les builds de tags de confiance ; sujet de phase B = archive Docker exportée et son SHA-256 fichier | Vérification indépendante du sujet, du commit, du workflow et des matériaux ; attestations invalides rejetées ; aucun digest OCI revendiqué ni publication |
| C — Signature | Signature Cosign keyless des artefacts publiés lorsque la publication aura été autorisée | Vérification par digest et identité exacte ; aucun secret de signature longue durée |
| D — Vérification de déploiement | Contrôle d'admission ou étape de déploiement vérifiant signature, provenance, SBOM et digest | Déploiement valide accepté ; mutations, absence de preuve et identité non autorisée refusées |
| E — Conservation et exploitation | Conservation durable des preuves, procédure de renouvellement et runbook d'incident | Restauration et vérification des preuves testées ; rétention et responsabilités documentées |

La phase B atteste un fichier archive `docker save` et son SBOM runtime lié, et non un manifeste OCI publié. Le workflow réutilisable de build conserve `contents: read` et téléverse l'archive ainsi que le SBOM runtime. Un job distinct du workflow tag télécharge ces fichiers via `actions/download-artifact` et utilise les attestations GitHub (SLSA provenance + SBOM CycloneDX) avec les permissions `id-token: write`, `attestations: write` et `artifact-metadata: write`, uniquement après validation d'un tag SemVer dont le commit est ancêtre de `main`. Le workflow CI général et les builds PR conservent `contents: read`. L'action d'attestation est épinglée au SHA `1e69f48acb82d1966a394da916b4c1698aa569d6` (v4). Aucun `packages: write`, `push-to-registry`, release ou publication d'image n'est activé.

Aucune phase ne s'active automatiquement du seul fait de l'acceptation de cet ADR. Chaque phase est livrée par incréments testés et revus.

## Conséquences

- (+) La chaîne de confiance devient vérifiable indépendamment de la personne qui a lancé le build : commit, workflow, builder, matériaux et digest sont liés.
- (+) Le SBOM runtime est destiné à être attesté avec l'archive Docker exportée ; le SBOM source reste un rapport de composition distinct tant qu'un artefact source immuable n'est pas défini. Le validateur de phase B vérifie les invariants structurels du contrat OpenBastion puis applique le JSON Schema officiel CycloneDX 1.7 (Draft 7), avec vérification des formats. Le schéma est conservé dans `third_party/cyclonedx/1.7/`, accompagné de sa provenance amont, de son SHA-256 et de sa licence Apache 2.0.
- (+) La signature keyless évite de gérer une clé privée de signature permanente dans les secrets CI.
- (+) Le déploiement peut refuser une image non signée, reconstruite depuis une source non autorisée, ou accompagnée de preuves incohérentes.
- (+) L'architecture conserve la politique de publication explicite d'ADR-0063 et ne donne pas de droits d'écriture globaux à la CI.
- (−) La génération et la vérification des attestations ajoutent des étapes, des dépendances et du temps aux workflows ; leurs actions et outils devront être épinglés et vérifiés comme les autres dépendances.
- (−) GitHub documente ses artifact attestations comme fournissant SLSA v1.0 Build Level 2 ; OpenBastion ne revendiquera ce niveau qu'après validation d'un bundle réel et de son identité. Un niveau supérieur dépend de l'isolation effective du builder et n'est pas revendiqué ici.
- (−) Les attestations GitHub keyless dépendent de l'accès OIDC et des services de signature/transparence ; la vérification hors ligne exige de conserver les bundles et éléments nécessaires à la validation.
- (−) La rotation ou le changement d'identité des workflows de confiance nécessite une mise à jour coordonnée des politiques de vérification ; une identité trop large annulerait une partie de la garantie.
- (−) Le contrôle d'admission peut rendre un environnement indisponible si les preuves ou le service de vérification sont indisponibles. Le comportement doit être explicite et fail-closed pour les nouveaux déploiements ; la disponibilité des workloads déjà démarrés reste gérée par l'orchestrateur.
- (−) La conservation à long terme des preuves entraîne un coût de stockage et impose une politique de rétention, de sauvegarde et de contrôle d'accès.
- (−) Cet ADR ne choisit pas encore un fournisseur de stockage durable, un contrôleur Kubernetes précis, une politique de publication GHCR, ni un niveau SLSA supérieur à L2.
- (−) Les artefacts actuellement construits ne deviennent pas rétroactivement attestés ou signés. La garantie ne s'applique qu'aux artefacts produits après activation des phases correspondantes.

## Alternatives envisagées

- **Conserver uniquement les SBOM Trivy comme artefacts CI** : écartée. Ils décrivent des composants, mais ne prouvent pas qui a construit l'artefact ni que le rapport correspond au digest déployé.
- **Utiliser uniquement une signature Cosign** : écartée. Une signature prouve le contrôle d'une identité sur un digest, pas que le code source, le workflow et les matériaux de construction sont autorisés.
- **Utiliser uniquement une provenance SLSA sans signature vérifiable** : écartée. Un document de provenance non authentifié peut être remplacé ou fabriqué.
- **Stocker une clé privée Cosign permanente dans GitHub Secrets** : écartée. Elle crée un secret de haute valeur accessible à la chaîne CI et impose sa rotation, sa sauvegarde et sa révocation.
- **Publier automatiquement à chaque tag** : écartée. Cela contredirait ADR-0063, qui réserve la publication au geste explicite du propriétaire.
- **Faire confiance aux étiquettes OCI** : écartée par ADR-0051 ; seule l'identité par digest est stable.
- **Autoriser le déploiement si la vérification échoue** : écartée. Une panne ou une preuve absente ne doit pas se transformer en autorisation implicite.
- **Revendiquer SLSA L3 dès l'ajout d'une attestation** : écartée. Le niveau doit être démontré par les propriétés du builder et de son isolation, pas par le format du document.
