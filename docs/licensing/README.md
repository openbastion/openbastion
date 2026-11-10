# Contrôle des licences et SBOM

OpenBastion est distribué sous GNU AGPL v3.0 only (`AGPL-3.0-only`). Le texte canonique est [`../../LICENSE`](../../LICENSE). Les composants tiers conservent leurs licences et notices propres.

## Contrôles automatisés

- `make license-check` vérifie les déclarations SPDX des paquets npm, des lockfiles, d'OpenAPI et des paramètres du projet, ainsi que la présence et la cohérence des notices.
- Le workflow CI `Containers` génère des SBOM CycloneDX source et image runtime, ainsi qu'un rapport JSON des licences avec Trivy, en incluant les dépendances de développement npm.
- Le contrôle des licences de dépendances échoue sur les licences classées `HIGH` ou `CRITICAL` par Trivy. Le rapport complet inclut également les fichiers source et documents. Les résultats `UNKNOWN` et les classifications moins sévères restent dans le rapport artefact et nécessitent une revue humaine ; le scanner ne décide pas à lui seul de la compatibilité juridique.
- Les artefacts `openbastion-source-sbom.cdx.json`, `openbastion-runtime-sbom.cdx.json` et `openbastion-license-report.json` sont publiés sous `openbastion-supply-chain-<commit>` pendant 30 jours.

Trivy classe les licences en catégories de risque ; cette classification ne remplace pas l'analyse de compatibilité réelle, des conditions de combinaison, des exceptions ni des notices requises. Voir [la politique de licence](../../.agents/policies/licensing-agpl-3.0.md).

## Source correspondant au binaire déployé

L'Admin UI affiche un pied de page avec le texte de licence et un lien source. Quand le build reçoit un SHA Git complet, le lien cible l'arbre de ce commit et le lien de licence cible le fichier `LICENSE` de ce même commit.

- Build Makefile : `make ui-build` injecte le SHA du checkout local.
- Build Docker Compose : définir `SOURCE_REVISION` sur le SHA Git complet avant `docker compose up --build` et, pour un fork GitHub, `SOURCE_REPOSITORY` sur l'URL HTTPS du dépôt du fork.
- Build Docker direct : fournir `--build-arg SOURCE_REVISION=<sha-complet>` et `--build-arg SOURCE_REPOSITORY=https://github.com/<owner>/<repo>`.
- Si le SHA n'est pas fourni ou n'est pas un SHA complet, l'interface indique explicitement que la révision n'est pas identifiée. Le lien générique vers le dépôt ne prouve pas que cette révision correspond au déploiement.

Pour une offre hébergée ou une version modifiée, l'exploitant doit publier le code source correspondant exactement à la version exécutée et le rendre accessible depuis l'interface, conformément à la section 13 de l'AGPLv3.

## Inventaire des Agent Skills

Voir [`skills-provenance.md`](skills-provenance.md) et [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md). Les éléments dont la provenance est inconnue restent bloqués pour approbation jusqu'à leur vérification ; aucune licence n'est inférée par défaut.
