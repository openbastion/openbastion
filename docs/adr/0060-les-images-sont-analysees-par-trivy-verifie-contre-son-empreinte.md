# ADR-0060 — Les images sont analysées par Trivy, un binaire vérifié contre son empreinte, jamais par ses actions ; ce qui est accepté l'est par écrit, par chemin et jusqu'à une date

**Contexte**
ADR-0052 cherche les vulnérabilités du code Go et des paquets npm, mais pas celles des **images** : les paquets du système de base, et les binaires qu'une image tierce embarque. ADR-0052 l'a noté : « un scanner d'images (Trivy, Grype) : à décider à part ». L'outil d'analyse est lui-même une cible : en mars 2026, les étiquettes d'`aquasecurity/trivy-action` (76 sur 77) et de `setup-trivy` ont été déplacées vers un voleur de secrets, et la v0.69.4 du binaire était piégée ([CVE-2026-33634](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).

**Décision** *(outillage retenu par Bony Kiss le 31 octobre 2026 parmi les reliquats proposés ; la forme est renversable)*

1. **Un job `images`** en CI et une cible `make scan-images` : l'image d'OpenBastion (cible `runtime` de `deploy/docker-compose/Dockerfile`, celle qu'on déploie) et `postgres:16` telle qu'épinglée dans le compose. **Une vulnérabilité HIGH ou CRITICAL corrigée ailleurs fait échouer le job.**
2. **Trivy est l'archive de sa version publiée** (0.76.1, à 10 jours de sa publication), téléchargée par le job et **vérifiée contre son SHA-256 écrit dans le workflow** : une version republiée ou une étiquette déplacée ne correspond plus, et rien ne s'exécute. **Jamais `trivy-action` ni `setup-trivy`.** Empreinte relevée de trois façons concordantes : celle que GitHub publie pour l'archive, le fichier d'empreintes de la version, le calcul local.
3. **Ce qui est accepté l'est par écrit**, dans `.trivyignore.yaml` : chaque entrée porte son identifiant, son **chemin** (la même vulnérabilité ailleurs échoue toujours), sa raison et sa **date d'expiration** (passée, elle ne cache plus rien).
4. **Accepté aujourd'hui** : les 26 constats (HIGH 25, CRITICAL 1) de la bibliothèque standard Go v1.24.6 dans `usr/local/bin/gosu` de `postgres:16` — `gosu` ne sert qu'au démarrage du conteneur, à passer de root à l'utilisateur `postgres`, sans réseau ni TLS ; jusqu'au 31 janvier 2027. La dernière `postgres:16` publiée est celle que nous épinglons : rien à mettre à jour de notre côté avant que l'amont reconstruise, et Dependabot le proposera (ADR-0059).

**Conséquences**
- (+) **Mesuré** (31 octobre 2026, Trivy 0.76.1) : l'image d'OpenBastion — Debian 12.15 et ses 11 binaires — n'a **aucune** vulnérabilité HIGH ou CRITICAL corrigée ; `postgres:16` n'en a aucune dans ses paquets Debian et 26 dans `gosu`.
- (+) **La porte est éprouvée dans les deux sens** : telle que commitée, `make scan-images` passe ; sans `.trivyignore.yaml`, `postgres:16` la fait échouer ; le même `gosu` copié sous un autre nom (`usr/local/bin/not-gosu`) la fait échouer malgré le fichier (26 constats) ; les entrées datées du 1ᵉʳ octobre 2026, elle échoue.
- (−) Le caractère « non atteignable » des constats de `gosu` est **jugé**, pas prouvé.
- (−) L'image `tools` (le travail ponctuel des certificats) et celle du bac à sable Base44 ne sont pas analysées ; ni les erreurs de configuration, ni les secrets (seulement les vulnérabilités).
- (−) La base de vulnérabilités est téléchargée à chaque passe (depuis le miroir par défaut de Trivy) : une panne de ce miroir fait échouer le job.
- (−) La signature Sigstore du fichier d'empreintes n'est pas vérifiée (pas de `cosign` ici) : l'empreinte écrite dans le workflow suffit à refuser un binaire changé, pas à prouver que le premier relevé était le bon.
- (−) Dependabot ne met pas à jour `TRIVY_VERSION` ni `TRIVY_SHA256` : à relever à la main, comme `GO_VERSION`.

**Alternatives envisagées**
- **`aquasecurity/trivy-action` épinglée par empreinte de commit** : protège d'une étiquette déplacée, mais l'action télécharge elle-même un binaire, que l'empreinte de l'action ne couvre pas.
- **Grype** : comparable ; Trivy lit aussi les binaires Go, ce qui a trouvé `gosu`.
- **Analyser sans faire échouer** (rapport seulement) : une porte qui ne ferme jamais n'est pas lue.
- **Passer à `postgres:16-alpine`** (pas de `gosu`, `su-exec` en C) : un changement de l'image de déploiement et de ses tests, pour un risque jugé faible ; à rouvrir si les constats de `gosu` durent après janvier 2027.
