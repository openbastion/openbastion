# ADR-0059 — Dependabot propose les mises à jour, une dépendance à la fois et après sept jours ; la CI décide

**Contexte**
ADR-0052 cherche les vulnérabilités **connues** à chaque commit et chaque lundi (`make vuln`), et ADR-0051 épingle les images par empreinte. Mais rien ne **propose** une version plus récente : une empreinte d'image, une action, `x/crypto` restent à la version du jour où on les a relevées, jusqu'à ce que quelqu'un y pense — ADR-0051 l'a noté (« mise à jour manuelle des empreintes »), et c'est une telle inattention qui avait laissé 21 vulnérabilités dans `x/crypto` (ADR-0052).

**Décision** *(outillage retenu par Bony Kiss le 31 octobre 2026 parmi les reliquats proposés, avec les pull requests qu'il ouvre ; la forme est renversable)*

1. **`.github/dependabot.yml`** pour les cinq sources du dépôt : les 17 modules Go, les 2 paquets npm, les actions du workflow, les `Dockerfile` et les fichiers compose. Une passe chaque lundi.
2. **Une pull request par dépendance**, jamais une mise à jour en masse (policy des dépendances, point 3) : la même dépendance avance dans tous les modules à la fois (`group-by: dependency-name`) — `x/crypto` fait une pull request, pas dix-sept, et les modules de `go.work` restent d'accord.
3. **Une version n'est proposée qu'à sept jours** (`cooldown`) : une version piégée est le plus souvent retirée en quelques jours. Les mises à jour **de sécurité** de Dependabot ne sont pas retardées.
4. **Les empreintes restent** : Dependabot déplace l'empreinte d'une action ou d'une image avec sa version ; `images_test.go` refuse toujours une image sans empreinte.
5. **Rien n'est fusionné de soi-même** : chaque pull request passe la CI entière (dont `make vuln`) ; la fusion est un geste humain.

**Conséquences**
- (+) Une version plus récente devient une pull request vérifiée, au lieu d'attendre qu'on y pense.
- (−) **Pas de test local possible** : la configuration est lue par GitHub après le push ; elle est vérifiée par la première passe de Dependabot (état noté dans `NOTES_SANDBOX.md`).
- (−) Les **alertes et mises à jour de sécurité** de Dependabot sont un réglage du dépôt (Settings → Code security), pas de ce fichier : à activer par le propriétaire.
- (−) Dependabot ne met pas à jour `go.work`, ni la version de Go de la CI (`GO_VERSION`), ni les empreintes écrites dans les tests (l'image OpenBao de `transit_flow_test.go`) : elles restent manuelles.
- (−) Les pull requests de Dependabot n'ont pas accès aux secrets du dépôt — la CI n'en utilise aucun.

**Alternatives envisagées**
- **Renovate** : plus de réglages, mais une application tierce avec un accès en écriture au dépôt ; Dependabot est déjà là.
- **Un groupe par écosystème** (une pull request par semaine pour tout Go) : moins de bruit, mais c'est la mise à jour en masse que la policy refuse — une régression ne se rattache plus à une dépendance.
- **Rien de plus que `make vuln`** : ne signale qu'une vulnérabilité publiée, jamais une version qui la corrige avant qu'elle le soit.
