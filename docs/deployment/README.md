# Déploiement

Pour l'administrateur qui installe et exploite la plateforme. La configuration fonctionnelle (comptes, politiques, break-glass, audit) est dans [`../administration/`](../administration/README.md).

| Page | Contenu |
|---|---|
| [`prerequisites.md`](prerequisites.md) | Prérequis de déploiement |
| [`docker-compose.md`](docker-compose.md) | Installation ; le déploiement reproductible est `deploy/docker-compose/` (ADR-0033, son `README.md`) |
| [`configuration.md`](configuration.md) | Limitation de débit de la Gateway, déclaration du reverse proxy (ADR-0014 à ADR-0016) |
| [`tls-certificates.md`](tls-certificates.md) | Identité des services : PKI interne et mTLS (ADR-0010) |
| [`high-availability.md`](high-availability.md) | Haute disponibilité |
| [`backup-restore.md`](backup-restore.md) | Sauvegardes |
| [`disaster-recovery.md`](disaster-recovery.md) | Reprise après sinistre (PRA/PCA) |
| [`upgrades.md`](upgrades.md) | Mise à jour de la plateforme |
| [`troubleshooting.md`](troubleshooting.md) | Dépannage courant |

## Pages prévues

| Page | État |
|---|---|
| `kubernetes.md`, `helm.md`, `k3s.md`, `openshift.md` | Pas de chart Helm ni de manifeste dans `deploy/` ; v1.0 de la [feuille de route](../roadmap.md) (« Helm charts … pour un déploiement Kubernetes/K3s/OpenShift »). |
