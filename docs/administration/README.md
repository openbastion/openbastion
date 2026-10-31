# Administration

Pour l'administrateur de la plateforme, une fois l'installation faite ([`../deployment/`](../deployment/README.md)). Le périmètre est celui du MVP.

| Page | Contenu |
|---|---|
| [`initial-setup.md`](initial-setup.md) | Les premiers gestes après l'installation |
| [`privileged-accounts.md`](privileged-accounts.md) | Comptes privilégiés au Vault : onboarding, clé d'hôte, rotation, SFTP et SCP |
| [`access-policies.md`](access-policies.md) | Politiques RBAC |
| [`approval-workflows.md`](approval-workflows.md) | Accès d'urgence (break-glass) : bornes, double validation, notification |
| [`session-recording.md`](session-recording.md) | Politique d'enregistrement : enregistrer ou refuser (ADR-0008) |
| [`identity-providers.md`](identity-providers.md) | Fédération d'identité (OIDC, ADR-0035) |
| [`audit-and-compliance.md`](audit-and-compliance.md) | Supervision et audit : chaîne, clé, ancrage, rétention |

## Pages prévues

| Page | État |
|---|---|
| `user-and-group-management.md` | Les utilisateurs locaux se créent par le CLI (`openbastion-cli user create`, voir `deploy/docker-compose/README.md`) ; pas de gestion de groupes dans le MVP. |
| `secret-rotation.md` | La rotation est décrite dans [`privileged-accounts.md`](privileged-accounts.md) (ADR-0037, ADR-0040, ADR-0041, ADR-0044). |
| `notifications.md` | Seule la notification du break-glass existe (webhook signé, ADR-0012 et ADR-0013, dans [`approval-workflows.md`](approval-workflows.md)). |
| `monitoring.md` | Voir [`../operations/`](../operations/README.md). |
