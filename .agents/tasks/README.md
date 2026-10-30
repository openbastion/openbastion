# tasks — workflows types, backlog, feuille de route

**Au début de chaque tâche**, choisis le workflow qui correspond et crée ta liste de tâches. Un travail est terminé quand les portes de `rules/completion-gates.md` sont franchies — pas avant.

| Demande | Workflow |
|---|---|
| Nouvelle fonctionnalité (surtout de sécurité) | [`architecture/new-feature.md`](architecture/new-feature.md) |
| Décision structurante | [`architecture/write-adr.md`](architecture/write-adr.md) |
| Bug | [`backend/bug-fix.md`](backend/bug-fix.md) |
| Route interne nouvelle ou modifiée | [`backend/internal-route.md`](backend/internal-route.md) |
| Nouveau protocole de proxy | [`backend/proxy-protocol.md`](backend/proxy-protocol.md) |
| Changement de schéma PostgreSQL | [`database/schema-change.md`](database/schema-change.md) |
| Écran ou comportement de l'Admin UI | [`frontend/ui-change.md`](frontend/ui-change.md) |
| Revue de sécurité | [`security/security-review.md`](security/security-review.md) |
| Dépendance | [`devsecops/dependency.md`](devsecops/dependency.md) |
| Déploiement, test Compose | [`devsecops/compose-test.md`](devsecops/compose-test.md) |
| Vérification complète avant un jalon | [`releases/full-verification.md`](releases/full-verification.md) |
| Livrer un jalon | [`releases/milestone.md`](releases/milestone.md) |

Ce qui reste à faire : [`backlog.md`](backlog.md). Où va le produit : [`roadmap.md`](roadmap.md).

## Reprise après une longue interruption

1. Relis `NOTES_SANDBOX.md` (sections récentes), `git log --oneline | head`, `git status` — et ce que l'utilisateur a en cours dans sa copie de travail : ne l'embarque pas.
2. Remets l'environnement en route (`settings/environments/local.yaml`) — PostgreSQL est probablement arrêté.
3. Relance `make build vet test` pour connaître l'état réel avant d'ajouter quoi que ce soit.
4. Ne te fie pas à un chiffre ou à une affirmation d'un résumé : revérifie ce dont ta tâche dépend.
