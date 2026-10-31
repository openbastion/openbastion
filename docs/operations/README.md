# Exploitation

Le MVP n'a pas encore d'outillage d'exploitation propre : pas de métriques exportées, pas de traces distribuées, pas de bus de messages. Cette section n'a donc pas encore de page ; ce qui existe est décrit ailleurs.

| Besoin | Où |
|---|---|
| Journaux des services, santé | [`../deployment/troubleshooting.md`](../deployment/troubleshooting.md), [`../development/debugging.md`](../development/debugging.md) |
| Supervision par l'audit (alertes `vault.rotation_overdue`, refus, expirations) | [`../administration/audit-and-compliance.md`](../administration/audit-and-compliance.md) |
| Panne d'un composant, dégradation gracieuse, tests de résilience | [`../deployment/high-availability.md`](../deployment/high-availability.md) |
| Perte d'un site, squelette de runbook de bascule | [`../deployment/disaster-recovery.md`](../deployment/disaster-recovery.md) |
| Sauvegardes | [`../deployment/backup-restore.md`](../deployment/backup-restore.md) |

## Pages prévues

| Page | État |
|---|---|
| `observability.md`, `logging.md`, `metrics.md`, `tracing.md`, `alerting.md` | Pas d'OpenTelemetry ni de métriques dans le code ; la notification poussée des alertes est l'étape suivante du backlog. |
| `capacity-planning.md`, `performance-testing.md` | Aucune mesure de charge à ce jour. |
| `backup-policy.md` | Voir [`../deployment/backup-restore.md`](../deployment/backup-restore.md). |
| `runbooks/` (service indisponible, base en panne, bus de messages, certificat expiré, compromission suspectée) | À écrire à partir des procédures réelles ; le MVP n'a pas de bus de messages. |
