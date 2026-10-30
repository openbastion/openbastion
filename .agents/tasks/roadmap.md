# Feuille de route (résumé)

La source est `docs/architecture/OpenBastion_04_Roadmap.md` ; ce fichier n'en garde que ce qui oriente le travail d'un agent. **Ce qui n'est pas implémenté n'existe pas** : ne fais pas comme si.

| Étape | Contenu | État |
|---|---|---|
| MVP | SSH (et SFTP/SCP) de bout en bout : Authentication, Authorization (RBAC), Session Broker, Password Vault (rotation sur la cible, clé d'hôte épinglée), SSH Proxy, Audit Service, Command Recorder, API Gateway, mTLS, Admin UI, OIDC, docker-compose | implémenté ; reste : rotation planifiée (`backlog.md` n° 1) |
| v1.0 | Scheduler complet (rotation planifiée et post-usage), Workflow/Approval Engine, MFA, autres protocoles, haute disponibilité | à concevoir |
| v2.0 | détection d'anomalies, score de risque, protocoles supplémentaires | à concevoir |

Une étape de la feuille de route commence par un ADR (`architecture/write-adr.md`) et la validation du propriétaire.
