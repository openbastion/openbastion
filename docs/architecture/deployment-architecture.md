# Architecture de déploiement

- **Empaquetage** : chaque microservice = image OCI, configuration 12-factor (variables d'environnement, aucun état local persistant hors cache).
- **Orchestration** : Helm charts comme artefact de référence, compatibles Kubernetes, K3s et OpenShift sans fork de manifeste.
- **Développement/on-prem léger** : Docker Compose pour environnement de développement et petites installations on-premise.
- **Ingress/Edge** : Traefik en reverse proxy de bordure, Envoy comme data plane du service mesh interne.
- **Observabilité** : stack CNCF standard — Prometheus (métriques), Grafana (dashboards), Loki (logs), Tempo (traces), OpenTelemetry (instrumentation commune).
- **Identité de plateforme** : Keycloak comme IdP de référence embarqué, sans exclure une fédération externe (`docs/architecture/system-overview.md`, « Fédération d'identité »).
