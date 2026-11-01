# Prérequis de déploiement

| Composant | Rôle |
|---|---|
| Kubernetes / K3s / OpenShift, ou Docker Compose pour un petit site on-premise | Orchestration (`docs/architecture/system-overview.md`) |
| PostgreSQL 15+ | Métadonnées, politiques, comptes (`docs/architecture/data-architecture.md`) |
| Redis | Cache, état de session |
| MinIO | Stockage des enregistrements (v0.0.1 pour la vidéo) |
| NATS, Kafka | Bus temps réel / audit durable (ADR-0001) |
| Keycloak | IdP de plateforme (ADR-0007) |
| Un fournisseur OIDC accessible | Fédération d'identité en périmètre MVP (`docs/roadmap.md` §2) |
| Une autorité de certification interne (cert-manager, Vault PKI, SPIRE…), ou `openbastion-pki` pour un petit site | Identité de chaque service pour le mTLS interne (ADR-0010) — sans elle, aucun service ne démarre |
