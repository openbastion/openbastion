# Qui appelle qui (identités mTLS)

Le graphe d'appels entre services. La source de vérité des appelants autorisés est le `internal/interfaces/callers.go` de chaque service ; ce schéma la résume.

Les noms de service sont ceux des SAN URI `spiffe://<domaine>/<service>` : `api-gateway`, `authentication`, `authorization`, `session-broker`, `workflow-service`, `ssh-proxy`, `password-vault`, `audit-service`, `command-recorder`, `video-recorder`, `seaweedfs`, `rdp-vnc-proxy` et `admin-cli`.

```
utilisateur ──HTTP──► api-gateway ──► authentication (login, verify)
                          ├──────► workflow-service (gestion hiérarchie ; ADR-0138)
                          ├──────► session-broker (sessions et décisions)
                          ├──────► password-vault (comptes, rotation, épinglage)
                          ├──────► authorization (politiques et contrôles d'accès)
                          ├──────► audit-service (lectures et acquittements autorisés)
                          ├──────► command-recorder (replay SSH)
                          └──────► video-recorder (replay vidéo)
workflow-service ──mTLS──► authentication (authorization-context, statut actif et rôles courants)
                  ├──────► authorization (check-access)
                  └──────► audit-service (événements signés)
session-broker ──mTLS──► workflow-service (création idempotente, liste et décisions d’approbation)
               ├──────► authentication (MFA action-step-up)
               ├──────► authorization (check-access)
               ├──────► password-vault (authorize-scope)
               ├──────► audit-service (emit-event)
               └──────► ssh-proxy (establish-session)
ssh-proxy ──► password-vault (fetch-credential) · audit-service · command-recorder
password-vault, command-recorder ──► authorization
command-recorder, video-recorder ──► audit-service
video-recorder ──► authorization · seaweedfs (S3/mTLS)
rdp-vnc-proxy ──► video-recorder (flux gRPC)
admin-cli ──► authentication (création utilisateur) · audit-service (vérification chaîne)
```

Ports par défaut : Gateway 8080, Vault 8081, Audit 8082, Authorization 8083, Broker 8084, SSH Proxy 8085 (API) + 2222 (SSH), Authentication 8086, Command Recorder 8087, Video Recorder HTTP 8088/gRPC 8089, Workflow Service 8091, SeaweedFS S3/TLS 8333. La source de vérité des appelants autorisés est `callers.go`, pas ce schéma.

## Workflow Service (ADR-0138)

- Authentication : seul `workflow-service` lit `GET /auth/v1/internal/users/{user_id}/authorization-context`.
- Authorization : `workflow-service` appelle `POST /authz/v1/check-access` avec les rôles actuels retournés par Authentication.
- Audit : `workflow-service` émet les événements préalables et vide son outbox post-commit via `POST /audit/v1/emit-event`.
- Gateway : seul `api-gateway` appelle les routes internes de gestion de hiérarchie.
- Session Broker : seul `session-broker` appelle les routes internes de création idempotente, de lecture de file et de décision d'approbation ; le dispatch est alimenté par son outbox durable.
- Aucun accès SQL inter-service ; chaque service garde sa propre base.
