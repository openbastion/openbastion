# Qui appelle qui (identités mTLS)

Le graphe d'appels entre services. La source de vérité des appelants autorisés est le `internal/interfaces/callers.go` de chaque service ; ce schéma la résume.

Les noms de service sont ceux des SAN URI `spiffe://<domaine>/<service>` : `api-gateway`, `authentication`, `authorization`, `session-broker`, `ssh-proxy`, `password-vault`, `audit-service`, `command-recorder`, `video-recorder`, `seaweedfs`, plus `admin-cli` (outillage opérateur).

```
utilisateur ──HTTP──► api-gateway ──► authentication   (login, verify)
                          │──────► session-broker      (/sessions… : création, `GET /sessions?status=pending_approval` (seul statut servi), connect, approve, reject — liste blanche ; l'identité de l'appelant est celle du jeton, la requête de liste est reconstruite)
                          │──────► password-vault      (administration des comptes, rotation, épinglage de la clé d'hôte)
                          │──────► authorization       (création de politiques)
                          ├──────► command-recorder    (lecture d'un replay SSH)
                          └──────► video-recorder      (lecture d'un replay vidéo)
session-broker ──mTLS──► authentication (client MFA action-step-up épinglé sur le SAN `authentication`, ADR-0097) · authorization (check-access) · password-vault (authorize-scope, métadonnées de compte)
               ──► audit-service (emit-event)   · ssh-proxy (establish-session)
               ──► webhook de notification (BREAKGLASS_NOTIFY_URL, HORS maillage mTLS, au mieux, jamais un contrôle — ADR-0012 ; signé si BREAKGLASS_NOTIFY_SECRET — ADR-0013)
ssh-proxy ──► password-vault (fetch-credential : le secret, l'adresse et la clé d'hôte épinglée — ADR-0039) · audit-service · command-recorder (écriture des commandes)
password-vault, command-recorder ──► authorization (check-access)
command-recorder, video-recorder ──► audit-service (recording.read, avant de servir)
video-recorder ──► authorization (recording:session:read)
rdp-vnc-proxy ──► video-recorder (flux gRPC acquitté ; identité réservée, proxy pas encore implémenté)
video-recorder ──mTLS──► seaweedfs (S3-compatible, profil Compose `recording`)
admin-cli ──► authentication (POST /auth/v1/users) · audit-service (GET /audit/v1/verify-chain)
```

Ports par défaut : gateway 8080, vault 8081, audit 8082, authorization 8083, broker 8084, ssh-proxy 8085 (API) + 2222 (SSH), authentication 8086, Command Recorder 8087, Video Recorder HTTP 8088/gRPC 8089, SeaweedFS S3/TLS 8333. La source de vérité des appelants autorisés est le `callers.go` de chaque service, pas ce schéma.

- `session-broker` → `ssh-proxy`: `POST /internal/v1/inject-vault-secret` via mTLS, action limitée à l'injection d'un scope Vault à usage unique sur une session existante. `ssh-proxy` seul appelle ensuite `password-vault` pour obtenir le credential. Aucun secret ne transite par Broker/Gateway (ADR-0097).
