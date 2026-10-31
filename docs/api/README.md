# API

L'API REST publique est servie par la Gateway sous `/api/v1`. Sa spécification est [`rest/openapi.yaml`](rest/openapi.yaml) (OpenAPI 3.1) ; ses conventions (version, authentification, pagination, erreurs, limitation de débit) sont dans [`conventions.md`](conventions.md). Les contrats entre services sont dans [`grpc/README.md`](grpc/README.md) et `proto/`.

## Table récapitulative des endpoints

| Endpoint | Méthode | Domaine | Description |
|---|---|---|---|
| `/auth/login` | POST | auth | Authentification locale (mot de passe) |
| `/auth/oidc/start` | POST | auth | Commence une connexion fédérée OIDC : URL du fournisseur (ADR-0035) |
| `/auth/oidc/callback` | POST | auth | Termine une connexion fédérée OIDC : `code` et `state` → jeton (ADR-0035) |
| `/auth/ldap` | GET | auth | Dit si la connexion par annuaire est activée (ADR-0061) |
| `/auth/ldap/login` | POST | auth | Connexion avec le mot de passe de l'annuaire LDAP ou Active Directory → jeton (ADR-0061) |
| `/auth/token/refresh` | POST | auth | Renouvellement de jeton |
| `/auth/me` | GET | auth | Profil courant |
| `/sessions` | GET / POST | sessions | Lister les demandes break-glass en attente que l'on peut décider (`status=pending_approval` seul, ADR-0012) / demander une session |
| `/sessions/{id}` | GET / DELETE | sessions | Détail (demandeur, décideur, ou politique `session-read:account:{id}`) / terminaison |
| `/sessions/{id}/connect` | POST | sessions | Ticket de connexion vers le SSH Proxy (réservé au demandeur) |
| `/sessions/{id}/approve` | POST | sessions | Approuver une demande break-glass (autre personne, politique `breakglass-approve:*`) |
| `/sessions/{id}/reject` | POST | sessions | Rejeter une demande break-glass |
| `/sessions/{id}/recording` | GET | sessions | Enregistrement texte de la session |
| `/vault/accounts` | GET / POST | vault | Lister / onboarder un compte privilégié |
| `/vault/accounts/{id}` | GET / DELETE | vault | Détail / suppression |
| `/vault/accounts/{id}/host-key` | PUT | vault | Épingler la clé d'hôte de la cible (ADR-0039) |
| `/vault/accounts/{id}/rotate` | POST | vault | Rotation manuelle |
| `/policies` | GET / POST | policies | Politiques RBAC |
| `/audit/events` | GET | audit | Recherche d'événements d'audit |
| `/audit/events/{id}` | GET | audit | Détail d'un événement, avec signature |

## Extensions prévues (hors MVP, non rupturantes)

- `/sessions/{id}/approve` et `/reject` existent déjà pour le break-glass (ADR-0011, dans le Session Broker). v1.0 les généralisera (Workflow/Approval Engine : quorum, N+1, ticket ITSM, fenêtre horaire) et ajoutera `/mfa/*` (MFA Service natif), et des variantes de `protocol` (`rdp`, `vnc`, `database`, `kubernetes`) sur `SessionRequest`.
- v2.0 étendra l'énumération `protocol` aux familles restantes (`docker`, `hypervisor`, `winrm`, `telnet`, `http`) et ajoutera `/risk/scores`.
- Toute extension se fait par ajout de champs optionnels et de nouveaux endpoints — jamais par modification d'un champ existant sur `/api/v1`, conformément à la convention de versionning (`docs/api/conventions.md`).
