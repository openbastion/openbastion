# OpenBastion — Interfaces inter-services (gRPC/Protobuf)

**Version** 0.1 · **Statut** Draft de travail
**Document précédent** `OpenBastion_06_Modele_Donnees.md`
**Portée** Contrats gRPC internes pour le périmètre MVP, entre Session Broker, Proxy protocolaire, Vault, Session Recorder, Audit Service et Authorization Service — dernier document de la séquence fixée en introduction.

---

## 1. Conventions

| Aspect | Convention |
|---|---|
| Nommage des packages | `openbastion.<domaine>.v1` — un dossier `proto/<domaine>/v1/` par contrat (arborescence, doc 02 §2) |
| Identité de l'appelant | Jamais un champ de message : dérivée du certificat mTLS et propagée via `RequestContext.calling_service_id` reconstruit côté serveur. **Implémenté (ADR-0010)** : l'identité est l'unique SAN URI `spiffe://<domaine>/<service>` ; chaque service porte une table `{méthode, chemin, appelants}` avec refus par défaut — les tables sont le contrat de qui peut appeler quoi, au même titre que les `.proto` le sont de la forme des messages. Les champs de corps qui prétendaient nommer l'appelant (`calling_proxy_id`) sont devenus facultatifs et doivent concorder avec le certificat |
| Valeur zéro des enums | Toujours `..._UNSPECIFIED = 0`, pour distinguer un champ non renseigné d'une valeur métier |
| Évolution de contrat | Ajout de champs/RPC uniquement sur v1 ; toute rupture (renumérotation, suppression, changement de type) impose un nouveau package `v2`, les deux coexistant pendant la migration |
| Suppression de champ | Le numéro est réservé (`reserved`), jamais réutilisé |
| Détection de rupture | `buf breaking` exécuté en CI sur `proto/` avant tout merge |

## 2. Types communs

```protobuf
// proto/common/v1/common.proto
syntax = "proto3";
package openbastion.common.v1;

option go_package = "github.com/openbastion/openbastion/proto/common/v1;commonv1";

// Reconstruit côté serveur à partir du JWT vérifié en périphérie et du
// certificat mTLS de l'appelant — jamais un secret de session ici.
message RequestContext {
  string trace_id = 1;
  string actor_user_id = 2;       // vide pour un appel système (Scheduler, ...)
  repeated string actor_roles = 3;
  string calling_service_id = 4;  // identité mTLS du service appelant — le nom de service du SAN URI, jamais une valeur du message
}
```

## 3. Session Broker ↔ API Gateway — `SessionOrchestration`

```protobuf
// proto/access/v1/session_orchestration.proto
syntax = "proto3";
package openbastion.access.v1;

import "common/v1/common.proto";
import "google/protobuf/timestamp.proto";

option go_package = "github.com/openbastion/openbastion/proto/access/v1;accessv1";

service SessionOrchestration {
  rpc CreateSession(CreateSessionRequest) returns (Session);
  rpc GetSession(GetSessionRequest) returns (Session);
  rpc TerminateSession(TerminateSessionRequest) returns (Session);
  // Double validation du break-glass (ADR-0011). L'identité de celui qui décide est
  // celle de context (vérifiée par le Gateway), jamais un champ du message. Approuver
  // exige une autre personne que le demandeur et une politique RBAC sur
  // breakglass-approve:account:{privileged_account_id} ; rejeter exige la même autorité.
  rpc ApproveBreakGlass(DecideBreakGlassRequest) returns (Session);
  rpc RejectBreakGlass(DecideBreakGlassRequest) returns (Session);
  // Découverte des demandes break-glass en attente (ADR-0012) : celles que l'appelant
  // pourrait approuver MAINTENANT (pas de lui, politique breakglass-approve:account:{id}
  // sur le compte, dérogation active, durée dans la limite du jour). Aucune autorité :
  // liste vide, jamais une erreur (la réponse ne dit pas si des demandes existent). Une
  // dépendance muette : erreur UNAVAILABLE, jamais une liste partielle.
  rpc ListPendingApprovals(ListPendingApprovalsRequest) returns (ListPendingApprovalsResponse);
}

enum SessionStatus {
  SESSION_STATUS_UNSPECIFIED = 0;
  SESSION_STATUS_PENDING_APPROVAL = 1;
  SESSION_STATUS_ACTIVE = 2;
  SESSION_STATUS_EXPIRED = 3;
  SESSION_STATUS_TERMINATED = 4;
  SESSION_STATUS_DENIED = 5;
}

enum Protocol {
  PROTOCOL_UNSPECIFIED = 0;
  PROTOCOL_SSH = 1;
  // PROTOCOL_RDP, PROTOCOL_VNC, PROTOCOL_DATABASE, ... ajoutés en v1.0
  // sans renumérotation des valeurs existantes.
}

message CreateSessionRequest {
  openbastion.common.v1.RequestContext context = 1;
  string privileged_account_id = 2;
  Protocol protocol = 3;
  string justification = 4;
  int32 duration_minutes = 5;
  // Dérogation d'urgence à l'enregistrement (ADR-0009). Exige une justification
  // d'au moins 10 caractères, une durée bornée par la plateforme et une politique
  // RBAC sur breakglass:account:{privileged_account_id}. Refusée par défaut.
  bool break_glass = 6;
}

message Session {
  string id = 1;
  SessionStatus status = 2;
  Protocol protocol = 3;
  string requested_by = 4;
  string privileged_account_id = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp expires_at = 7;
  bool break_glass = 8;  // autorisée à s'exécuter sans recorder — pas « l'a fait » (audit : session.breakglass)
  // Qui a approuvé ou rejeté une demande break-glass, et quand (ADR-0011) ; vide sinon.
  // Tant que le statut est PENDING_APPROVAL, expires_at est l'échéance de la décision ;
  // à l'approbation il devient décision + durée demandée.
  string decided_by = 9;
  google.protobuf.Timestamp decided_at = 10;
}

message DecideBreakGlassRequest {
  openbastion.common.v1.RequestContext context = 1;
  string session_id = 2;
}

message ListPendingApprovalsRequest {
  openbastion.common.v1.RequestContext context = 1;  // l'identité et les rôles de l'appelant : ceux du jeton, jamais un champ
  int32 page = 2;       // < 1 → 1
  int32 page_size = 3;  // < 1 → 20 ; > 100 → 100 (comme les listes de la doc 05)
}

message ListPendingApprovalsResponse {
  repeated Session items = 1;  // les plus proches de leur échéance d'abord
  int32 page = 2;              // la page SERVIE (après bornage)
  int32 page_size = 3;
  int32 total_items = 4;       // de la liste déjà filtrée
  // Vrai si le Broker a dû couper sa lecture à 100 demandes en attente : il y en avait d'autres.
  bool truncated = 5;
}

message GetSessionRequest {
  openbastion.common.v1.RequestContext context = 1;
  string session_id = 2;
}

message TerminateSessionRequest {
  openbastion.common.v1.RequestContext context = 1;
  string session_id = 2;
  string reason = 3;
}
```

**Double validation du break-glass (ADR-0011).** Sous la configuration par défaut (`BREAKGLASS_APPROVAL=required`), `CreateSession(break_glass=true)` qui passe les verrous d'ADR-0009 renvoie une session au statut `PENDING_APPROVAL` : pas de `session.create`, pas de scope, pas de ticket. `ApproveBreakGlass` la rend `ACTIVE` (la durée demandée court à partir de l'approbation) ; `RejectBreakGlass` la rend `DENIED`. Mise en œuvre HTTP/JSON dans le sandbox : `POST /sessions/{id}/approve|reject`, corps `{decidedBy, actorRoles}` **construit par le Gateway** à partir du jeton vérifié (le corps du client est écarté) ; réponses `200`, `403` (soi-même, politique `breakglass-approve:account:{id}` absente, dérogation coupée ou hors limite), `404`, `409` (déjà décidée, périmée, pas une demande break-glass), `503` (une dépendance ne répond pas : la décision n'est pas prise). La décision est auditée **avant** d'agir (`session.breakglass_approved` / `session.breakglass_rejected`) et passe par une comparaison-échange atomique : une seule décision par demande.

**Découverte des demandes en attente et notification (ADR-0012).** `ListPendingApprovals` est ce que l'approbateur appelle pour voir ce qu'il peut décider ; mise en œuvre HTTP/JSON dans le sandbox : `GET /sessions?status=pending_approval&page=&pageSize=` (doc 05), où le Gateway ne relaie que `status`, `page` et `pageSize` et pose `callerId` et `actorRoles` (rôles séparés par des virgules) d'après le jeton vérifié. Réponses : `200` (liste, vide pour qui n'a aucune autorité), `400` (autre statut que `pending_approval`), `403` (appelant non identifié), `503` (une dépendance ne répond pas : jamais de liste partielle). Le Broker interroge l'Authorization Service une fois par compte distinct. Côté sortie, le Broker déclare un port `ApprovalNotifier` — sans valeur de retour, appelé après coup (demande enregistrée ; décision gagnée) — dont l'adaptateur est un webhook `POST` JSON (`BREAKGLASS_NOTIFY_URL`, hors maillage mTLS) portant `event` (`breakglass.requested|approved|rejected`), `sessionId`, `accountId`, `requestedBy`, `decidedBy`, `durationMinutes`, `expiresAt`, `at` et `text` ; ni justification ni rien de la cible. Ce n'est pas un contrat gRPC : le Notification Service de la v1.0 remplacera l'adaptateur sans toucher le Broker.

**Connexion réservée au demandeur (ADR-0011).** `POST /sessions/{id}/connect` (HTTP, doc 05 §2 — hors de ce proto) porte désormais `{callerId}`, posé par le Gateway ; le Broker refuse (`403`) tout autre que `requested_by`, approbateur compris. Le Broker ne transmet la dérogation au proxy (`break_glass` de `EstablishSession`) que si la session a été approuvée, quand l'approbation est requise.

## 4. Session Broker → Proxy — `ProxyControl`

Implémenté identiquement par les 9 proxies protocolaires. Ne transporte **jamais** de secret — seulement les métadonnées nécessaires à l'établissement de connexion (ADR-0003).

```protobuf
// proto/proxy/v1/proxy_control.proto
syntax = "proto3";
package openbastion.proxy.v1;

import "common/v1/common.proto";
import "google/protobuf/timestamp.proto";

option go_package = "github.com/openbastion/openbastion/proto/proxy/v1;proxyv1";

service ProxyControl {
  // Refuse d'établir la session (UNAVAILABLE, « recording unavailable ») si le
  // Command Recorder n'est pas prêt : une session qui ne peut pas être
  // enregistrée n'a pas lieu (ADR-0008). Le scope Vault n'est alors pas
  // consommé — l'appel peut être renouvelé tel quel.
  rpc EstablishSession(EstablishSessionRequest) returns (EstablishSessionResponse);
  rpc TerminateSession(TerminateSessionRequest) returns (TerminateSessionResponse);
  rpc StreamHealth(HealthRequest) returns (stream HealthStatus);
}

message EstablishSessionRequest {
  openbastion.common.v1.RequestContext context = 1;
  string session_id = 2;
  string target_host = 3;
  string vault_scope_token = 4;    // jeton d'autorisation émis par le Broker — pas un secret
  google.protobuf.Timestamp expires_at = 5;
  string target_user = 6;          // nom du compte sur la cible — voir doc 06 §3, privileged_accounts.username
  // Autorisation du Broker de déroger à l'enregistrement (ADR-0009). Une demande,
  // pas un ordre : le proxy ne l'honore que s'il a lui-même été configuré pour
  // (BREAKGLASS_ENABLED) ET que le recorder n'est pas prêt ; sinon il refuse
  // comme d'habitude. La dérogation est auditée (session.breakglass) avant que
  // le credential ne soit récupéré.
  bool break_glass = 7;
}

message EstablishSessionResponse {
  string proxy_endpoint = 1;
  string connection_ticket = 2;    // jeton à usage unique, consommé à la connexion du client
}

message TerminateSessionRequest {
  openbastion.common.v1.RequestContext context = 1;
  string session_id = 2;
}

message TerminateSessionResponse {
  bool terminated = 1;
}

message HealthRequest {
  string proxy_instance_id = 1;
}

message HealthStatus {
  int32 active_sessions = 1;
  google.protobuf.Timestamp reported_at = 2;
}
```

## 5. Proxy ↔ Vault — le contrat le plus sensible

Modélisé en **deux services distincts** pour matérialiser la séparation d'autorité posée par ADR-0003 : le Broker autorise un *scope*, seul le proxy peut l'échanger contre un secret.

```protobuf
// proto/vault/v1/vault.proto
syntax = "proto3";
package openbastion.vault.v1;

import "common/v1/common.proto";
import "google/protobuf/timestamp.proto";

option go_package = "github.com/openbastion/openbastion/proto/vault/v1;vaultv1";

// Appelé par le Session Broker. Ne renvoie jamais de secret.
service VaultAuthorization {
  rpc AuthorizeScope(AuthorizeScopeRequest) returns (AuthorizeScopeResponse);
}

// Appelé UNIQUEMENT par un proxy protocolaire, jamais par le control plane.
// Seul RPC de tout le système qui transporte un secret.
service VaultCredentialIssuance {
  rpc FetchCredential(FetchCredentialRequest) returns (FetchCredentialResponse);
}

// Administration du cycle de vie d'un compte privilégié — appelé par
// l'Administration UI/API Gateway, jamais au fil d'une session (ce qui
// distingue ce service des deux ci-dessus). Contrairement à eux,
// PrivilegedAccount porte délibérément des métadonnées (username compris)
// — ADR-0003 ne l'interdit pas ici : seul un secret en est protégé, et
// aucun des trois RPC n'en renvoie un. Miroir de la surface REST
// documentée dans OpenBastion_05_OpenAPI.md §2 (/vault/accounts,
// .../{id}, .../{id}/rotate) et du modèle de données de doc 06 §3 —
// formalisé ici après avoir existé un moment comme API REST sans contrat
// gRPC propre ; voir NOTES_SANDBOX.md.
service VaultAccountAdmin {
  rpc OnboardAccount(OnboardAccountRequest) returns (PrivilegedAccount);
  rpc GetAccount(GetAccountRequest) returns (PrivilegedAccount);
  rpc RotateSecret(RotateSecretRequest) returns (RotateSecretResponse);
}

message AuthorizeScopeRequest {
  openbastion.common.v1.RequestContext context = 1;
  string session_id = 2;
  string privileged_account_id = 3;
  string proxy_service_id = 4;     // identité mTLS du proxy autorisé à échanger ce scope
  google.protobuf.Timestamp expires_at = 5;
}

message AuthorizeScopeResponse {
  string scope_token = 1;
  google.protobuf.Timestamp expires_at = 2;
}

message FetchCredentialRequest {
  string scope_token = 1;          // émis par AuthorizeScope, à usage unique
  string calling_proxy_id = 2;     // dérivé du certificat mTLS, vérifié contre le scope ; en HTTP/JSON facultatif, et une discordance avec le certificat est un 403 (ADR-0010)
}

message FetchCredentialResponse {
  bytes credential_material = 1;   // en mémoire uniquement côté appelant ; jamais journalisé
  string credential_type = 2;      // ex. "ssh_private_key", "password"
  google.protobuf.Timestamp valid_until = 3;
}

message OnboardAccountRequest {
  openbastion.common.v1.RequestContext context = 1;
  string id = 2;
  string name = 3;
  string username = 4;
  string target_host = 5;
  string protocol = 6;             // ex. "ssh" — énumération étendue en v1.0/v2.0 (doc 06 §3)
  string rotation_policy = 7;      // "manual" | "post_use" | "scheduled"
  bytes initial_secret = 8;        // vide = généré automatiquement (même règle que RotateSecretRequest.new_secret)
}

message GetAccountRequest {
  openbastion.common.v1.RequestContext context = 1;
  string id = 2;
}

// PrivilegedAccount ne porte jamais de secret, même chiffré — c'est la
// même séparation qu'ADR-0003 impose ailleurs, ici entre métadonnées de
// compte et matériel de credential plutôt qu'entre scope et secret.
message PrivilegedAccount {
  string id = 1;
  string name = 2;
  string username = 3;
  string target_host = 4;
  string protocol = 5;
  string rotation_policy = 6;
  google.protobuf.Timestamp last_rotated_at = 7;
  google.protobuf.Timestamp created_at = 8;
}

message RotateSecretRequest {
  openbastion.common.v1.RequestContext context = 1;
  string account_id = 2;
  bytes new_secret = 3;            // vide = généré automatiquement
}

message RotateSecretResponse {
  google.protobuf.Timestamp rotated_at = 1;
}
```

## 6. Proxy → Session Recorder — `SessionRecording`

```protobuf
// proto/recording/v1/recording.proto
syntax = "proto3";
package openbastion.recording.v1;

import "google/protobuf/timestamp.proto";

option go_package = "github.com/openbastion/openbastion/proto/recording/v1;recordingv1";

service SessionRecording {
  rpc StreamCommandEntries(stream CommandEntry) returns (StreamAck);
  // Signature réservée pour l'ajout du Video Recorder en v1.0 — ne rompt pas
  // le contrat existant.
  rpc StreamVideoFrames(stream VideoFrame) returns (StreamAck);
}

message CommandEntry {
  string session_id = 1;
  google.protobuf.Timestamp ts = 2;
  string command = 3;
}

message VideoFrame {
  string session_id = 1;
  google.protobuf.Timestamp ts = 2;
  bytes frame_data = 3;
  string codec = 4;
}

message StreamAck {
  int64 entries_received = 1;
}

// Lecture de l'enregistrement texte d'une session, par un auditeur — le
// pendant « lecture » de StreamCommandEntries. Appelé par l'API Gateway, qui
// transmet les rôles vérifiés du jeton (jamais ceux fournis par le client).
// L'accès est décidé par le Command Recorder lui-même via Authorization :
// action recording:session:read sur la ressource recording:session:{id}.
service SessionRecordingQuery {
  rpc GetCommandRecording(GetCommandRecordingRequest) returns (GetCommandRecordingResponse);
}

message GetCommandRecordingRequest {
  string session_id = 1;
  repeated string actor_roles = 2;
  int32 page = 3;       // < 1 est ramené à 1
  int32 page_size = 4;  // < 1 → 20 ; > 100 → 100 (comme les listes de la doc 05)
}

message GetCommandRecordingResponse {
  string session_id = 1;
  repeated CommandEntry entries = 2;  // dans l'ordre d'enregistrement (ts, puis insertion)
  int32 page = 3;                     // la page réellement servie, pas la demandée
  int32 page_size = 4;
  int64 total_entries = 5;
}
```

**Ce que `StreamCommandEntries` transporte réellement.** Ce que le proxy envoie est la commande telle que l'opérateur l'a *saisie* (édition de ligne appliquée : retour arrière, Ctrl-C/U/W), pas telle que le shell de la cible l'a exécutée — historique et complétion ne sont pas reconstitués. Une ligne saisie à un prompt de secret (sudo, su, ssh…) est remplacée côté proxy par le marqueur `[redacted: input at a secret prompt]` avant tout envoi ; un marqueur plutôt qu'un silence, pour qu'un faux prompt affiché par un initié reste visible dans le replay. **Enregistrer ou refuser (ADR-0008).** Par défaut (`RECORDING_POLICY=required`), l'enregistrement est une condition de la session, pas un canal parallèle :

- *Admission* — à `EstablishSession` (avant d'émettre le ticket) puis à nouveau à la connexion du client, avant de récupérer le credential, le proxy sonde la disponibilité du recorder (`GET /readyz` dans l'implémentation HTTP/JSON actuelle : le recorder répond `200` seulement s'il pourrait écrire, c'est-à-dire base joignable **et** inscriptible — un réplica en lecture seule est « non prêt »). Non prêt ⇒ `EstablishSession` est refusé (`UNAVAILABLE` ; `503 recording unavailable` en HTTP) et `session.recording_unavailable` est audité.
- *Acquittement* — le proxy n'envoie une ligne de commande à la cible qu'**après** que le recorder a accepté le lot (tout ou rien). Un échec d'enregistrement ⇒ la commande n'est pas exécutée, la session est terminée, l'opérateur est prévenu, `session.recording_lost` est audité.
- *Nouvelles tentatives* — deux au plus, uniquement sur erreur de connexion ou `500`/`503` (cas où le recorder garantit n'avoir rien stocké). Le recorder étant en ajout seul, sans déduplication, un échec ambigu (`502`, `504`, délai dépassé, connexion coupée) n'est pas rejoué : il peut sur-enregistrer une commande jamais exécutée, jamais l'inverse.

**Break-glass (ADR-0009).** Une session que le Broker a autorisée à déroger (`break_glass` à l'établissement) est admise même si le recorder n'est pas prêt — et seulement alors : un recorder prêt garde à la session son enregistrement acquitté. La dérogation est auditée (`session.breakglass`) **avant** la récupération du credential, et si cet événement ne peut pas être écrit la session est refusée. Ses commandes partent ensuite vers le recorder sans qu'on les attende (comme en mode au mieux) : elles ne bloquent jamais l'opérateur, et une panne du recorder ne coupe plus la session.

Le mode asynchrone — par lots, sans acquittement, où un recorder lent ou injoignable ne bloque pas la session au prix d'entrées perdues (comptées et journalisées) — n'existe plus que sous `RECORDING_POLICY=best-effort`, qui doit être demandé explicitement et dont le proxy avertit au démarrage. Il est réservé au développement.

## 7. Tout service → Audit Service — `AuditIngestion`

```protobuf
// proto/audit/v1/audit.proto
syntax = "proto3";
package openbastion.audit.v1;

import "common/v1/common.proto";
import "google/protobuf/timestamp.proto";

option go_package = "github.com/openbastion/openbastion/proto/audit/v1;auditv1";

service AuditIngestion {
  // Le chaînage prev_hash → hash (doc 06 §4) est calculé côté Audit Service :
  // un appelant ne connaît jamais le dernier hash de la chaîne.
  rpc EmitEvent(EmitEventRequest) returns (EmitEventResponse);
}

message EmitEventRequest {
  openbastion.common.v1.RequestContext context = 1;
  string action = 2;              // ex. "session.connect", "vault.rotate"
  string resource_type = 3;
  string resource_id = 4;
  bool success = 5;
  bytes signature = 6;            // signée par la clé de service de l'émetteur
}

message EmitEventResponse {
  string event_id = 1;
  google.protobuf.Timestamp ts = 2;
}
```

## 8. Broker/Gateway → Authorization Service — `Authorization`

```protobuf
// proto/authz/v1/authorization.proto
syntax = "proto3";
package openbastion.authz.v1;

import "common/v1/common.proto";

option go_package = "github.com/openbastion/openbastion/proto/authz/v1;authzv1";

service Authorization {
  rpc CheckAccess(CheckAccessRequest) returns (CheckAccessResponse);
}

message CheckAccessRequest {
  openbastion.common.v1.RequestContext context = 1;
  string resource = 2;            // ex. "vault:account:prod-db-01"
  string action = 3;              // ex. "session:create"
}

message CheckAccessResponse {
  bool allowed = 1;
  bool requires_approval = 2;     // false en MVP (pas de Workflow Service) ; actif dès v1.0
  string decision_reason = 3;
}
```

## 9. Flux MVP annoté au niveau RPC

```mermaid
sequenceDiagram
    participant GW as API Gateway
    participant BRK as Session Broker
    participant AUTHZ as Authorization Service
    participant VAULT as Vault (Authorization)
    participant PXY as SSH Proxy
    participant CRED as Vault (Credential Issuance)
    participant REC as Session Recorder
    participant AUD as Audit Service
    participant TGT as Serveur cible

    GW->>BRK: CreateSession(context, account, protocol=SSH)
    BRK->>AUTHZ: CheckAccess(resource, action)
    AUTHZ-->>BRK: allowed=true, requires_approval=false
    BRK->>VAULT: AuthorizeScope(session_id, account_id, proxy_service_id)
    VAULT-->>BRK: scope_token
    BRK->>PXY: EstablishSession(session_id, target_host, target_user, scope_token)
    PXY->>REC: Ready ? (GET /readyz)
    alt recorder non prêt, sans dérogation (ADR-0008)
        REC-->>PXY: indisponible
        PXY->>AUD: EmitEvent(action="session.recording_unavailable", success=false)
        PXY-->>BRK: UNAVAILABLE — session refusée, scope non consommé
    else recorder non prêt, break_glass autorisé par le Broker ET activé sur ce proxy (ADR-0009)
        PXY->>AUD: EmitEvent(action="session.breakglass", success=true)
        Note over PXY,REC: la session s'exécute ; ses commandes vont au recorder sans acquittement
    else recorder prêt
        REC-->>PXY: prêt
    end
    PXY->>CRED: FetchCredential(scope_token, calling_proxy_id)
    CRED-->>PXY: credential_material
    PXY->>TGT: Connexion SSH native
    PXY->>REC: StreamCommandEntries(session_id, ts, command)
    REC-->>PXY: acquittement — seulement alors la commande part vers TGT
    PXY->>AUD: EmitEvent(action="session.connect", success=true)
    Note over PXY,CRED: credential_material purgé après usage
```

## 10. Récapitulatif des contrats

| Service gRPC | Appelant(s) | Appelé | Transporte un secret ? |
|---|---|---|---|
| `SessionOrchestration` | API Gateway | Session Broker | Non |
| `ProxyControl` | Session Broker | Proxy protocolaire | Non (scope token uniquement) |
| `VaultAuthorization` | Session Broker | Vault | Non (scope token uniquement) |
| `VaultCredentialIssuance` | Proxy protocolaire | Vault | **Oui — seul RPC concerné** |
| `VaultAccountAdmin` | Administration UI/API Gateway | Vault | Non |
| `SessionRecording` | Proxy protocolaire | Command Recorder | Non (mais le texte d'une commande saisie peut en contenir un — voir §6) |
| `SessionRecordingQuery` | API Gateway | Command Recorder | Non (idem : le replay est une donnée sensible) |
| `AuditIngestion` | Tout service | Audit Service | Non |
| `Authorization` | Session Broker, API Gateway | Authorization Service | Non |

## 11. Clôture de la séquence documentaire initiale

Les huit livrables demandés en introduction sont désormais produits : architecture globale, diagrammes C4, arborescence du dépôt, ADR, feuille de route, contrats OpenAPI, modèle de données, interfaces inter-services. `VaultCredentialIssuance.FetchCredential` matérialise, au niveau du contrat de plus bas niveau documenté, l'invariant posé dès le premier document (§6, doc 00) et vérifié à chaque étage depuis : c'est le seul point de tout le système, du diagramme de contexte jusqu'au champ Protobuf, où un secret existe.

---
*Fin de la séquence initiale — prêt pour l'implémentation du MVP (`OpenBastion_04_Roadmap.md`, §2) ou pour l'approfondissement d'un des guides mentionnés en introduction (sécurité, HA, PRA/PCA), selon votre priorité.*
