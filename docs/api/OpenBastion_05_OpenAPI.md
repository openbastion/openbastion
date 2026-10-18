# OpenBastion — Contrats OpenAPI

**Version** 0.1 · **Statut** Draft de travail
**Document précédent** `OpenBastion_04_Roadmap.md`
**Portée** API REST publique correspondant au périmètre MVP (`OpenBastion_04_Roadmap.md`, §2) : Authentication, Authorization (politiques RBAC), Session Broker, sessions SSH, Password Vault, Audit. Les contrats gRPC internes ne sont pas couverts ici — ils font l'objet du document 7 (interfaces inter-services).

---

## 1. Conventions générales

| Aspect | Convention |
|---|---|
| Préfixe de version | `/api/v1` — toute rupture de compatibilité incrémente le préfixe, jamais de rupture silencieuse sur v1 |
| Authentification | Bearer JWT (émis par `POST /auth/login`, ADR-0007 — Keycloak en émetteur sous-jacent) |
| Pagination | `page` / `pageSize` en requête, enveloppe `{ items, page, pageSize, totalItems }` en réponse |
| Erreurs | Enveloppe unique `Error { code, message, traceId }`, `traceId` corrélé à OpenTelemetry |
| Horodatage | ISO 8601 / RFC 3339, UTC |
| Idempotence | Les endpoints de mutation sensibles (`POST /sessions`, `POST .../rotate`) acceptent un header `Idempotency-Key` |

Ce que cette API REST **n'expose jamais** : un secret cible en clair. `POST /sessions/{id}/connect` renvoie un ticket de connexion court terme vers le proxy protocolaire, jamais un mot de passe (ADR-0003) — cohérent avec l'invariant posé dès le document 00.

## 2. Spécification OpenAPI 3.1 (extrait MVP)

```yaml
openapi: 3.1.0
info:
  title: OpenBastion REST API
  version: "0.1.0-mvp"
  summary: API publique OpenBastion — périmètre MVP
  license:
    name: Apache-2.0
    identifier: Apache-2.0
  description: >
    API REST de la plateforme PAM OpenBastion. Ce document ne couvre que le
    périmètre MVP (voir OpenBastion_04_Roadmap.md). Les endpoints liés aux
    protocoles hors SSH, au Workflow Service et au MFA Service natif seront
    ajoutés en v1.0 sans rupture de compatibilité sur ce préfixe /v1.

servers:
  - url: "https://{host}/api/v1"
    variables:
      host:
        default: bastion.example.com

security:
  - bearerAuth: []

tags:
  - name: auth
  - name: sessions
  - name: vault
  - name: policies
  - name: audit

paths:
  /auth/login:
    post:
      tags: [auth]
      summary: Authentifie un opérateur (identité locale ou fédérée OIDC)
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/LoginRequest" }
      responses:
        "200":
          description: Authentification réussie
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TokenPair" }
        "401":
          description: Identifiants invalides
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }

  /auth/token/refresh:
    post:
      tags: [auth]
      summary: Renouvelle un access token à partir d'un refresh token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [refreshToken]
              properties:
                refreshToken: { type: string }
      responses:
        "200":
          description: Nouveau couple de jetons
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TokenPair" }

  /auth/me:
    get:
      tags: [auth]
      summary: Identité de l'opérateur authentifié
      responses:
        "200":
          description: Profil courant
          content:
            application/json:
              schema: { $ref: "#/components/schemas/User" }

  /sessions:
    get:
      tags: [sessions]
      summary: Liste les demandes/sessions de l'opérateur (ou toutes, si administrateur)
      parameters:
        - $ref: "#/components/parameters/Page"
        - $ref: "#/components/parameters/PageSize"
        - name: status
          in: query
          schema: { $ref: "#/components/schemas/SessionStatus" }
      responses:
        "200":
          description: Page de sessions
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/PagedResponse"
                  - type: object
                    properties:
                      items:
                        type: array
                        items: { $ref: "#/components/schemas/Session" }
    post:
      tags: [sessions]
      summary: Demande une nouvelle session privilégiée
      description: >
        En périmètre MVP, l'octroi est immédiat après vérification RBAC —
        aucune étape de validation multi-approbateurs (ajoutée en v1.0).
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/SessionRequest" }
      responses:
        "201":
          description: Session créée
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Session" }
        "403":
          description: Refusé par l'Authorization Service
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }

  /sessions/{sessionId}:
    parameters:
      - $ref: "#/components/parameters/SessionId"
    get:
      tags: [sessions]
      summary: Détail d'une session
      responses:
        "200":
          description: Session
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Session" }
        "404":
          description: Session introuvable
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }
    delete:
      tags: [sessions]
      summary: Termine une session active
      responses:
        "204":
          description: Session terminée

  /sessions/{sessionId}/connect:
    parameters:
      - $ref: "#/components/parameters/SessionId"
    post:
      tags: [sessions]
      summary: Émet un ticket de connexion court terme vers le SSH Proxy
      description: >
        Ne retourne jamais de secret cible — uniquement une adresse de proxy
        et un jeton de connexion à courte durée de vie, consommé une seule
        fois par le SSH Proxy (ADR-0003).

        Une session dont l'enregistrement n'est pas possible n'est pas
        établie (ADR-0008) : si le Command Recorder n'est pas prêt, le SSH
        Proxy refuse et la requête répond `503`. Aucune commande n'a été
        exécutée et aucun secret n'a été consommé ; la même requête peut
        être renouvelée une fois le recorder rétabli. L'événement d'audit
        `session.recording_unavailable` est émis.
      responses:
        "200":
          description: Ticket de connexion
          content:
            application/json:
              schema: { $ref: "#/components/schemas/ConnectionTicket" }
        "503":
          description: >
            Enregistrement indisponible — la session n'a pas été établie.
            Distinct de `409` (la session n'est pas dans un état où elle
            peut être connectée) : ici l'état de la session est inchangé et
            l'appel peut être renouvelé.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }

  /sessions/{sessionId}/recording:
    parameters:
      - $ref: "#/components/parameters/SessionId"
    get:
      tags: [sessions]
      summary: Récupère l'enregistrement texte (commandes) d'une session
      description: >
        Les commandes de la session, dans l'ordre où elles ont été
        enregistrées, paginées. Lisible pendant la session comme après.
        Réservé aux rôles autorisés par une politique
        `recording:session:read` sur `recording:session:{sessionId}` ; la
        Gateway transmet les rôles du jeton vérifié, jamais ceux que le
        client pourrait fournir. Le refus (403) est le même que la session
        existe ou non, et une session sans commande enregistrée donne un
        enregistrement vide (200), pas un 404 : l'API ne permet pas de
        sonder quelles sessions existent.
        Chaque entrée est la commande telle que l'opérateur l'a saisie, pas
        telle que le shell de la cible l'a exécutée (historique et
        complétion ne sont pas reconstitués). Une ligne saisie à un prompt
        de secret (sudo, su, ssh…) apparaît sous la forme
        `[redacted: input at a secret prompt]`.
      parameters:
        - $ref: "#/components/parameters/Page"
        - $ref: "#/components/parameters/PageSize"
      responses:
        "200":
          description: Flux de commandes horodaté
          content:
            application/json:
              schema: { $ref: "#/components/schemas/CommandRecording" }
        "403":
          description: Refusé par l'Authorization Service (ou injoignable — fermé par défaut)
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }

  /vault/accounts:
    get:
      tags: [vault]
      summary: Liste les comptes privilégiés
      parameters:
        - $ref: "#/components/parameters/Page"
        - $ref: "#/components/parameters/PageSize"
      responses:
        "200":
          description: Page de comptes
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/PagedResponse"
                  - type: object
                    properties:
                      items:
                        type: array
                        items: { $ref: "#/components/schemas/PrivilegedAccount" }
    post:
      tags: [vault]
      summary: Enregistre (onboard) un compte privilégié
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/PrivilegedAccountInput" }
      responses:
        "201":
          description: Compte créé
          content:
            application/json:
              schema: { $ref: "#/components/schemas/PrivilegedAccount" }

  /vault/accounts/{accountId}:
    parameters:
      - name: accountId
        in: path
        required: true
        schema: { type: string, format: uuid }
    get:
      tags: [vault]
      summary: Détail d'un compte privilégié (métadonnées, jamais le secret)
      responses:
        "200":
          description: Compte
          content:
            application/json:
              schema: { $ref: "#/components/schemas/PrivilegedAccount" }
        "404":
          description: "Compte introuvable ou désactivé (les deux cas ne sont volontairement pas distingués)"
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }
    delete:
      tags: [vault]
      summary: Retire un compte du coffre-fort
      responses:
        "204":
          description: Compte supprimé
        "403":
          description: Refusé par l'Authorization Service
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }
        "404":
          description: "Compte introuvable ou déjà supprimé. Même ordre que pour rotate : 403 avant 404."
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }

  /vault/accounts/{accountId}/rotate:
    parameters:
      - name: accountId
        in: path
        required: true
        schema: { type: string, format: uuid }
    post:
      tags: [vault]
      summary: Déclenche une rotation manuelle immédiate
      description: >-
        Aucun corps de requête : un secret de 32 octets aléatoires est
        toujours généré automatiquement. Choix délibéré, pas une omission —
        l'API Gateway ne relaie jamais vers Password Vault un secret fourni
        par le client sur cette route (voir le handler Gateway de cette
        route), précisément pour qu'un opérateur ne puisse jamais connaître
        ni choisir la valeur recréée. Le contrat interne de Password Vault
        (service VaultAccountAdmin, RPC RotateSecret — doc 07 §5) accepte
        techniquement un secret explicite optionnel, pensé pour un futur
        appelant interne programmatique (le Scheduler, doc 04), pas pour
        cette surface publique, qui ne l'expose donc pas ici.
      responses:
        "202":
          description: Rotation acceptée et en cours
        "403":
          description: Refusé par l'Authorization Service
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }
        "404":
          description: "Compte introuvable ou désactivé (les deux cas ne sont volontairement pas distingués). Le contrôle d'accès passe avant l'existence : un appelant non autorisé reçoit 403 que le compte existe ou non."
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Error" }

  /policies:
    get:
      tags: [policies]
      summary: Liste les politiques RBAC
      responses:
        "200":
          description: Page de politiques
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/PagedResponse"
                  - type: object
                    properties:
                      items:
                        type: array
                        items: { $ref: "#/components/schemas/Policy" }
    post:
      tags: [policies]
      summary: Crée une politique RBAC
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/PolicyInput" }
      responses:
        "201":
          description: Politique créée
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Policy" }

  /audit/events:
    get:
      tags: [audit]
      summary: Recherche dans le journal d'audit signé
      parameters:
        - $ref: "#/components/parameters/Page"
        - $ref: "#/components/parameters/PageSize"
        - name: actor
          in: query
          schema: { type: string }
        - name: action
          in: query
          schema: { type: string }
        - name: dateFrom
          in: query
          schema: { type: string, format: date-time }
        - name: dateTo
          in: query
          schema: { type: string, format: date-time }
      responses:
        "200":
          description: Page d'événements d'audit
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/PagedResponse"
                  - type: object
                    properties:
                      items:
                        type: array
                        items: { $ref: "#/components/schemas/AuditEvent" }

  /audit/events/{eventId}:
    parameters:
      - name: eventId
        in: path
        required: true
        schema: { type: string, format: uuid }
    get:
      tags: [audit]
      summary: Détail d'un événement d'audit, avec sa signature
      responses:
        "200":
          description: Événement
          content:
            application/json:
              schema: { $ref: "#/components/schemas/AuditEvent" }

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  parameters:
    Page:
      name: page
      in: query
      schema: { type: integer, minimum: 1, default: 1 }
    PageSize:
      name: pageSize
      in: query
      schema: { type: integer, minimum: 1, maximum: 100, default: 20 }
    SessionId:
      name: sessionId
      in: path
      required: true
      schema: { type: string, format: uuid }

  schemas:
    Error:
      type: object
      required: [code, message]
      properties:
        code: { type: string, example: "SESSION_DENIED" }
        message: { type: string }
        traceId: { type: string }

    PagedResponse:
      type: object
      properties:
        page: { type: integer }
        pageSize: { type: integer }
        totalItems: { type: integer }

    LoginRequest:
      type: object
      required: [username, password]
      properties:
        username: { type: string }
        password: { type: string, format: password }

    TokenPair:
      type: object
      properties:
        accessToken: { type: string }
        refreshToken: { type: string }
        expiresIn: { type: integer, description: "secondes" }

    User:
      type: object
      properties:
        id: { type: string, format: uuid }
        username: { type: string }
        displayName: { type: string }
        identitySource: { type: string, enum: [local, oidc] }
        roles:
          type: array
          items: { type: string }

    SessionStatus:
      type: string
      enum: [pending_approval, active, expired, terminated, denied]

    SessionRequest:
      type: object
      required: [targetAccountId, protocol, justification]
      properties:
        targetAccountId: { type: string, format: uuid, description: "Réfère un PrivilegedAccount du Vault" }
        protocol: { type: string, enum: [ssh] }
        justification: { type: string, minLength: 10 }
        durationMinutes: { type: integer, default: 60, maximum: 480 }

    Session:
      type: object
      properties:
        id: { type: string, format: uuid }
        status: { $ref: "#/components/schemas/SessionStatus" }
        protocol: { type: string }
        targetHost: { type: string }
        requestedBy: { type: string, format: uuid }
        justification: { type: string }
        createdAt: { type: string, format: date-time }
        expiresAt: { type: string, format: date-time }

    ConnectionTicket:
      type: object
      properties:
        proxyEndpoint: { type: string, example: "ssh-proxy.internal:2222" }
        ticket: { type: string, description: "Jeton à usage unique, consommé par le SSH Proxy" }
        expiresAt: { type: string, format: date-time }

    CommandRecording:
      type: object
      properties:
        sessionId: { type: string }
        page: { type: integer, description: "Page réellement servie (la page demandée, ramenée à 1 si < 1)" }
        pageSize: { type: integer, description: "Taille réellement servie (défaut 20, maximum 100)" }
        totalEntries: { type: integer, description: "Nombre total de commandes enregistrées pour la session" }
        entries:
          type: array
          items:
            type: object
            properties:
              timestamp: { type: string, format: date-time }
              command: { type: string }

    PrivilegedAccountInput:
      type: object
      required: [name, username, targetHost, protocol]
      properties:
        name: { type: string }
        username: { type: string, description: "Compte sur la cible — distinct de name, qui identifie l'enregistrement (doc 06 §3)." }
        targetHost: { type: string }
        protocol: { type: string, enum: [ssh] }
        rotationPolicy: { type: string, enum: [manual, post_use, scheduled], default: post_use }

    PrivilegedAccount:
      allOf:
        - $ref: "#/components/schemas/PrivilegedAccountInput"
        - type: object
          properties:
            id: { type: string, format: uuid }
            lastRotatedAt: { type: string, format: date-time }
            createdAt: { type: string, format: date-time }
            disabledAt: { type: string, format: date-time, description: "Absent tant que le compte est actif. Posé par DELETE /vault/accounts/{id} (suppression logique — doc 06 §3) ; un compte avec ce champ renseigné n'apparaît plus dans GET /vault/accounts et GET /vault/accounts/{id} répond 404." }

    PolicyInput:
      type: object
      required: [name, role, resourcePattern, effect]
      properties:
        name: { type: string }
        role: { type: string }
        resourcePattern: { type: string, example: "vault:account:prod-*" }
        effect: { type: string, enum: [allow, deny] }

    Policy:
      allOf:
        - $ref: "#/components/schemas/PolicyInput"
        - type: object
          properties:
            id: { type: string, format: uuid }
            createdAt: { type: string, format: date-time }

    AuditEvent:
      type: object
      properties:
        id: { type: string, format: uuid }
        timestamp: { type: string, format: date-time }
        actor: { type: string }
        action:
          type: string
          example: "session.connect"
          description: >
            Famille `ressource.verbe`. Pour les sessions : `session.connect`,
            `session.terminate`, et — politique d'enregistrement obligatoire,
            ADR-0008 — `session.recording_unavailable` (session refusée à
            l'admission, recorder non prêt) et `session.recording_lost`
            (session terminée en cours de route parce qu'une commande n'a pas
            pu être enregistrée ; la commande n'a pas été exécutée). Ces deux
            événements portent `result = failure`.
        resourceType: { type: string }
        resourceId: { type: string }
        result: { type: string, enum: [success, failure] }
        signature: { type: string, description: "Signature de l'événement, base64" }
```

## 3. Table récapitulative des endpoints

| Endpoint | Méthode | Domaine | Description |
|---|---|---|---|
| `/auth/login` | POST | auth | Authentification locale ou fédérée OIDC |
| `/auth/token/refresh` | POST | auth | Renouvellement de jeton |
| `/auth/me` | GET | auth | Profil courant |
| `/sessions` | GET / POST | sessions | Lister / demander une session |
| `/sessions/{id}` | GET / DELETE | sessions | Détail / terminaison |
| `/sessions/{id}/connect` | POST | sessions | Ticket de connexion vers le SSH Proxy |
| `/sessions/{id}/recording` | GET | sessions | Enregistrement texte de la session |
| `/vault/accounts` | GET / POST | vault | Lister / onboarder un compte privilégié |
| `/vault/accounts/{id}` | GET / DELETE | vault | Détail / suppression |
| `/vault/accounts/{id}/rotate` | POST | vault | Rotation manuelle |
| `/policies` | GET / POST | policies | Politiques RBAC |
| `/audit/events` | GET | audit | Recherche d'événements d'audit |
| `/audit/events/{id}` | GET | audit | Détail d'un événement, avec signature |

## 4. Extensions prévues (hors MVP, non rupturantes)

- v1.0 ajoutera `/sessions/{id}/approve`, `/sessions/{id}/reject` (Workflow/Approval Engine), `/mfa/*` (MFA Service natif), et des variantes de `protocol` (`rdp`, `vnc`, `database`, `kubernetes`) sur `SessionRequest`.
- v2.0 étendra l'énumération `protocol` aux familles restantes (`docker`, `hypervisor`, `winrm`, `telnet`, `http`) et ajoutera `/risk/scores`.
- Toute extension se fait par ajout de champs optionnels et de nouveaux endpoints — jamais par modification d'un champ existant sur `/api/v1`, conformément à la convention de versionning (§1).

## 5. Prochaine étape

Le document suivant établit le **modèle de données PostgreSQL** sous-jacent à ces contrats (tables `sessions`, `privileged_accounts`, `policies`, `audit_events`, et leurs relations).

---
*Document suivant : `OpenBastion_06_Modele_Donnees.md`*
