# Architecture du framework d'agents distribués

**Jalon** : v0.0.3 · **Statut** : architecture proposée, liée aux ADR-0102 à ADR-0110.

Cette page décrit la cible d'architecture. Elle ne signifie pas que les agents ou les services de contrôle sont déjà implémentés.

## 1. Principes

- Séparer le plan de transport réseau (Network Agent) du plan de collecte (Security Agent).
- Garder l'authentification et l'autorisation des utilisateurs dans les services centraux.
- Garder la terminaison protocolaire et les credentials de cible dans les proxies.
- N'ouvrir un tunnel qu'avec une capacité éphémère, liée à une session et à une destination.
- Traiter toute donnée venant d'un hôte administré comme une observation potentiellement falsifiable.
- Fermer les tunnels à la perte du canal de contrôle ; ne pas reprendre une session sans nouvelle décision.
- Ne pas ajouter de chemin d'exécution de commande arbitraire.

## 2. Vue C4 — conteneurs

~~~mermaid
flowchart TB
  OP[Administrateur] --> PORTAL[Admin UI / User Portal]
  PORTAL --> GW[API Gateway]
  GW --> AUTH[Authentication Service]
  GW --> AZ[Authorization Service]
  GW --> BROKER[Session Broker]
  BROKER --> PROXY[Protocol Proxy]
  PROXY --> ACTRL[Agent Control]
  ACTRL <-->|gRPC bidi · TLS 1.3 · mTLS| NA[Network Agent]
  NA --> TARGET[Hôtes et services privés]
  SA[Security Agent] -->|gRPC telemetry · mTLS| ATEL[Agent Telemetry]
  ATEL --> INGEST[Normalisation / stockage télémétrie]
  INGEST --> TS[Stockage télémétrie / détection]
  INGEST --> AUDIT[Audit Service · métadonnées de réception et qualité seulement]
  BROKER --> AUDIT
  PROXY --> AUDIT
  RELEASE[Chaîne de livraison signée] --> NA
  RELEASE --> SA
~~~

| Conteneur | Responsabilité | Identité / privilèges |
|---|---|---|
| Agent Registry / Enrollment | Inventaire, enrôlement, certificats, révocation | Service mTLS dédié ; accès à l'autorité PKI |
| Agent Control | Présence, capacités, multiplexage et révocation des tunnels | Service mTLS ; n'émet pas de credentials cible |
| Agent Telemetry | Réception, validation, acquittement et provenance des observations | Service mTLS ; ne transforme pas les observations en actions PAM |
| Network Agent | Connexion sortante et sockets TCP explicitement autorisées | Compte système dédié, sans root permanent |
| Security Agent | Collecte hôte en lecture seule | Processus et identité séparés ; helpers privilégiés étroits seulement |

## 3. Chemin d'une session

~~~mermaid
sequenceDiagram
  actor User as Opérateur
  participant Auth as Authentication
  participant AZ as Authorization
  participant Broker as Session Broker
  participant Proxy as Proxy protocolaire
  participant Control as Agent Control
  participant Agent as Network Agent
  participant Target as Cible

  User->>Auth: Authentification + MFA
  Auth-->>User: Identité vérifiée
  User->>Broker: Demande de session
  Broker->>AZ: Évaluer la politique
  AZ-->>Broker: Autorisation
  Broker->>Proxy: Établir la session
  Proxy->>Control: Demander un tunnel vers la ressource
  Control->>Agent: OpenTunnel + capacité JWS
  Agent->>Agent: Vérifier identité, jti, politique locale et destination
  Agent->>Target: Dial TCP vers IP/port autorisés
  Agent-->>Proxy: Flux TCP multiplexé
  Proxy->>Target: Terminaison SSH/RDP/VNC/SQL et médiation PAM
  Note over Proxy: Le credential cible reste dans le proxy
  User->>Target: Échanges protocole via le proxy
  Broker->>Control: Révocation
  Control->>Agent: CloseTunnel
  Agent-->>Control: TunnelClosed
~~~

Le diagramme est conceptuel : le proxy échange les données avec la cible à travers le transport de tunnel fourni par l'agent. L'agent ne reçoit jamais le secret cible.

## 4. Flux de télémétrie

Security Agent collecte des événements structurés en lecture seule. Il les envoie par un flux mTLS distinct. Agent Telemetry vérifie l'identité issue du certificat, les limites, le schéma et la séquence ; il acquitte uniquement les événements acceptés.

Les observations sont stockées dans un stockage de télémétrie dédié avec une provenance explicite `host-agent`. Audit Service ne reçoit que les événements de réception, de révocation, de perte ou de qualité de collecte ; le contenu brut des observations n'est pas injecté dans la chaîne d'audit faisant autorité. L'Audit Service conserve les décisions du Broker et les événements des proxies selon ADR-0025 à ADR-0028.

## 5. Frontières de confiance

| Frontière | Données traversantes | Contrôles |
|---|---|---|
| Gateway / services PAM | identité opérateur et demande de session | JWT/MFA, RBAC/ABAC, mTLS interne |
| Proxy / Agent Control | identifiant session, ressource, IP/port et capacité | identité mTLS, autorisation par route, JWS éphémère |
| Agent Control / Network Agent | ordres tunnel et trames TCP | mTLS, séquences, quotas, bornes, révocation |
| Network Agent / réseau privé | connexion TCP sortante | IP littérale, politique locale, ports/CIDR autorisés |
| Security Agent / Agent Telemetry | lots d'observations | mTLS, séquences, validation et limites |
| Network Agent / Security Agent | aucune interface de contrôle partagée | processus, comptes, clés et IPC séparés |
| Livraison / agents | binaires et politiques | signature, provenance, SBOM, anti-rollback |

## 6. Déploiement et disponibilité

- Un ou plusieurs Network Agents peuvent être déployés par site ; chaque agent a une identité distincte.
- Les agents initient les connexions sortantes vers les endpoints Agent Control déclarés.
- Les endpoints serveur sont épinglés ; aucune validation TLS n'est désactivée en production.
- Les pare-feu des cibles refusent les connexions privilégiées directes depuis les zones opérateurs et n'autorisent que les sources Network Agent déclarées. L'agent ne peut pas empêcher seul un chemin réseau alternatif.
- Le registre partage l'état d'identité, de révocation et de génération de politique entre replicas.
- Un agent ne maintient qu'un flux de contrôle actif par génération d'identité.
- La perte du flux ferme les tunnels ; la reprise exige une nouvelle session, une nouvelle autorisation et une nouvelle capacité.
- Le Security Agent peut être absent sans désactiver les contrôles PAM ; l'absence de télémétrie est visible et ne vaut pas preuve d'absence d'activité.

## 7. Contrats et décisions

Les contrats Protobuf proposés sont dans `proto/agent/v1/`. L'exception gRPC est limitée aux flux agent ↔ services Agent Control/Agent Telemetry. Les RPC entre microservices restent HTTP/JSON sous mTLS (ADR-0050).

- ADR-0102 : séparation des agents.
- ADR-0103 : tunnel sortant et transport.
- ADR-0104 : PKI et enrôlement.
- ADR-0105 : capacités et destinations.
- ADR-0106 : isolation et privilèges.
- ADR-0107 : télémétrie.
- ADR-0108 : mises à jour.
- ADR-0109 : haute disponibilité.
- ADR-0110 : provenance et audit.

## 8. Hors périmètre

Aucun agent de production, exécuteur distant, EDR, réponse automatique, SOCKS, UDP, VPN L3 ou accès direct aux credentials n'est livré par le jalon documentaire v0.0.3. Les détails de menace sont dans `docs/security/threat-model-agents.md`.
