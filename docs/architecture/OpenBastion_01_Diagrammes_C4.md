# OpenBastion — Diagrammes C4

**Version** 0.1 · **Statut** Draft de travail
**Document précédent** `OpenBastion_00_Architecture_Globale.md`
**Portée** Formalisation visuelle de l'architecture selon le modèle C4 (Simon Brown) : Contexte → Conteneurs → Composants. Le niveau 4 (Code) est volontairement exclu à ce stade, aucune ligne de code n'ayant encore été écrite.

---

## 1. Notation

| Niveau | Question à laquelle il répond | Granularité |
|---|---|---|
| **1 — Contexte** | Qui utilise OpenBastion et avec quoi interagit-il ? | Le système comme boîte noire |
| **2 — Conteneurs** | De quels grands blocs déployables OpenBastion est-il composé ? | Applications, services, magasins de données |
| **3 — Composants** | Comment un conteneur est-il structuré en interne ? | Microservices / modules au sein d'un conteneur |

Les diagrammes sont exprimés en Mermaid (syntaxe C4) pour rester versionnés en texte aux côtés du code (docs-as-code), conformément à la convention documentaire du projet.

---

## 2. Niveau 1 — Diagramme de contexte système

```mermaid
C4Context
    title Contexte système — OpenBastion

    Person(admin, "Administrateur PAM", "Configure politiques, comptes, workflows, connecteurs")
    Person(operator, "Opérateur privilégié", "Demande et utilise des accès à des systèmes cibles")
    Person(approver, "Approbateur", "Valide ou refuse les demandes d'accès sensibles")
    Person(auditor, "Auditeur / RSSI", "Consulte enregistrements, audit et rapports de conformité")

    System(ob, "OpenBastion", "Plateforme PAM cloud-native : centralise, proxifie, enregistre et audite tous les accès privilégiés")

    System_Ext(idp, "Fournisseurs d'identité", "LDAP, Active Directory, Entra ID, OIDC, SAML")
    System_Ext(chat, "Outils de notification", "Slack, Teams, email")
    System_Ext(itsm, "Outils ITSM", "ServiceNow, Jira — tickets obligatoires")
    System_Ext(targets, "Systèmes cibles", "Serveurs, bases de données, conteneurs/K8s, hyperviseurs, matériel IPMI, consoles web")

    Rel(admin, ob, "Configure et administre")
    Rel(operator, ob, "Demande et utilise un accès")
    Rel(approver, ob, "Valide une demande")
    Rel(auditor, ob, "Consulte audit / replay / rapports")

    Rel(ob, idp, "Authentifie et fédère les identités via")
    Rel(ob, chat, "Notifie et recueille les approbations via")
    Rel(ob, itsm, "Vérifie l'existence d'un ticket via")
    Rel(ob, targets, "Établit une connexion proxifiée et éphémère vers", "SSH/RDP/VNC/SQL/K8s/IPMI/HTTPS…")
```

**Lecture** : OpenBastion est le seul point de passage entre les humains (opérateurs, approbateurs, administrateurs, auditeurs) et les systèmes cibles. Aucune flèche ne relie directement un acteur humain à un système cible — c'est la traduction visuelle du principe *No Direct Access*.

---

## 3. Niveau 2 — Diagramme de conteneurs

```mermaid
C4Container
    title Conteneurs — OpenBastion

    Person(operator, "Opérateur / Administrateur / Approbateur / Auditeur")

    System_Boundary(ob, "OpenBastion") {
        Container(auiu, "Administration UI", "React / TypeScript / Vite", "Console d'administration : comptes, politiques, secrets, audit, reporting")
        Container(portal, "User Portal", "React / TypeScript / Vite", "Portail self-service : demande d'accès, sessions actives, historique")
        Container(desktop, "Desktop Client", "Tauri", "Client natif pour sessions RDP/SSH avec intégration OS")
        Container(cli, "CLI", "Go", "Automatisation et intégration CI/CD")
        Container(sdk, "SDKs", "Go, Python, Java, JavaScript", "Intégration programmatique tierce")

        Container(gw, "API Gateway", "Go", "Point d'entrée unique HTTP/gRPC, routage, rate-limiting, validation")

        Container(access, "Accès & Session", "Go", "Authentification, autorisation, orchestration de session (Authn, Authz, Session Broker)")
        Container(proxy, "Couche Proxy", "Go", "9 proxies protocolaires — seuls composants détenant un secret en mémoire, transitoirement")
        Container(vault, "Vault & Secrets", "Go", "Password Vault + Secrets Manager, rotation et secrets dynamiques")
        Container(rec, "Enregistrement & Audit", "Go", "Session/Video/Command Recorder, Audit Service, Search Engine, Reporting")
        Container(gov, "Gouvernance", "Go", "Workflow Service, Approval Engine, Notification Service")
        Container(sec, "Sécurité & Intelligence", "Go", "MFA Service, Anomaly Detection / Risk Engine")
        Container(fed, "Fédération d'identité", "Go", "Connecteurs LDAP, AD, Entra ID, OIDC, SAML, SCIM")
        Container(sched, "Scheduler", "Go", "Tâches planifiées : rotations, expirations, rapports")

        ContainerDb(pg, "PostgreSQL", "Base relationnelle", "Comptes, politiques, métadonnées de session, workflows")
        ContainerDb(redis, "Redis", "Cache", "Sessions actives, verrous, rate-limiting")
        ContainerDb(search, "OpenSearch", "Moteur de recherche", "Index audit et sessions")
        ContainerDb(minio, "MinIO", "Stockage objet", "Enregistrements vidéo/commande chiffrés")
        Container(nats, "NATS", "Bus événementiel", "Coordination temps réel")
        Container(kafka, "Kafka", "Bus de streaming", "Streaming durable d'audit")
        Container(kc, "Keycloak", "IdP", "Identité de plateforme et fédération")
    }

    System_Ext(idp, "IdP externes")
    System_Ext(chat, "Slack / Teams")
    System_Ext(itsm, "ServiceNow / Jira")
    System_Ext(targets, "Systèmes cibles")

    Rel(operator, auiu, "HTTPS")
    Rel(operator, portal, "HTTPS")
    Rel(operator, desktop, "Sessions RDP/SSH")
    Rel(operator, cli, "CLI")

    Rel(auiu, gw, "REST/gRPC", "mTLS")
    Rel(portal, gw, "REST/gRPC", "mTLS")
    Rel(desktop, gw, "REST/gRPC", "mTLS")
    Rel(cli, gw, "REST/gRPC", "mTLS")
    Rel(sdk, gw, "REST/gRPC", "mTLS")

    Rel(gw, access, "gRPC", "mTLS")
    Rel(access, gov, "gRPC", "mTLS")
    Rel(access, proxy, "gRPC", "mTLS")
    Rel(access, sec, "gRPC", "mTLS")
    Rel(proxy, vault, "gRPC — récupération credential éphémère", "mTLS")
    Rel(proxy, rec, "Flux session", "mTLS")
    Rel(rec, search, "Indexation")
    Rel(rec, minio, "Stockage artefacts")
    Rel(gov, chat, "Webhooks")
    Rel(gov, itsm, "API")
    Rel(fed, idp, "LDAP/OIDC/SAML")
    Rel(proxy, targets, "SSH/RDP/VNC/SQL/K8s/IPMI/HTTPS")

    Rel(access, pg, "SQL")
    Rel(vault, pg, "SQL")
    Rel(gov, pg, "SQL")
    Rel(access, redis, "Cache session")
    Rel(access, nats, "Pub/Sub")
    Rel(rec, kafka, "Streaming audit")
    Rel(access, kc, "OIDC")
```

### Table de correspondance conteneurs → technologie

| Conteneur | Nature | Technologie |
|---|---|---|
| Administration UI, User Portal | Application web | React / TypeScript / Vite |
| Desktop Client | Application native | Tauri |
| CLI | Binaire | Go |
| SDKs | Bibliothèques | Go, Python, Java, JavaScript |
| API Gateway | Service | Go, Envoy (data plane) |
| Accès & Session, Proxy Layer, Vault & Secrets, Enregistrement & Audit, Gouvernance, Sécurité & Intelligence, Fédération d'identité, Scheduler | Groupes de microservices | Go |
| PostgreSQL, Redis, OpenSearch, MinIO | Magasins de données | — |
| NATS, Kafka | Bus de messages | — |
| Keycloak | Identity Provider | — |

Chaque conteneur backend listé ci-dessus regroupe plusieurs microservices détaillés au niveau 3.

---

## 4. Niveau 3 — Diagrammes de composants

### 4.1 Conteneur « Accès & Session »

```mermaid
C4Component
    title Composants — Accès & Session

    Container_Boundary(access, "Accès & Session") {
        Component(authn, "Authentication Service", "Go", "Authentifie l'opérateur, émet des JWT courte durée")
        Component(authz, "Authorization Service", "Go", "Point de décision RBAC/ABAC")
        Component(broker, "Session Broker", "Go", "Orchestrateur : déclenche workflow, sélectionne le proxy, demande le credential")
    }

    Container(gw, "API Gateway")
    Container(gov, "Gouvernance")
    Container(proxy, "Couche Proxy")
    Container(sec, "Sécurité & Intelligence")
    Container(fed, "Fédération d'identité")
    ContainerDb(redis, "Redis")

    Rel(gw, authn, "Authentifie")
    Rel(gw, authz, "Vérifie l'autorisation")
    Rel(gw, broker, "Crée la demande de session")
    Rel(authn, fed, "Délègue si identité fédérée")
    Rel(broker, gov, "Déclenche workflow si requis")
    Rel(broker, sec, "Demande un score de risque")
    Rel(broker, proxy, "Établit la session")
    Rel(authz, redis, "Cache des décisions")
```

### 4.2 Conteneur « Couche Proxy »

```mermaid
C4Component
    title Composants — Couche Proxy

    Container_Boundary(proxy, "Couche Proxy") {
        Component(ssh, "SSH/SFTP/SCP Proxy", "Go")
        Component(rdp, "RDP/VNC Proxy", "Go")
        Component(tel, "Telnet/Serial-IPMI Proxy", "Go")
        Component(winrm, "WinRM Proxy", "Go")
        Component(db, "Database Proxy", "Go")
        Component(k8s, "Kubernetes Proxy", "Go")
        Component(docker, "Docker Proxy", "Go")
        Component(hyp, "Hypervisor Console Proxy", "Go")
        Component(web, "HTTP/HTTPS Web Proxy", "Go")
    }

    Container(broker, "Session Broker")
    Container(vault, "Vault & Secrets")
    Container(rec, "Enregistrement & Audit")
    System_Ext(targets, "Systèmes cibles")

    Rel(broker, ssh, "Route selon protocole")
    Rel(broker, rdp, "Route selon protocole")
    Rel(broker, tel, "Route selon protocole")
    Rel(broker, winrm, "Route selon protocole")
    Rel(broker, db, "Route selon protocole")
    Rel(broker, k8s, "Route selon protocole")
    Rel(broker, docker, "Route selon protocole")
    Rel(broker, hyp, "Route selon protocole")
    Rel(broker, web, "Route selon protocole")

    Rel(ssh, vault, "Credential éphémère", "mTLS, mémoire uniquement")
    Rel(rdp, vault, "Credential éphémère", "mTLS, mémoire uniquement")
    Rel(db, vault, "Credential éphémère", "mTLS, mémoire uniquement")

    Rel(ssh, targets, "Connexion directe")
    Rel(rdp, targets, "Connexion directe")
    Rel(k8s, targets, "Connexion directe")

    Rel(ssh, rec, "Flux commande")
    Rel(rdp, rec, "Flux vidéo")
```

**Note d'implémentation** : les neuf proxies partagent un pipeline commun (négociation, injection de credential, capture, purge mémoire) implémenté comme bibliothèque interne partagée plutôt que dupliqué — détail qui sera traité dans les ADR et les spécifications d'interfaces inter-services.

### 4.3 Conteneur « Vault & Secrets »

```mermaid
C4Component
    title Composants — Vault & Secrets

    Container_Boundary(vault, "Vault & Secrets") {
        Component(pv, "Password Vault", "Go", "Comptes privilégiés : mots de passe, clés SSH, certificats de compte")
        Component(sm, "Secrets Manager", "Go", "API keys, tokens, secrets dynamiques à durée de vie courte")
        Component(rot, "Rotation Engine", "Go", "Rotation automatique, planifiée, post-usage")
        Component(disc, "Discovery Engine", "Go", "Découverte automatique de comptes privilégiés")
    }

    Container(proxy, "Couche Proxy")
    Container(sched, "Scheduler")
    ContainerDb(pg, "PostgreSQL — secrets chiffrés au repos")

    Rel(proxy, pv, "Demande credential éphémère", "mTLS")
    Rel(proxy, sm, "Demande secret dynamique", "mTLS")
    Rel(sched, rot, "Déclenche rotation planifiée")
    Rel(rot, pv, "Effectue la rotation")
    Rel(disc, pv, "Alimente en comptes découverts")
    Rel(pv, pg, "Persistance chiffrée AES-256")
    Rel(sm, pg, "Persistance chiffrée AES-256")
```

### 4.4 Conteneur « Enregistrement & Audit »

```mermaid
C4Component
    title Composants — Enregistrement & Audit

    Container_Boundary(rec, "Enregistrement & Audit") {
        Component(sr, "Session Recorder", "Go", "Orchestration du cycle de vie d'un enregistrement")
        Component(vr, "Video Recorder", "Go", "Capture pixel RDP/VNC")
        Component(cr, "Command Recorder", "Go", "Capture texte SSH/DB/K8s")
        Component(aud, "Audit Service", "Go", "Journal immuable et signé")
        Component(se, "Search Engine", "Go", "Indexation et recherche")
        Component(rep, "Reporting Service", "Go", "Rapports de conformité")
    }

    Container(proxy, "Couche Proxy")
    ContainerDb(minio, "MinIO")
    ContainerDb(search, "OpenSearch")
    Container(kafka, "Kafka")

    Rel(proxy, sr, "Flux clipboard / transfert fichiers / impression")
    Rel(proxy, vr, "Flux pixel")
    Rel(proxy, cr, "Flux commande")
    Rel(sr, aud, "Événements signés")
    Rel(vr, minio, "Artefacts vidéo chiffrés")
    Rel(cr, minio, "Logs commande chiffrés")
    Rel(aud, kafka, "Streaming durable")
    Rel(kafka, se, "Indexation")
    Rel(se, search, "Stockage index")
    Rel(rep, search, "Agrégation")
```

### 4.5 Conteneur « Gouvernance »

```mermaid
C4Component
    title Composants — Gouvernance

    Container_Boundary(gov, "Gouvernance") {
        Component(wf, "Workflow Service", "Go", "Machine à états de la demande d'accès")
        Component(apr, "Approval Engine", "Go", "Évalue les politiques d'approbation")
        Component(notif, "Notification Service", "Go", "Relais Slack/Teams/email/webhook")
    }

    Container(broker, "Session Broker")
    System_Ext(chat, "Slack / Teams")
    System_Ext(itsm, "ServiceNow / Jira")

    Rel(broker, wf, "Initie le workflow")
    Rel(wf, apr, "Demande évaluation")
    Rel(apr, itsm, "Vérifie ticket obligatoire")
    Rel(apr, notif, "Déclenche notification d'approbation")
    Rel(notif, chat, "Envoie et recueille la décision")
    Rel(apr, wf, "Retourne la décision")
    Rel(wf, broker, "Session autorisée / refusée")
```

### 4.6 Conteneurs « Sécurité & Intelligence » et « Fédération d'identité » — synthèse

Ces deux conteneurs sont volontairement présentés sous forme de table plutôt qu'en diagramme, leur structure interne étant peu ramifiée à ce stade :

| Conteneur | Composant | Rôle |
|---|---|---|
| Sécurité & Intelligence | MFA Service | TOTP, WebAuthn/FIDO2, YubiKey, Passkeys, carte à puce/PKI |
| Sécurité & Intelligence | Anomaly Detection / Risk Engine | Score de risque par règles, brique ML optionnelle |
| Fédération d'identité | LDAP Connector | Auth/synchro LDAP/OpenLDAP |
| Fédération d'identité | Active Directory Connector | Auth/synchro AD, Kerberos |
| Fédération d'identité | Entra ID Connector | OIDC/SAML + Graph API |
| Fédération d'identité | OpenID Connect Connector | OIDC/OAuth2 générique |
| Fédération d'identité | SAML Connector | SAML 2.0 générique |
| Fédération d'identité | SCIM Provisioning Service | Provisioning/déprovisioning automatique |

---

## 5. Traçabilité — conteneurs ↔ catalogue de microservices

| Conteneur (Niveau 2) | Microservices correspondants (doc 00, §4) |
|---|---|
| Accès & Session | API Gateway*, Authentication Service, Authorization Service, Session Broker |
| Couche Proxy | 9 proxies protocolaires (§4.2) |
| Vault & Secrets | Password Vault, Secrets Manager |
| Enregistrement & Audit | Session/Video/Command Recorder, Audit Service, Search Engine, Reporting Service |
| Gouvernance | Workflow Service, Approval Engine, Notification Service |
| Sécurité & Intelligence | MFA Service, Anomaly Detection / Risk Engine |
| Fédération d'identité | LDAP, AD, Entra ID, OIDC, SAML Connectors, SCIM Provisioning Service |
| Scheduler | Scheduler |

*L'API Gateway est représenté comme conteneur autonome au niveau 2 (point d'entrée), regroupé ici pour la traçabilité.

---

## 6. Prochaine étape

Le document suivant détaille l'**arborescence complète du dépôt Git** (organisation monorepo, structure par microservice, conventions de nommage des packages Go et des modules frontend).

---
*Document suivant : `OpenBastion_02_Arborescence_Depot.md`*
