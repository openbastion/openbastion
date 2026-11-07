# Composants (C4, niveau 3)

## Conteneur « Accès & Session »

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

## Conteneur « Couche Proxy »

```mermaid
C4Component
    title Composants — Couche Proxy

    Container_Boundary(proxy, "Couche Proxy") {
        Component(ssh, "SSH/SFTP/SCP Proxy", "Go")
        Component(rdp, "RDP/VNC Proxy", "Go", "Client VNC RFB 3.8 en fondation ; service proxy à venir (ADR-0071)")
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

## Conteneur « Vault & Secrets »

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

## Conteneur « Enregistrement & Audit »

```mermaid
C4Component
    title Composants — Enregistrement & Audit

    Container_Boundary(rec, "Enregistrement & Audit") {
        Component(sr, "Session Recorder", "Go", "Orchestration du cycle de vie d'un enregistrement")
        Component(vr, "Video Recorder", "Go", "Persistance et replay de segments PNG ; producteur graphique à raccorder (ADR-0071)")
        Component(cr, "Command Recorder", "Go", "Capture texte SSH/DB/K8s")
        Component(aud, "Audit Service", "Go", "Journal immuable et signé")
        Component(se, "Recherche", "Go", "Dans le Command Recorder et le Session Broker, sans index (ADR-0080)")
        Component(rep, "Reporting Service", "Go", "Rapports de conformité")
    }

    Container(proxy, "Couche Proxy")
    ContainerDb(objects, "Stockage objet S3-compatible")
    Container(kafka, "Kafka")

    Rel(proxy, sr, "Flux clipboard / transfert fichiers / impression")
    Rel(proxy, vr, "Flux pixel (producteur prévu par ADR-0069)")
    Rel(proxy, cr, "Flux commande")
    Rel(sr, aud, "Événements signés")
    Rel(vr, objects, "Segments vidéo chiffrés")
    Rel(cr, aud, "Événements de session")
    Rel(aud, kafka, "Streaming durable")
    Rel(kafka, se, "Indexation")
    Rel(rep, objects, "Agrégation")
```

## Conteneur « Gouvernance »

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

## Conteneurs « Sécurité & Intelligence » et « Fédération d'identité » — synthèse

Ces deux conteneurs sont volontairement présentés sous forme de table plutôt qu'en diagramme, leur structure interne étant peu ramifiée à ce stade :

| Conteneur | Composant | Rôle |
|---|---|---|
| Sécurité & Intelligence | MFA Service | TOTP, WebAuthn/FIDO2, YubiKey, Passkeys, carte à puce/PKI |
| Sécurité & Intelligence | Anomaly Detection / Risk Engine | Score de risque par règles, brique ML optionnelle |
| Fédération d'identité | LDAP Connector | Auth/synchro LDAP/OpenLDAP |
| Fédération d'identité | Active Directory Connector | Auth/synchro AD, Kerberos |
| Fédération d'identité | Entra ID Connector | Profil OIDC lié à un tenant (ADR-0079) ; ni SAML ni Graph API à ce jour |
| Fédération d'identité | OpenID Connect Connector | OIDC/OAuth2 générique |
| Fédération d'identité | SAML Connector | SAML 2.0 générique |
| Fédération d'identité | SCIM Provisioning Service | Provisioning/déprovisioning automatique |
