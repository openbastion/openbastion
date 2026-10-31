# Contexte du système (C4, niveau 1)

## Notation

| Niveau | Question à laquelle il répond | Granularité |
|---|---|---|
| **1 — Contexte** | Qui utilise OpenBastion et avec quoi interagit-il ? | Le système comme boîte noire |
| **2 — Conteneurs** | De quels grands blocs déployables OpenBastion est-il composé ? | Applications, services, magasins de données |
| **3 — Composants** | Comment un conteneur est-il structuré en interne ? | Microservices / modules au sein d'un conteneur |

Les diagrammes sont exprimés en Mermaid (syntaxe C4) pour rester versionnés en texte aux côtés du code (docs-as-code), conformément à la convention documentaire du projet.

## Niveau 1 — Diagramme de contexte système

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
