# Feuille de route MVP → v0.0.1 → v0.0.2 → v0.0.3

Séquencement du périmètre fonctionnel, sans estimation calendaire. Les versions suivent Semantic Versioning (ADR-0063, [`development/versioning.md`](development/versioning.md)) : les anciens jalons « v1.0 » et « v2.0 » sont devenus **v0.0.1** et **v0.0.2**.

## 0. État d'avancement — 18 novembre 2026

La roadmap décrit les jalons de livraison ; elle ne signifie pas qu'une fonction inscrite dans une phase est déjà disponible.

- **MVP SSH/SFTP/SCP** : parcours fonctionnel de référence, avec Gateway, Broker, Vault, proxy SSH, audit et replay texte.
- **VNC** : parcours de bout en bout validé avec TigerVNC 1.13.1, incluant Gateway, Broker, Vault, proxy écran et Video Recorder. Le replay est disponible par API et dans l'Admin UI (lecteur d'écran enregistré, page « Enregistrements ») ; plusieurs fonctions de redirection restent à faire.
- **Marqueurs de relecture vidéo (ADR-0111)** : contrat Protobuf, stockage append-only, RPC mTLS proxy/Gateway et route REST paginée implémentés dans la branche de réalisation ; le raccordement à la transaction d’injection Vault VNC/RDP et l’affichage dans la timeline Admin UI restent à intégrer.
- **Rapprochement des injections Vault (ADR-0112)** : projection en lecture seule sur chaîne retenue et archives vérifiées, route interne mTLS `admin-cli` et commande `openbastion-cli audit secret-injections` implémentées. La façade Gateway et le composant Admin UI `SecretInjectionReconciliation` sont livrés sous ADR-0113/0114. Restent le test multi-processus de perte de l’acquittement Audit après frappe et le scénario PostgreSQL 16 archive → redémarrage → relecture. Les politiques historiques conservent `action_pattern=*` par compatibilité ; leur réduction vers des actions explicites reste un travail de durcissement.
- **RDP** : moteur Go pur ([ADR-0071](adr/0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md)), éprouvé contre FreeRDP 3 et Windows Server 2022 en CI :
  - CredSSP/NTLMv2 avec certificat épinglé avant tout secret ;
  - image en 15, 16 et 32 bpp, fragments Fast-Path, réactivation ;
  - clavier QWERTY et AZERTY vérifiés, reprise de session ;
  - enregistrement rejouable à l'octet, `recording_lost` au-delà de 4 Mio.

  Il est ouvert aux opérateurs **par défaut depuis le 13 novembre 2026** (`RDP_ENABLED=false` le ferme) ([ADR-0088](adr/0088-rdp-ouvert-aux-operateurs-par-la-route-ecran-derriere-un-interrupteur.md)). Le texte est rendu par bitmaps, sans cache de glyphes ([ADR-0089](adr/0089-le-texte-rdp-reste-rendu-par-bitmaps-sans-cache-de-glyphes.md)). Ni ordres graphiques annoncés, ni canaux virtuels, ni Kerberos, ni RD Gateway : c'est le plan v0.0.2 ([ADR-0090](adr/0090-rdp-v002-glyphes-ordres-canaux-et-protocoles.md), proposé).
- **Veille externe** : ADR-0081 propose une veille hebdomadaire de gopher-rdp, gordp et Casvisor afin d'identifier les évolutions utiles sans adopter automatiquement leur code ou leurs choix de sécurité.

La source de vérité opérationnelle pour les capacités réellement présentes, leurs tests et leurs limites est [`docs/security/known-limitations.md`](security/known-limitations.md). Toute activation runtime ou preuve d'interopérabilité doit être reflétée ici et dans le README.

## 1. Principe de séquencement

Deux règles guident l'ordre de livraison :

1. **Prouver l'invariant avant d'étendre la couverture.** Le MVP doit démontrer de bout en bout, sur *un seul* protocole, la chaîne complète Zero Standing Privilege → No Direct Access → Full Auditability (ADR-0003) avant d'ajouter des protocoles supplémentaires. Mieux vaut un seul proxy solide que neuf proxies fragiles.
2. **L'audit n'est jamais optionnel.** Contrairement à d'autres fonctionnalités qui peuvent être différées, `Command Recorder` et `Audit Service` sont présents dès le MVP — *Full Auditability* est un principe fondateur (`docs/architecture/principles.md`), pas une fonctionnalité v2.

## 2. MVP — Prouver l'invariant sur un protocole

**Objectif** : un opérateur s'authentifie, obtient une session SSH sur un serveur cible sans jamais voir le mot de passe, et toute la session est journalisée et rejouable en texte.

| Domaine | Composants inclus |
|---|---|
| Périmètre & Accès | API Gateway, Authentication Service, Authorization Service (RBAC simple), Session Broker |
| Proxy | **SSH/SFTP/SCP Proxy** uniquement |
| Vault | Password Vault (rotation manuelle, post-usage et planifiée — cette dernière par un balayage du Vault, ADR-0040, en attendant le Scheduler complet) |
| Enregistrement & Audit | Session Recorder, Command Recorder, Audit Service |
| Fédération d'identité | OIDC Connector uniquement (MFA délégué au fournisseur d'identité externe) |
| Plateforme | Scheduler (expiration de session uniquement) |
| Clients | Admin UI (comptes, politiques, consultation d'audit), CLI |

**Explicitement hors périmètre du MVP** : tout protocole autre que SSH, Workflow/Approval Engine (octroi immédiat après autorisation RBAC, pas de validation multi-étapes), MFA Service dédié, Video/Search/Reporting, tous les connecteurs d'identité hors OIDC, User Portal, Desktop Client, SDKs, Risk Engine.

**Critères de sortie**
- Une session SSH complète est établie sans qu'aucun composant du control plane (Gateway, Broker) n'ait jamais eu le mot de passe en mémoire ou en log — vérifié par test de sécurité dédié (ADR-0003).
- Le replay texte d'une session retrouve chaque commande exécutée, horodatée.
- Déploiement reproductible via `docker-compose/` en environnement de développement.

## 3. v0.0.1 — Couverture protocolaire élargie et gouvernance complète

**Objectif** : couvrir les scénarios d'entreprise les plus courants (serveurs Windows/Linux, bases de données, Kubernetes) avec un vrai processus d'approbation et une fédération d'identité complète.

| Domaine | Composants ajoutés |
|---|---|
| Proxy | RDP/VNC Proxy, Database Proxy, Kubernetes Proxy |
| Gouvernance | Workflow Service, Approval Engine (validation N+1, ticket ServiceNow/Jira), notifications Slack/Teams (par les services qui les émettent, sans service dédié : ADR-0074) |
| Sécurité & Intelligence | MFA Service (TOTP, WebAuthn/FIDO2, YubiKey, Passkeys, carte à puce) |
| Vault | Secrets Manager (secrets applicatifs dynamiques) |
| Enregistrement & Audit | Video Recorder, recherche plein texte des commandes et des sessions, par déchiffrement à la volée dans une fenêtre bornée (ADR-0080 : sans index ni OpenSearch) |
| Fédération d'identité | LDAP Connector, Active Directory Connector, Entra ID Connector, SAML Connector, SCIM Provisioning |
| Plateforme | Scheduler complet (rotation planifiée et post-usage) |
| Clients | User Portal, Desktop Client (Tauri), SDK Go |

**État RDP/VNC dans cette phase** :
- **VNC** : parcours de bout en bout, rejoué dans l'Admin UI. Ni presse-papiers, ni interopérabilité RealVNC.
- **RDP** :
  - critères de sortie de l'incrément 3 d'ADR-0071 tenus contre Windows Server 2022 : session enregistrée et rejouable, texte lisible (par bitmaps, ADR-0089), capacités non annoncées refusées, QWERTY et AZERTY, `recording_lost` au-delà de 4 Mio ;
  - parcours depuis l'API publique prouvé contre FreeRDP 3 ;
  - l'ouverture aux opérateurs est le choix de l'exploitant (`RDP_ENABLED`, ADR-0088) ;
  - restent ouverts : la réactivation, jamais envoyée par Windows, et l'incrément 4 (durcissement et preuves).

Suivre [ADR-0071](adr/0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md), [ADR-0081](adr/0081-veille-rdp-externe-et-integration-selective.md) et [les limites connues](security/known-limitations.md).

**Explicitement hors périmètre v0.0.1** : Docker Proxy, Hypervisor Console Proxy, WinRM Proxy, Telnet/Serial-IPMI Proxy, HTTP/HTTPS Web Proxy, Risk Engine, Reporting Service, SDK Python/Java/JavaScript.

**Critères de sortie**
- Une demande d'accès peut être soumise à double validation avec ticket obligatoire et notification Slack/Teams, de bout en bout. — **Atteint** le 7 novembre 2026 (ADR-0067, ADR-0074) : sur de vrais services, une demande avec ticket et son approbation par une autre personne arrivent dans un vrai Teams et un vrai Slack, signées, sans la justification. Le ticket est vérifié dans son format, pas dans un ITSM : c'est ce qu'ADR-0067 a retenu.
- Replay vidéo disponible pour les sessions RDP/VNC ; recherche plein texte opérationnelle sur commandes et sessions.
- Au moins trois fournisseurs d'identité externes fédérés simultanément en environnement de test. — **Atteint** le 7 novembre 2026 (ADR-0076) : un Authentication Service fédère à la fois un vrai OpenLDAP, un vrai Samba AD et deux Dex, chaque compte lié à son fournisseur (`test/integration/identity_providers_flow_test.go`).
- Helm charts et `docs/deployment/high-availability.md` disponibles pour un déploiement Kubernetes/K3s/OpenShift en production.

## 4. v0.0.2 — Couverture complète, intelligence et écosystème

**Objectif** : couvrir l'intégralité des six familles de systèmes cibles, ajouter la détection d'anomalies, et livrer l'écosystème d'intégration complet.

| Domaine | Composants ajoutés |
|---|---|
| Proxy | Docker Proxy, Hypervisor Console Proxy (VMware/Hyper-V/Proxmox/OpenStack), WinRM Proxy, Telnet/Serial-IPMI Proxy, HTTP/HTTPS Web Proxy |
| Sécurité & Intelligence | Anomaly Detection / Risk Engine (moteur à règles + brique ML optionnelle et détachable) |
| Enregistrement & Audit | Reporting Service, forensics avancés (détection copier/coller, capture clipboard/transfert de fichiers/impression) |
| Clients | SDK Python, SDK Java, SDK JavaScript |
| RDP ([ADR-0090](adr/0090-rdp-v002-glyphes-ordres-canaux-et-protocoles.md), proposé) | Mesures d'abord (débit, encodage, latence) ; ordres graphiques et caches, dont le cache de glyphes ; pipeline graphique RDPGFX sans perte ; canaux virtuels sous ADR-0069 §6 (Display Control, presse-papiers, lecteurs, impression) ; entrée Fast-Path et Unicode, pointeur, reconnexion automatique, redirection de ferme RDS, Kerberos, RD Gateway |

**Critères de sortie**
- Les six familles de systèmes cibles de `docs/architecture/system-overview.md` sont couvertes.
- Un score de risque est calculé pour chaque session active et influence les politiques d'approbation (ex. déclenchement automatique d'une validation N+1 si score élevé).
- `docs/deployment/disaster-recovery.md` validé par un exercice de bascule réel.

## 5. v0.0.3 — Fondations du framework d'agents distribués

**Objectif** : concevoir et valider les contrats et les garanties de sécurité des agents avant toute implémentation connectée à un réseau réel. La v0.0.3 est un jalon d'architecture et de sécurité ; elle ne prétend pas livrer des agents de production.

| Domaine | Livrables v0.0.3 |
|---|---|
| Architecture | Framework à deux plans : Network Agent et Security Agent ; séparation des processus, identités et privilèges (ADR-0102) |
| Connectivité | Tunnel sortant multiplexé, gRPC bidirectionnel sur TLS 1.3/mTLS, exception limitée à Agent Control (ADR-0103) |
| Identité | Enrôlement à usage unique, PKI individuelle, certificats courts et révocation (ADR-0104) |
| Autorisation réseau | Capacités JWS EdDSA à usage unique, liées à l'agent, à la session, à la ressource, à l'IP et au port ; politique locale restrictive (ADR-0105) |
| Durcissement | Processus isolés, comptes dédiés, permissions minimales, confinement Linux/Windows (ADR-0106) |
| Télémétrie | Contrat Security Agent en lecture seule, séquencement, acquittement et signalement des pertes (ADR-0107) |
| Chaîne de livraison | Signature, provenance, SBOM, politique signée et anti-rollback (ADR-0108, ADR-0094) |
| Résilience | Registre HA, bascule contrôlée, fermeture des tunnels à la perte du flux et nouvelle autorisation à la reprise (ADR-0109) |
| Audit | Provenance distincte de la télémétrie hôte, corrélation et séparation de la preuve d'audit PAM (ADR-0110) |
| Contrats | Protobuf sous proto/agent/v1 : enrôlement, contrôle bidirectionnel, tunnels et télémétrie |
| Sécurité | Modèle STRIDE/DREAD dédié aux agents, frontières de confiance, risques résiduels et plan de vérification |

**Critères de sortie**

- Les neuf ADR-0102 à ADR-0110 sont relus individuellement par le propriétaire du projet ; aucun statut Accepté n'est attribué sans son accord explicite. Tout ADR encore Proposé conserve ses points ouverts et bloque le gel de conception concerné.
- Les contrats Protobuf sont validés par Buf (lint et breaking check) et leur génération est reproductible avant toute implémentation runtime.
- Chaque RPC, champ et flux agent est couvert par une règle d'identité, d'autorisation, de taille, de délai et de comportement en erreur.
- Les menaces P0 du modèle STRIDE disposent de contrôles spécifiés et de tests de sécurité planifiés ; aucune menace P0 non traitée ne permet un pilote sur réseau réel.
- La séparation Network/Security Agent, l'absence de secrets cibles dans les messages et le refus des commandes arbitraires sont vérifiés par revue de contrat.
- Le chemin direct depuis une zone opérateur vers les ports privilégiés des cibles est refusé par les ACL/firewalls du site ; les tests démontrent que seule la passerelle autorisée peut atteindre ces ports.
- Les risques résiduels root/SYSTEM, hôte compromis, PKI et chaîne de livraison sont documentés.

**Explicitement hors périmètre v0.0.3** : binaire agent de production, tunnel réseau opérationnel, enrôlement runtime, collecte effective Linux/Windows, mise à jour automatique, réponse EDR, exécution distante, accès SOCKS/UDP et déploiement multi-site. Ces travaux ne commencent qu'après acceptation des ADR et clôture des portes de sécurité.

## 6. Alignement des écrans SVG sur la roadmap

Les SVG sont des propositions d'interface et ne constituent jamais une preuve de disponibilité. Leur statut doit suivre les contrats et les tests réels (ADR-0129). Les nouveaux écrans ci-dessous sont des maquettes de capacité planifiée ; aucun bouton ne doit être activé avant livraison de l'API publique Gateway correspondante.

### MVP / capacités déjà livrées

- `openbastion-dashboard.svg` : uniquement métriques réellement calculées et états de couverture.
- `openbastion-acces-privilegies.svg` : comptes Vault, politiques et rotations réellement disponibles.
- `openbastion-sessions-historique.svg` : recherche selon les filtres réellement exposés.
- `openbastion-sessions-enregistrements.svg` : replay terminal/vidéo selon protocole et couverture effective ; aucune affirmation de vérification cryptographique UI.
- `openbastion-securite.svg` : constats Vault livrés ; posture transverse ADR-0118 reste proposée.
- `openbastion-audit-conformite.svg` : métadonnées d'injection ADR-0113 seulement ; `verify-chain` reste `admin-cli` mTLS.

### v0.0.1 — nouveaux écrans proposés

| SVG | Domaine | Dépendances |
|---|---|---|
| `openbastion-workflows-approbations.svg` | Demandes, double validation, tickets, échéances | ADR-0067, ADR-0074, ADR-0126 |
| `openbastion-secrets-dynamiques.svg` | Secrets dynamiques, TTL, rotation et révocation | ADR-0005, ADR-0040, ADR-0127 |
| `openbastion-identites-federation.svg` | Fournisseurs, fédération et provisioning | ADR-0061, ADR-0076, contrats SCIM/SAML |
| `openbastion-acces-database-kubernetes.svg` | Accès proxifiés DB et Kubernetes | Database Proxy, Kubernetes Proxy, ADR-0130 |

### v0.0.2 — nouveaux écrans proposés

| SVG | Domaine | Dépendances |
|---|---|---|
| `openbastion-forensics-recherche.svg` | Recherche et forensics bornés | ADR-0080, ADR-0096, ADR-0125 |
| `openbastion-risque-anomalies.svg` | Règles explicables, risque et ML optionnel | ADR-0128 |
| `openbastion-reporting-conformite.svg` | Rapports et preuves vérifiables | ADR-0123 |
| `openbastion-protocoles-etendus.svg` | Docker, WinRM, hyperviseurs, Telnet/IPMI et HTTP(S) | ADR-0130 et ADR protocolaires dédiés |

### v0.0.3 — extension proposée

- `openbastion-agents-distribues.svg` : inventaire d'enrôlement PKI, tunnels sortants mTLS, état de télémétrie en lecture seule, provenance et posture de déploiement. Cet écran est conceptuel : les agents de production restent hors périmètre v0.0.3.
- Les écrans v0.0.3 ne doivent jamais proposer d'exécution distante arbitraire, d'accès direct aux ports cibles ou de modification de politique agent depuis un navigateur.

**Règle de livraison UI :** chaque élément doit être traçable à un contrat Gateway, une permission ressource/action, un service propriétaire, un ADR, des tests et un état `implemented|partial|planned|proposed|unavailable`. Les routes internes et leurs schémas ne sont pas des contrats UI.

## 7. Matrice de couverture par microservice

| Composant | MVP | v0.0.1 | v0.0.2 |
|---|:---:|:---:|:---:|
| API Gateway | ✅ | | |
| Authentication Service | ✅ | | |
| Authorization Service | ✅ (RBAC) | ABAC | |
| Session Broker | ✅ | | |
| SSH/SFTP/SCP Proxy | ✅ | | |
| RDP/VNC Proxy | | ✅ VNC E2E ; RDP ouvert par défaut depuis le 13 novembre 2026 (`RDP_ENABLED`, ADR-0088) | RDP : glyphes, ordres, canaux virtuels, protocoles (ADR-0090) |
| Database Proxy | | ✅ | |
| Kubernetes Proxy | | ✅ | |
| Docker Proxy | | | ✅ |
| Hypervisor Console Proxy | | | ✅ |
| WinRM Proxy | | | ✅ |
| Telnet/Serial-IPMI Proxy | | | ✅ |
| HTTP/HTTPS Web Proxy | | | ✅ |
| Password Vault | ✅ (manuel) | rotation planifiée | |
| Secrets Manager | | ✅ | |
| Session Recorder | ✅ | | |
| Command Recorder | ✅ | | |
| Video Recorder | | ⚠️ (pipeline VNC E2E ; API des marqueurs latéraux ADR-0111 ; raccordement injection et timeline UI restants) | |
| Audit Service | ✅ | | |
| Recherche plein texte (ADR-0080, sans OpenSearch) | | ✅ | |
| Reporting Service | | | ✅ |
| Workflow Service | | ✅ | |
| Approval Engine | | ✅ | |
| Notifications Slack/Teams | | ✅ (ADR-0074 ; vrais Teams et Slack : alertes de l'Audit Service, break-glass et demandes avec ticket du Broker, et leurs approbations) | |
| MFA Service | | ✅ (TOTP, ADR-0062, et WebAuthn, ADR-0065, livrés dans l'Authentication Service) | |
| Anomaly Detection / Risk Engine | | | ✅ |
| OIDC Connector | ✅ | | |
| LDAP Connector | | ✅ (livré, ADR-0061) | |
| Active Directory Connector | | ✅ (livré, ADR-0061) | |
| Entra ID Connector | | ✅ | |
| SAML Connector | | ✅ | |
| SCIM Provisioning | | ✅ | |
| Scheduler | ✅ (expiration) | rotation planifiée | |
| Admin UI | ✅ | | |
| User Portal | | ✅ | |
| Desktop Client (Tauri) | | ✅ | |
| CLI | ✅ | | |
| SDK Go | | ✅ | |
| SDK Python / Java / JavaScript | | | ✅ |

## 8. Risques de séquencement

| Risque | Mitigation |
|---|---|
| Le MVP mono-protocole (SSH) ne convainc pas des utilisateurs déjà équipés d'un PAM commercial couvrant RDP/DB dès le premier jour | Communiquer le MVP comme une preuve d'architecture, pas comme un produit de remplacement immédiat |
| `pkg/proxycore` (ADR-0006) conçu pour SSH seul en MVP pourrait nécessiter un refactoring lors de l'ajout de RDP en v0.0.1 | Concevoir l'interface `Codec` dès le MVP en anticipant au moins un second protocole (RDP), sans l'implémenter |


### Suivi spécifique des agents — v0.0.3

| Élément | Statut documentaire | Porte de sécurité |
|---|---|---|
| ADR-0102 à ADR-0110 | Proposés dans cette branche | Acceptation propriétaire |
| Contrats Protobuf agent | Définis dans proto/agent/v1 | Buf lint, breaking et génération |
| STRIDE/DREAD | Analyse initiale publiée dans docs/security/threat-model-agents.md | Revue des menaces P0 et validation des contrôles |
| Implémentation Network Agent | Non commencée | Après ADR-0102 à ADR-0105 et revue STRIDE |
| Implémentation Security Agent | Non commencée | Après ADR-0106 à ADR-0110 et revue STRIDE |
