# Feuille de route MVP → v0.0.1 → v0.0.2

Séquencement du périmètre fonctionnel, sans estimation calendaire. Les versions suivent Semantic Versioning (ADR-0063, [`development/versioning.md`](development/versioning.md)) : les anciens jalons « v1.0 » et « v2.0 » sont devenus **v0.0.1** et **v0.0.2**.

## 0. État d'avancement — 8 novembre 2026

La roadmap décrit les jalons de livraison ; elle ne signifie pas qu'une fonction inscrite dans une phase est déjà disponible.

- **MVP SSH/SFTP/SCP** : parcours fonctionnel de référence, avec Gateway, Broker, Vault, proxy SSH, audit et replay texte.
- **VNC** : parcours de bout en bout validé avec TigerVNC 1.13.1, incluant Gateway, Broker, Vault, proxy écran et Video Recorder. Le replay est disponible par API et dans l'Admin UI (lecteur d'écran enregistré, page « Enregistrements ») ; plusieurs fonctions de redirection restent à faire.
- **RDP** : moteur Go pur en développement avancé. X.224/HYBRID, TLS épinglé, CredSSP/NTLMv2, MCS/GCC, licensing partiel, négociation de capacités et décodage graphique partiel sont présents. **Le runtime RDP reste désactivé** ; la couverture des ordres graphiques et Fast-Path est incomplète ; l'interopérabilité Windows/RDS réelle, les licences CAL complètes et les canaux virtuels ne sont pas validés.
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

**État RDP/VNC dans cette phase** : VNC possède une preuve de parcours de bout en bout, mais n'est pas encore une expérience complète (lecteur vidéo UI, clipboard et interopérabilité RealVNC notamment). RDP reste un moteur en cours d'activation : l'ouverture de session contre FreeRDP 3.15 est un test d'interopérabilité de développement, **pas** une preuve Windows/RDS. La sortie de cette capacité exige un runtime RDP activé, validation stricte des certificats, enregistrement obligatoire, tests négatifs et interopérabilité réelle Windows Server/RDS. Suivre [ADR-0071](adr/0071-le-proxy-rdp-vnc-termine-la-cible-en-go-pur-et-sert-un-flux-ecran-acquitte.md), [ADR-0081](adr/0081-veille-rdp-externe-et-integration-selective.md) et [les limites connues](security/known-limitations.md).

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

**Critères de sortie**
- Les six familles de systèmes cibles de `docs/architecture/system-overview.md` sont couvertes.
- Un score de risque est calculé pour chaque session active et influence les politiques d'approbation (ex. déclenchement automatique d'une validation N+1 si score élevé).
- `docs/deployment/disaster-recovery.md` validé par un exercice de bascule réel.

## 5. Matrice de couverture par microservice

| Composant | MVP | v0.0.1 | v0.0.2 |
|---|:---:|:---:|:---:|
| API Gateway | ✅ | | |
| Authentication Service | ✅ | | |
| Authorization Service | ✅ (RBAC) | ABAC | |
| Session Broker | ✅ | | |
| SSH/SFTP/SCP Proxy | ✅ | | |
| RDP/VNC Proxy | | ⚠️ (VNC E2E validé ; RDP runtime désactivé) | |
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
| Video Recorder | | ⚠️ (pipeline VNC E2E ; lecteur UI restant) | |
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

## 6. Risques de séquencement

| Risque | Mitigation |
|---|---|
| Le MVP mono-protocole (SSH) ne convainc pas des utilisateurs déjà équipés d'un PAM commercial couvrant RDP/DB dès le premier jour | Communiquer le MVP comme une preuve d'architecture, pas comme un produit de remplacement immédiat |
| `pkg/proxycore` (ADR-0006) conçu pour SSH seul en MVP pourrait nécessiter un refactoring lors de l'ajout de RDP en v0.0.1 | Concevoir l'interface `Codec` dès le MVP en anticipant au moins un second protocole (RDP), sans l'implémenter |
