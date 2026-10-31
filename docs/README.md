# Documentation OpenBastion

OpenBastion est un PAM (Privileged Access Management) open source sous licence Apache 2.0 : l'opérateur n'a jamais le mot de passe de la cible, toute connexion passe par un proxy, toute session est enregistrée et auditée. Le MVP couvre SSH, SFTP et SCP de bout en bout ; le reste du périmètre est sur la [feuille de route](roadmap.md).

Une page de cette documentation décrit ce que fait le code. Ce qui est prévu sans être construit n'a pas de page : il est listé dans le `README.md` de la section, avec le point de la feuille de route qui le couvre. L'état réel, les chiffres de tests et les écarts connus sont tenus dans [`NOTES_SANDBOX.md`](../NOTES_SANDBOX.md) ; les limites de sécurité du MVP, dans [`security/known-limitations.md`](security/known-limitations.md).

## Par public

| Vous êtes… | Commencez par |
|---|---|
| Opérateur (vous demandez et utilisez une session) | [`user-guide/`](user-guide/README.md) |
| Administrateur de la plateforme | [`deployment/`](deployment/README.md), puis [`administration/`](administration/README.md) |
| Responsable sécurité, auditeur | [`security/`](security/README.md), [`administration/audit-and-compliance.md`](administration/audit-and-compliance.md), [`compliance/`](compliance/README.md) |
| SRE, exploitation | [`deployment/high-availability.md`](deployment/high-availability.md), [`deployment/disaster-recovery.md`](deployment/disaster-recovery.md), [`operations/`](operations/README.md) |
| Contributeur | [`development/`](development/README.md), [`architecture/`](architecture/README.md), [`adr/`](adr/README.md), [`api/`](api/README.md) |

## Sections

| Dossier | Contenu |
|---|---|
| [`architecture/`](architecture/README.md) | Vue d'ensemble, principes et invariant, C4 (contexte, conteneurs, composants), déploiement, modèle de données |
| [`adr/`](adr/README.md) | Les décisions d'architecture, un fichier par ADR (ADR-0001 à ADR-0052) |
| [`api/`](api/README.md) | Conventions, spécification OpenAPI de l'API publique, contrats entre services |
| [`security/`](security/README.md) | Modèle de menace, sécurité par domaine, limites connues |
| [`development/`](development/README.md) | Prérequis, environnement local, arborescence, tests, contribution |
| [`deployment/`](deployment/README.md) | Installation, configuration, mTLS interne, haute disponibilité, sauvegardes, reprise, mise à jour, dépannage |
| [`administration/`](administration/README.md) | Comptes privilégiés, politiques, break-glass, enregistrement, fédération d'identité, audit |
| [`user-guide/`](user-guide/README.md) | Le parcours de l'opérateur |
| [`operations/`](operations/README.md) | Index : ce qui existe ailleurs, et les pages prévues |
| [`compliance/`](compliance/README.md) | Index : ce qui existe ailleurs, et les pages prévues |

## Ancien document → nouveau fichier

Jusqu'au 31 octobre 2026, la documentation était une séquence de documents numérotés (`docs/architecture/OpenBastion_NN_*.md`, `docs/api/OpenBastion_05_OpenAPI.md`, `docs/guides/OpenBastion_*.md`). Leur contenu a été repris à l'identique dans les fichiers ci-dessous ; seules les sections qui ne décrivaient que l'ordre de rédaction (« Prochaine étape », « Document suivant », « Clôture de la séquence ») ont été retirées. Les migrations SQL déjà appliquées gardent leurs commentaires d'origine, que leur texte ne peut plus changer (ADR-0030) : cette table sert à les lire, ainsi que l'historique git. Un document déplacé en entier garde sa numérotation : « doc 06 §3 » est la section 3 de [`architecture/data-architecture.md`](architecture/data-architecture.md).

| Ancien document | Section | Nouveau fichier |
|---|---|---|
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 1. Résumé exécutif | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 3. Vue d'ensemble en couches | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 4. Catalogue des microservices | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 5. Flux illustratif : accès SSH avec workflow d'approbation | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 7. Le double bus : NATS + Kafka | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 10. Stack technologique — vue de synthèse | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 11. Exigences non fonctionnelles (aperçu) | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 12. Risques architecturaux identifiés | [`architecture/system-overview.md`](architecture/system-overview.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 2. Principes fondateurs | [`architecture/principles.md`](architecture/principles.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 6. Invariant architectural : les secrets ne traversent jamais le control plane | [`architecture/principles.md`](architecture/principles.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 8. Modèle de déploiement et portabilité cloud-native | [`architecture/deployment-architecture.md`](architecture/deployment-architecture.md) |
| doc 00 — Architecture globale (`OpenBastion_00_Architecture_Globale.md`) | 9. Sécurité transverse | [`security/security-overview.md`](security/security-overview.md) |
| doc 01 — Diagrammes C4 (`OpenBastion_01_Diagrammes_C4.md`) | 1. Notation | [`architecture/system-context.md`](architecture/system-context.md) |
| doc 01 — Diagrammes C4 (`OpenBastion_01_Diagrammes_C4.md`) | 2. Niveau 1 — Diagramme de contexte système | [`architecture/system-context.md`](architecture/system-context.md) |
| doc 01 — Diagrammes C4 (`OpenBastion_01_Diagrammes_C4.md`) | 3. Niveau 2 — Diagramme de conteneurs | [`architecture/containers.md`](architecture/containers.md) |
| doc 01 — Diagrammes C4 (`OpenBastion_01_Diagrammes_C4.md`) | 5. Traçabilité — conteneurs ↔ catalogue de microservices | [`architecture/containers.md`](architecture/containers.md) |
| doc 01 — Diagrammes C4 (`OpenBastion_01_Diagrammes_C4.md`) | 4. Niveau 3 — Diagrammes de composants | [`architecture/components.md`](architecture/components.md) |
| doc 02 — Arborescence du dépôt (`OpenBastion_02_Arborescence_Depot.md`) | tout, numérotation gardée | [`development/repository-structure.md`](development/repository-structure.md) |
| doc 04 — Feuille de route (`OpenBastion_04_Roadmap.md`) | tout, numérotation gardée | [`roadmap.md`](roadmap.md) |
| doc 05 — Contrats OpenAPI (`OpenBastion_05_OpenAPI.md`) | 1. Conventions générales | [`api/conventions.md`](api/conventions.md) |
| doc 05 — Contrats OpenAPI (`OpenBastion_05_OpenAPI.md`) | 2. Spécification OpenAPI 3.1 (extrait MVP) | [`api/rest/openapi.yaml`](api/rest/openapi.yaml) |
| doc 05 — Contrats OpenAPI (`OpenBastion_05_OpenAPI.md`) | 3. Table récapitulative des endpoints | [`api/README.md`](api/README.md) |
| doc 05 — Contrats OpenAPI (`OpenBastion_05_OpenAPI.md`) | 4. Extensions prévues (hors MVP, non rupturantes) | [`api/README.md`](api/README.md) |
| doc 06 — Modèle de données (`OpenBastion_06_Modele_Donnees.md`) | tout, numérotation gardée | [`architecture/data-architecture.md`](architecture/data-architecture.md) |
| doc 07 — Interfaces inter-services (`OpenBastion_07_Interfaces_Inter_Services.md`) | tout, numérotation gardée | [`api/grpc/README.md`](api/grpc/README.md) |
| doc 08 — Analyse ORM (`OpenBastion_08_Analyse_ORM.md`) | tout, numérotation gardée | [`architecture/data-access-orm-analysis.md`](architecture/data-access-orm-analysis.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 1. Prérequis de déploiement | [`deployment/prerequisites.md`](deployment/prerequisites.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 2. Installation | [`deployment/docker-compose.md`](deployment/docker-compose.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | Identité des services (mTLS interne) | [`deployment/tls-certificates.md`](deployment/tls-certificates.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | Limitation de débit du Gateway (ADR-0014, ADR-0016) | [`deployment/configuration.md`](deployment/configuration.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | Derrière Traefik : déclarer le proxy (ADR-0015) | [`deployment/configuration.md`](deployment/configuration.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 8. Sauvegardes | [`deployment/backup-restore.md`](deployment/backup-restore.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 9. Mise à jour de la plateforme | [`deployment/upgrades.md`](deployment/upgrades.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 10. Dépannage courant | [`deployment/troubleshooting.md`](deployment/troubleshooting.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 3. Configuration initiale | [`administration/initial-setup.md`](administration/initial-setup.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | Politique d'enregistrement | [`administration/session-recording.md`](administration/session-recording.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | Accès d'urgence (break-glass) | [`administration/approval-workflows.md`](administration/approval-workflows.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 4. Gestion des comptes privilégiés (Vault) | [`administration/privileged-accounts.md`](administration/privileged-accounts.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 5. Gestion des politiques RBAC | [`administration/access-policies.md`](administration/access-policies.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 6. Fédération d'identité | [`administration/identity-providers.md`](administration/identity-providers.md) |
| Documentation Administrateur (`OpenBastion_Doc_Administrateur.md`) | 7. Supervision et audit courant | [`administration/audit-and-compliance.md`](administration/audit-and-compliance.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 1. Prérequis | [`development/prerequisites.md`](development/prerequisites.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 2. Démarrer l'environnement local | [`development/local-environment.md`](development/local-environment.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 7. Tests | [`development/testing.md`](development/testing.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 8. Observabilité en développement | [`development/debugging.md`](development/debugging.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 3. Repères dans le monorepo | [`development/contributing.md`](development/contributing.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 4. Structure d'un microservice — rappel | [`development/contributing.md`](development/contributing.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 5. Ajouter un nouveau protocole de proxy | [`development/contributing.md`](development/contributing.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 6. Travailler avec les contrats Protobuf | [`development/contributing.md`](development/contributing.md) |
| Documentation Développeur (`OpenBastion_Doc_Developpeur.md`) | 9. Processus de contribution | [`development/contributing.md`](development/contributing.md) |
| Guide HA (`OpenBastion_Guide_HA.md`) | tout, numérotation gardée | [`deployment/high-availability.md`](deployment/high-availability.md) |
| Guide PRA/PCA (`OpenBastion_Guide_PRA_PCA.md`) | tout, numérotation gardée | [`deployment/disaster-recovery.md`](deployment/disaster-recovery.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 1. Modèle de menace | [`security/threat-model.md`](security/threat-model.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 2. Rappel des trois invariants (doc 00, §2) | [`security/security-overview.md`](security/security-overview.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 3. Sécurité du transport | [`security/network-security.md`](security/network-security.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 4. Sécurité de l'authentification | [`security/authentication.md`](security/authentication.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 5. Sécurité de l'autorisation | [`security/authorization-rbac-abac.md`](security/authorization-rbac-abac.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 6. Sécurité des secrets | [`security/secrets-management.md`](security/secrets-management.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 7. Sécurité applicative | [`security/secure-development.md`](security/secure-development.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 8. Sécurité de la couche proxy | [`security/session-security.md`](security/session-security.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 9. Sécurité de l'audit | [`security/audit-integrity.md`](security/audit-integrity.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 10. Durcissement du déploiement | [`security/hardening.md`](security/hardening.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 11. Gestion des vulnérabilités et divulgation responsable | [`security/vulnerability-management.md`](security/vulnerability-management.md) |
| Guide Sécurité (`OpenBastion_Guide_Securite.md`) | 12. Limites connues du périmètre MVP | [`security/known-limitations.md`](security/known-limitations.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 2. Se connecter | [`user-guide/login-and-mfa.md`](user-guide/login-and-mfa.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 3. Demander une session | [`user-guide/requesting-access.md`](user-guide/requesting-access.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 4. Se connecter à la session | [`user-guide/launching-sessions.md`](user-guide/launching-sessions.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 5. Pendant la session | [`user-guide/launching-sessions.md`](user-guide/launching-sessions.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 6. Terminer une session | [`user-guide/launching-sessions.md`](user-guide/launching-sessions.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 7. Consulter votre historique | [`user-guide/using-session-recordings.md`](user-guide/using-session-recordings.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 8. Questions fréquentes | [`user-guide/troubleshooting.md`](user-guide/troubleshooting.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 1. Ce que fait OpenBastion pour vous | [`user-guide/README.md`](user-guide/README.md) |
| Guide Utilisateur (`OpenBastion_Guide_Utilisateur.md`) | 9. Bonnes pratiques | [`user-guide/README.md`](user-guide/README.md) |
| doc 03 — ADR (`OpenBastion_03_ADR.md`) | §1 format, §2 index ; chaque ADR-NNNN | [`adr/README.md`](adr/README.md) ; `adr/NNNN-….md` |
