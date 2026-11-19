# Références visuelles OpenBastion

Ces SVG sont les sources de conception de l'Admin UI. Ils sont conservés dans le dépôt pour assurer leur traçabilité et permettre leur consultation sans dépendre de Figma ni d'un poste de développement.

## Source Figma

Fichier : [OpenBastion](https://www.figma.com/design/yUuwYSnGX7kSLzYX2rZXIU/OpenBastion) (clé `yUuwYSnGX7kSLzYX2rZXIU`). Extraction du 19 novembre 2026 : les 40 cadres de premier niveau des 8 pages, exportés en SVG par l'API REST de Figma (`GET /v1/images/{clé}?format=svg&svg_outline_text=false&svg_simplify_stroke=true`), texte conservé en `<text>` (cherchable, 1,2 Mo pour les 40). Le texte appelle les polices Inter et IBM Plex Mono : sans elles, le lecteur affiche une police de repli.

Pour refaire l'extraction : un token personnel Figma en lecture seule (*File content: Read-only*), jamais commité, puis le même appel avec les identifiants de nœud ci-dessous, et un fichier par cadre sous le nom indiqué.

| Fichier | Page | Cadre Figma | Nœud | Statut |
|---|---|---|---|---|
| `openbastion-dashboard.svg` | Vue d’ensemble | OpenBastion · Vue d’ensemble | `5:63` | Shell et Dashboard React intégrés ; séries temporelles signalées comme indisponibles faute de contrat API |
| `openbastion-auth-connexion.svg` | Vue d’ensemble | Auth + MFA · Connexion | `34:33` | Intégré dans l'Admin UI |
| `openbastion-mfa-validation.svg` | Vue d’ensemble | Auth + MFA · Vérification à deux facteurs | `34:36` | Intégré dans l'Admin UI |
| `openbastion-acces-privilegies.svg` | Accès privilégiés | OpenBastion · Accès privilégiés | `5:154` | Intégré dans l'Admin UI |
| `openbastion-acces-privilegies-comptes.svg` | Accès privilégiés | Accès privilégiés — Comptes | `2007:1543` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-acces-privilegies-politiques.svg` | Accès privilégiés | Accès privilégiés — Politiques | `2007:1748` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-acces-privilegies-demandes.svg` | Accès privilégiés | Accès privilégiés — Demandes | `2007:1953` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-alertes.svg` | Sessions | Sessions — Alertes de Session | `2007:1345` | Intégré : en-tête, indicateurs et panneau « alertes récentes » ; contrat API de file d'alertes manquant, état explicite |
| `openbastion-sessions-enregistrements.svg` | Sessions | Sessions — Enregistrements | `2007:1147` | Intégré : bibliothèque et aperçu ; recherche des commandes SSH et ouverture du replay réelles |
| `openbastion-sessions-historique.svg` | Sessions | Sessions — Historique | `2007:949` | Intégré : en-tête dédié, indicateurs, filtres, tableau de référence et pagination par curseur |
| `openbastion-sessions.svg` | Sessions | OpenBastion · Sessions | `52:116` | Intégré dans l'Admin UI : en-tête, quatre indicateurs, onglets, espace à deux panneaux (demandes à décider, détail) |
| `openbastion-sessions-nouvelle-demande-incomplete.svg` | Sessions | Sessions — Nouvelle demande — Ouvert · formulaire incomplet | `2044:1013` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-nouvelle-demande-erreur-validation.svg` | Sessions | Sessions — Nouvelle demande — Erreur de validation | `2044:1018` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-nouvelle-demande-prete.svg` | Sessions | Sessions — Nouvelle demande — Prêt à envoyer · exemple fictif | `2044:1023` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-nouvelle-demande-soumission.svg` | Sessions | Sessions — Nouvelle demande — Soumission en cours | `2044:1028` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-nouvelle-demande-erreur-serveur.svg` | Sessions | Sessions — Nouvelle demande — Erreur serveur | `2044:1033` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-replay-ssh.svg` | Sessions | Sessions — Enregistrements — Replay terminal SSH | `2044:1335` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-demande-confirmee.svg` | Sessions | Sessions — Demande créée — Création confirmée | `2044:1530` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-demande-en-attente.svg` | Sessions | Sessions — Demande créée — En attente d’approbation | `2044:1760` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-sessions-demande-autre-statut.svg` | Sessions | Sessions — Demande créée — Autre statut retourné | `2044:1990` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-infrastructure.svg` | Infrastructure | OpenBastion · Infrastructure | `5:336` | Intégré : en-tête, quatre indicateurs, topologie des accès, santé du cluster et tableau des connecteurs. Seul le nombre de comptes du Vault est produit par l'API publique ; les contrats manquants (connecteurs, cluster, disponibilité) sont signalés sur place |
| `openbastion-audit-conformite.svg` | Audit & conformité | OpenBastion · Audit & conformité | `5:427` | Intégré dans l'Admin UI |
| `openbastion-audit-conformite-rapports.svg` | Audit & conformité | Audit & conformité — Rapports | `2007:3322` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-audit-conformite-preuves.svg` | Audit & conformité | Audit & conformité — Preuves | `2007:3638` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-audit-conformite-retention.svg` | Audit & conformité | Audit & conformité — Politiques de rétention | `2007:3954` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-securite.svg` | Sécurité | Sécurité — Centre de sécurité | `2044:611` | Nouvelle référence : écart avec l'Admin UI à évaluer |
| `openbastion-parametres.svg` | Paramètres | OpenBastion · Paramètres | `5:518` | Intégré : en-tête, onglets et sections ; valeurs déclarées au déploiement en lecture seule, l'API publique n'expose aucune écriture des paramètres |
| `openbastion-parametres-securite.svg` | Paramètres | Paramètres — Sécurité | `2007:209` | Intégré : facteurs, règles d'accès, enregistrement, état de sécurité et intégrité de l'audit |
| `openbastion-parametres-identites-sso.svg` | Paramètres | Paramètres — Identités & SSO | `2007:394` | Intégré : fournisseurs déclarés, mappage des groupes, provisionnement et second facteur |
| `openbastion-parametres-integrations.svg` | Paramètres | Paramètres — Intégrations | `2007:579` | Intégré : clés et secrets, messageries et architecture des échanges ; URL et clés restent hors de l'UI |
| `openbastion-parametres-notifications.svg` | Paramètres | Paramètres — Notifications | `2007:764` | Intégré : canaux, configuration déclarative, fiabilité et limites connues |
| `openbastion-icones-a-securite-acces.svg` | Icônes | A · Icônes — Sécurité & accès | `5:1412` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-b-utilisateurs-identites.svg` | Icônes | B · Icônes — Utilisateurs & identités | `5:1433` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-c-infrastructure-systemes.svg` | Icônes | C · Icônes — Infrastructure & systèmes | `5:1454` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-d-protocoles-connexions.svg` | Icônes | D · Icônes — Protocoles & connexions | `5:1475` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-e-sessions-controle.svg` | Icônes | E · Icônes — Sessions & contrôle | `5:1496` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-f-administration-operations.svg` | Icônes | F · Icônes — Administration & opérations | `5:1517` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-g-audit-observabilite.svg` | Icônes | G · Icônes — Audit & observabilité | `5:1538` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-icones-h-developpement-livraison.svg` | Icônes | H · Icônes — Développement & livraison | `5:1559` | Planche d'icônes : source de `@openbastion/icons` |
| `openbastion-identite-ressources.svg` | Icônes | 00 · OpenBastion — Identité & ressources | `2039:174` | Planche d'icônes : source de `@openbastion/icons` |

## Maquettes hors Figma

Ces SVG n'ont pas de cadre dans le fichier Figma : ils sont conservés tels quels.

- `openbastion-acces-database-kubernetes.svg`
- `openbastion-agents-distribues.svg`
- `openbastion-forensics-recherche.svg`
- `openbastion-identites-federation.svg`
- `openbastion-protocoles-etendus.svg`
- `openbastion-reporting-conformite.svg`
- `openbastion-risque-anomalies.svg`
- `openbastion-secrets-dynamiques.svg`
- `openbastion-workflows-approbations.svg`

## Règles

Le shell partagé et le Dashboard ont été rapprochés de la référence Dashboard. Les trois maquettes Sessions ont été dérivées de la référence Sessions, avec les mêmes dimensions et la même structure de navigation. Les données de maquette sont illustratives et ne constituent pas des métriques de production ni des contrats d'API.

Les cinq sections de Paramètres et la page Infrastructure décrivent ce que ce build applique réellement (facteurs, refus par défaut, « enregistrer ou refuser », chaîne d'audit, connecteurs appelés par les services, variables d'environnement de notification). Aucune route publique n'écrit ces réglages : les champs sont en lecture seule et l'action « Enregistrer les modifications » de la maquette reste présente mais indisponible.

L'implémentation React doit rester bornée aux routes documentées dans `docs/api/rest/openapi.yaml`. En particulier, aucune API publique ne fournit actuellement une file d'alertes de sessions, un état de traitement ou un compteur d'alertes non lues : la maquette Alertes est conservée comme référence, mais l'interface indique cette limite sans inventer de compteur ni d'action.
