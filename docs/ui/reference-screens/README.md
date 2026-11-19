# Références visuelles OpenBastion

Ces SVG sont les maquettes de l'Admin UI, extraites de Figma. Ils sont conservés dans le dépôt pour assurer leur traçabilité et permettre leur consultation sans dépendre de Figma ni d'un poste de développement.

## Source Figma

Fichier : [OpenBastion](https://www.figma.com/design/yUuwYSnGX7kSLzYX2rZXIU/OpenBastion) (clé `yUuwYSnGX7kSLzYX2rZXIU`), **seule source** des maquettes : aucun SVG de ce dossier n'existe hors de Figma. Extraction du 19 novembre 2026 : les 40 cadres de premier niveau des 8 pages.

Chaque SVG est reconstitué pour rester fidèle au cadre Figma hors de Figma :

- **Calques** : chaque groupe, texte et forme porte le nom de son calque Figma (`id`) et son nœud (`data-node-id`). Figma écrit ces noms octet par octet en UTF-8 (`Acc&#195;&#168;s`) ; ils sont rétablis (`Accès`).
- **Textes** : conservés en `<text>` (cherchables, sélectionnables), pas convertis en tracés.
- **Graisses** : l'export SVG de Figma ne connaît que « normal » et « bold » ; la graisse exacte de chaque texte (400, 500, 600) est relue dans le document Figma par son nœud et réappliquée.
- **Polices** : un sous-ensemble WOFF2 d'**Inter 4.001** (axe des graisses 400–600, taille optique 14) et d'**IBM Plex Mono** Regular, limité aux caractères du fichier, est intégré dans chaque SVG : le rendu ne dépend pas des polices installées et tient dans un `<img>`. Licences SIL OFL 1.1 dans [`fonts/`](fonts/). Trois symboles absents de ces polices (`⌕`, `☷`, `●`) restent rendus par la police de repli du lecteur, comme dans Figma.
- **Icônes et formes** : tracés vectoriels tels que Figma les exporte (contours non simplifiés).

Contrôle mesuré sur Sessions, Vue d'ensemble et Paramètres — Sécurité : rendu Chromium du SVG comparé au PNG que Figma rend du même cadre, 0,7 à 1,2 % de pixels s'écartent de plus de 48/255 (anticrénelage), contre 2,0 à 2,5 % pour l'export brut.

Les calques masqués dans Figma (états de démonstration « États et erreurs », 27 cadres et 47 textes) ne sont pas exportés : Figma ne rend pas un calque masqué.

### Refaire l'extraction

Un token personnel Figma en lecture seule (*File content: Read-only*), dans un fichier hors du dépôt, jamais commité. Avec `IDS` la liste des nœuds du tableau ci-dessous :

1. `GET https://api.figma.com/v1/images/yUuwYSnGX7kSLzYX2rZXIU?ids=$IDS&format=svg&svg_outline_text=false&svg_include_id=true&svg_include_node_id=true&svg_simplify_stroke=false` (en-tête `X-Figma-Token`), puis télécharger chaque URL rendue sous le nom du tableau ;
2. `GET https://api.figma.com/v1/files/yUuwYSnGX7kSLzYX2rZXIU/nodes?ids=$IDS` pour les styles de texte ;
3. Inter et IBM Plex Mono depuis `google/fonts` (`ofl/inter/Inter[opsz,wght].ttf`, `ofl/ibmplexmono/IBMPlexMono-Regular.ttf`) ;
4. `python3 -I scripts/figma-reference-screens.py <svg-bruts> <sortie> nodes.json map.tsv <polices>` (fontTools et brotli requis), `map.tsv` donnant `nœud<TAB>nom` pour chaque ligne du tableau.

| Fichier | Page | Cadre Figma | Nœud | Statut |
|---|---|---|---|---|
| `openbastion-dashboard.svg` | Vue d’ensemble | OpenBastion · Vue d’ensemble | `5:63` | Shell et Dashboard React intégrés ; séries temporelles signalées comme indisponibles faute de contrat API |
| `openbastion-auth-connexion.svg` | Vue d’ensemble | Auth + MFA · Connexion | `34:33` | Intégré dans l'Admin UI |
| `openbastion-mfa-validation.svg` | Vue d’ensemble | Auth + MFA · Vérification à deux facteurs | `34:36` | Intégré dans l'Admin UI |
| `openbastion-acces-privilegies.svg` | Accès privilégiés | OpenBastion · Accès privilégiés | `5:154` | Intégré dans l'Admin UI |
| `openbastion-acces-privilegies-comptes.svg` | Accès privilégiés | Accès privilégiés — Comptes | `2007:1543` | Partiel : tableau et actions livrés ; panneau de détail et colonnes Type, Authentification, Dernière rotation absents ; la maquette marque « Prévu » une rotation déjà livrée |
| `openbastion-acces-privilegies-politiques.svg` | Accès privilégiés | Accès privilégiés — Politiques | `2007:1748` | Intégré : mêmes quatre champs ; textes d'aide et panneau « liste indisponible » absents |
| `openbastion-acces-privilegies-demandes.svg` | Accès privilégiés | Accès privilégiés — Demandes | `2007:1953` | Partiel : cartes des demandes en attente ; tableau, filtres, historique et décision sur place absents |
| `openbastion-sessions-alertes.svg` | Sessions | Sessions — Alertes de Session | `2007:1345` | Intégré : en-tête, indicateurs et panneau « alertes récentes » ; contrat API de file d'alertes manquant, état explicite |
| `openbastion-sessions-enregistrements.svg` | Sessions | Sessions — Enregistrements | `2007:1147` | Intégré : bibliothèque et aperçu ; recherche des commandes SSH et ouverture du replay réelles |
| `openbastion-sessions-historique.svg` | Sessions | Sessions — Historique | `2007:949` | Intégré : en-tête dédié, indicateurs, filtres, tableau de référence et pagination par curseur |
| `openbastion-sessions.svg` | Sessions | OpenBastion · Sessions | `52:116` | Intégré dans l'Admin UI : en-tête, quatre indicateurs, onglets, espace à deux panneaux (demandes à décider, détail) |
| `openbastion-sessions-nouvelle-demande-incomplete.svg` | Sessions | Sessions — Nouvelle demande — Ouvert · formulaire incomplet | `2044:1013` | Partiel : champs intégrés ; textes d'aide, Annuler et zone de texte absents |
| `openbastion-sessions-nouvelle-demande-erreur-validation.svg` | Sessions | Sessions — Nouvelle demande — Erreur de validation | `2044:1018` | Non intégré : validation native du navigateur, pas d'erreur par champ |
| `openbastion-sessions-nouvelle-demande-prete.svg` | Sessions | Sessions — Nouvelle demande — Prêt à envoyer · exemple fictif | `2044:1023` | Partiel : compteur du ticket absent |
| `openbastion-sessions-nouvelle-demande-soumission.svg` | Sessions | Sessions — Nouvelle demande — Soumission en cours | `2044:1028` | Non intégré : aucun état d'envoi, double envoi possible |
| `openbastion-sessions-nouvelle-demande-erreur-serveur.svg` | Sessions | Sessions — Nouvelle demande — Erreur serveur | `2044:1033` | Partiel : champs conservés ; message de l'API au lieu du texte prévu |
| `openbastion-sessions-replay-ssh.svg` | Sessions | Sessions — Enregistrements — Replay terminal SSH | `2044:1335` | Partiel : commandes horodatées listées ; lecteur (lecture, pause) absent |
| `openbastion-sessions-demande-confirmee.svg` | Sessions | Sessions — Demande créée — Création confirmée | `2044:1530` | Intégré : statut serveur affiché ; bandeau et « Retour à En direct » à aligner |
| `openbastion-sessions-demande-en-attente.svg` | Sessions | Sessions — Demande créée — En attente d’approbation | `2044:1760` | Intégré : demande sélectionnée et listée en attente |
| `openbastion-sessions-demande-autre-statut.svg` | Sessions | Sessions — Demande créée — Autre statut retourné | `2044:1990` | Intégré : statut inconnu affiché tel quel |
| `openbastion-infrastructure.svg` | Infrastructure | OpenBastion · Infrastructure | `5:336` | Intégré : en-tête, quatre indicateurs, topologie des accès, santé du cluster et tableau des connecteurs. Seul le nombre de comptes du Vault est produit par l'API publique ; les contrats manquants (connecteurs, cluster, disponibilité) sont signalés sur place |
| `openbastion-audit-conformite.svg` | Audit & conformité | OpenBastion · Audit & conformité | `5:427` | Intégré dans l'Admin UI |
| `openbastion-audit-conformite-rapports.svg` | Audit & conformité | Audit & conformité — Rapports | `2007:3322` | Intégré : onglet indisponible ; mention « aucune certification » absente |
| `openbastion-audit-conformite-preuves.svg` | Audit & conformité | Audit & conformité — Preuves | `2007:3638` | Divergent : l'UI renvoie aux enregistrements, la maquette montre une projection de métadonnées |
| `openbastion-audit-conformite-retention.svg` | Audit & conformité | Audit & conformité — Politiques de rétention | `2007:3954` | Intégré : onglet indisponible ; paragraphe « aucune durée implicite » absent |
| `openbastion-securite.svg` | Sécurité | Sécurité — Centre de sécurité | `2044:611` | Écran intégré (`SecurityCenter.tsx`) ; écarts avec ce cadre non évalués |
| `openbastion-parametres.svg` | Paramètres | OpenBastion · Paramètres | `5:518` | Intégré : en-tête, onglets et sections ; valeurs déclarées au déploiement en lecture seule, l'API publique n'expose aucune écriture des paramètres |
| `openbastion-parametres-securite.svg` | Paramètres | Paramètres — Sécurité | `2007:209` | Intégré : facteurs, règles d'accès, enregistrement, état de sécurité et intégrité de l'audit |
| `openbastion-parametres-identites-sso.svg` | Paramètres | Paramètres — Identités & SSO | `2007:394` | Intégré : fournisseurs déclarés, mappage des groupes, provisionnement et second facteur |
| `openbastion-parametres-integrations.svg` | Paramètres | Paramètres — Intégrations | `2007:579` | Intégré : clés et secrets, messageries et architecture des échanges ; URL et clés restent hors de l'UI |
| `openbastion-parametres-notifications.svg` | Paramètres | Paramètres — Notifications | `2007:764` | Intégré : canaux, configuration déclarative, fiabilité et limites connues |
| `openbastion-icones-a-securite-acces.svg` | Icônes | A · Icônes — Sécurité & accès | `5:1412` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-b-utilisateurs-identites.svg` | Icônes | B · Icônes — Utilisateurs & identités | `5:1433` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-c-infrastructure-systemes.svg` | Icônes | C · Icônes — Infrastructure & systèmes | `5:1454` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-d-protocoles-connexions.svg` | Icônes | D · Icônes — Protocoles & connexions | `5:1475` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-e-sessions-controle.svg` | Icônes | E · Icônes — Sessions & contrôle | `5:1496` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-f-administration-operations.svg` | Icônes | F · Icônes — Administration & opérations | `5:1517` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-g-audit-observabilite.svg` | Icônes | G · Icônes — Audit & observabilité | `5:1538` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-icones-h-developpement-livraison.svg` | Icônes | H · Icônes — Développement & livraison | `5:1559` | Aligné : toutes les icônes nommées existent dans `@openbastion/icons` (tracés non comparés) |
| `openbastion-identite-ressources.svg` | Icônes | 00 · OpenBastion — Identité & ressources | `2039:174` | Partiel : palette officielle absente des tokens, logo non utilisé par l'UI |


## Écarts avec l'Admin UI

Le détail des écarts entre les maquettes et l'Admin UI, et les priorités proposées, sont dans [`ecarts-admin-ui.md`](ecarts-admin-ui.md).

## Règles

Le shell partagé et le Dashboard ont été rapprochés de la référence Dashboard. Les trois maquettes Sessions ont été dérivées de la référence Sessions, avec les mêmes dimensions et la même structure de navigation. Les données de maquette sont illustratives et ne constituent pas des métriques de production ni des contrats d'API.

Les cinq sections de Paramètres et la page Infrastructure décrivent ce que ce build applique réellement (facteurs, refus par défaut, « enregistrer ou refuser », chaîne d'audit, connecteurs appelés par les services, variables d'environnement de notification). Aucune route publique n'écrit ces réglages : les champs sont en lecture seule et l'action « Enregistrer les modifications » de la maquette reste présente mais indisponible.

L'implémentation React doit rester bornée aux routes documentées dans `docs/api/rest/openapi.yaml`. En particulier, aucune API publique ne fournit actuellement une file d'alertes de sessions, un état de traitement ou un compteur d'alertes non lues : la maquette Alertes est conservée comme référence, mais l'interface indique cette limite sans inventer de compteur ni d'action.
