# Écarts entre les maquettes Figma et l'Admin UI

Comparaison du 19 novembre 2026 entre les 24 maquettes ajoutées par l'extraction Figma (voir [`README.md`](README.md)) et l'Admin UI de `main` (8da45e3). Méthode : texte et structure de chaque SVG, contre les composants React et les traductions françaises (`web/admin-ui/src`) ; pour les planches d'icônes, les noms contre `web/packages/icons/manifest.json`. Aucune capture de l'UI avec des données réelles : les écarts de mise en page fine (espacements, couleurs exactes) ne sont pas mesurés ici.

Légende du sens de l'écart : **UI en retard** (la maquette décrit un comportement que l'UI n'a pas) ; **maquette en retard** (l'UI ou l'API fait déjà plus que ce que la maquette montre) ; **aligné**.

## Synthèse

| Maquette | Sens | Écart principal |
|---|---|---|
| Accès privilégiés — Comptes | Mixte | Colonnes, filtres et panneau de détail différents ; la maquette marque « Prévu » une rotation que l'UI et l'API font déjà |
| Accès privilégiés — Politiques | UI en retard (léger) | Champs identiques ; textes d'aide et panneau « liste indisponible » absents |
| Accès privilégiés — Demandes | UI en retard | Tableau filtrable et décision sur place ; l'UI n'a que des cartes qui renvoient vers Sessions |
| Sessions — Nouvelle demande (5 états) | UI en retard | Pas d'état « envoi en cours » (double envoi possible), pas d'erreurs par champ, justification sur une ligne, pas de bouton Annuler |
| Sessions — Demande créée (3 états) | Aligné, détails | Statut serveur affiché tel quel ; bandeau de succès et retour « En direct » à aligner |
| Sessions — Replay terminal SSH | UI en retard | L'UI liste les commandes ; la maquette montre un lecteur de terminal (lecture, pause, début) |
| Audit & conformité — Rapports | Aligné, détails | Onglet « indisponible » présent ; mention « aucune certification revendiquée » absente |
| Audit & conformité — Preuves | Divergent | La maquette montre une projection de métadonnées vide ; l'UI renvoie vers les enregistrements de sessions |
| Audit & conformité — Rétention | Aligné, détails | Onglet « indisponible » présent ; paragraphe « aucune durée implicite » absent |
| Icônes A à H (8 planches) | Aligné (noms) | Les 124 icônes existent dans `@openbastion/icons` sous le même nom ; tracés non comparés |
| Identité & ressources | UI en retard | Palette officielle absente des tokens ; marque de l'UI dessinée à la main au lieu du logo |

## Accès privilégiés

### Comptes (`openbastion-acces-privilegies-comptes.svg`)

- **Maquette** : tableau en lecture seule, colonnes *Alias du compte, Ressource / réf., Type, Authentification, Statut, Dernière rotation, Dernière utilisation* ; filtres *Ressource, Type, Statut, Rotation* ; panneau latéral de détail (*Métadonnées autorisées, Rotation & synchronisation, Protection des valeurs*) ; « Ajouter un compte · Prévu » et « Lancer une rotation · Prévu » désactivés.
- **UI** (`Accounts.tsx`, `AccountTable.tsx`) : colonnes *Ressource, Adresse, Protocole, Environnement, Accès, État, Actions* ; actions actives (épingler la clé d'hôte ou le certificat, exiger l'approbation, rotation, désactivation, avec confirmation) ; constructeur de filtres et vues enregistrées ; pas de panneau de détail.
- **Écarts** :
  - UI en retard : panneau de détail, colonnes *Type*, *Authentification*, *Dernière rotation*. *Dernière utilisation* n'est exposée par aucune route : la maquette le dit déjà (« Non exposée »).
  - Maquette en retard : la rotation (`POST /vault/accounts/{id}/rotate`), la désactivation et les épinglages sont livrés et actifs dans l'UI ; la maquette les montre « Prévu ». C'est la maquette qu'il faut corriger, pas l'UI.

### Politiques (`openbastion-acces-privilegies-politiques.svg`)

- **Aligné** : le formulaire de création a les mêmes quatre champs (*Nom, Rôle, Motif de ressource, Effet*) et le même appel (`POST /policies`) ; l'auteur n'est pas saisi.
- **UI en retard (léger)** : l'effet est une liste déroulante, pas deux boutons radio ; les textes d'aide (« Quatre champs uniquement… », « La création n'est confirmée qu'après la réponse du serveur ») et le panneau « Liste des politiques · Indisponible » manquent. L'onglet affiche un compteur « — » sans explication.

### Demandes (`openbastion-acces-privilegies-demandes.svg`)

- **Maquette** : tableau des demandes accessibles (*Demande / demandeur, Ressource / compte, Justification / ticket, Période, Décisions possibles, Échéance, Statut*), filtres, statuts *En attente, À traiter, Expirée, Refusée*, panneau de détail avec *Approuver / Refuser* sur place, et refus explicite de l'auto-approbation (« Vous êtes le demandeur… contrôles désactivés »).
- **UI** (`ApprovalCards.tsx`) : cartes des seules demandes en attente (demandeur, compte, justification, ancienneté) ; « Ouvrir » renvoie à Sessions, où l'on décide.
- **Écarts (UI en retard)** : pas de tableau ni de filtres, pas de demandes expirées ou refusées (la liste vient de `GET /sessions?status=pending_approval`), pas de décision sur place.
- **Auto-approbation** : le Broker la refuse (`session_broker_service.go`, décision par le demandeur rejetée), mais l'écran Sessions propose quand même « Approuver » au demandeur, qui reçoit une erreur. Écart d'ergonomie, pas de sécurité : masquer ou désactiver le bouton quand `requestedBy` est l'utilisateur courant, en gardant le refus serveur comme seule garantie.

## Sessions

### Nouvelle demande, 5 états (`openbastion-sessions-nouvelle-demande-*.svg`)

- **Aligné** : fenêtre modale, champs *Compte privilégié, Protocole (SSH, VNC, RDP), Durée (minimum 1), Justification, Ticket (128 caractères max)*, envoi `POST /sessions`, champs conservés après une erreur serveur.
- **UI en retard** (`SessionRequest.tsx`, `FormCard.tsx`) :
  - **Envoi en cours** : aucun état d'attente, le bouton reste actif. Un double clic peut créer deux demandes. C'est l'écart à corriger en premier.
  - **Erreurs de validation** : l'UI s'appuie sur `required` (bulle native du navigateur) ; ni message sous le champ (« Renseignez le compte cible », « Une justification explicite est obligatoire »), ni résumé « Corrigez les champs obligatoires ».
  - **Justification** sur une ligne (`Input`) au lieu d'une zone de texte ; pas de compteur `0/128` pour le ticket.
  - Textes d'aide absents (« Un compte existant est requis… », « Le Broker valide cette correspondance », « La création ne vaut ni approbation ni ouverture de session »), ainsi que « * Champs obligatoires » et le bouton **Annuler**.
  - **Erreur serveur** : l'UI affiche le code et le message de l'API, pas « La création n'est pas confirmée. Vos champs sont conservés. ».
  - **Accessibilité** : la maquette demande le focus initial sur le compte cible ; la fenêtre (Radix) piège déjà le focus et le rend au déclencheur, le focus initial n'est pas vérifié.

### Demande créée, 3 états (`openbastion-sessions-demande-*.svg`)

- **Aligné** : après la réponse du serveur, l'UI sélectionne la demande, l'affiche dans le panneau de détail et affiche son statut ; un statut inconnu est affiché tel quel (`StatusBadge`), comme la maquette « Autre statut retourné » le demande.
- **Détails** : la maquette a un bandeau « Demande créée avec succès » avec un texte par cas, une carte de demande dans la liste « En direct », et « Retour à En direct » ; l'UI affiche une notice unique et ne place la demande dans la liste que si elle est en attente d'approbation.

### Replay terminal SSH (`openbastion-sessions-replay-ssh.svg`)

- **Maquette** : lecteur de terminal (horodatage, commandes), *Lire / Pause / Revenir au début*, mention « Terminal SSH ≠ vidéo RDP / VNC », état sans lecture si le replay est absent ou refusé.
- **UI** (`Recording.tsx`) : liste paginée des commandes enregistrées de la session ; le replay vidéo (RDP/VNC) est un composant distinct (`VideoReplay.tsx`), ce que la maquette demande.
- **Écart (UI en retard)** : pas de lecteur temporel pour le terminal SSH. Le contenu (commandes horodatées, refus explicite) est là ; seule la lecture est absente.

## Audit & conformité

- **Rapports** — aligné : onglet présent et marqué indisponible. Manque le paragraphe « Aucune certification revendiquée » (journal d'audit ≠ ISO, SOC 2, NIS2).
- **Preuves** — divergent : la maquette montre une projection de métadonnées autorisées (tableau vide *Référence, Type, Source logique, Disponibilité*) et rappelle que la vérification de la chaîne reste `admin-cli` en mTLS ; l'UI dit que les preuves disponibles sont les enregistrements de sessions et y renvoie. Les deux restent sans verdict cryptographique ; à trancher : quelle projection l'API expose-t-elle réellement ?
- **Politiques de rétention** — aligné : onglet présent et marqué indisponible. Manque le paragraphe « Aucune durée implicite » (expiration, archivage et suppression sont distincts).

## Icônes et identité

- **Planches A à H** : 124 icônes nommées, toutes présentes dans `@openbastion/icons` (140 icônes) sous le même nom. Les tracés ne sont pas comparés ; la planche indique « base Lucide · ISC », à vérifier contre la provenance déclarée du paquet.
- **Identité & ressources** :
  - La palette officielle de la planche (*Navy* `#0B1F3B`, *Cyan* `#00D1FF`, *Blue* `#0B5ED7`, *Dark* `#101F32`) n'est pas dans `@openbastion/design-tokens`, qui a des valeurs voisines (`--ob-palette-navy-900: #0B1E33`, `--ob-palette-cyan-500: #06B6D4`). Seul *Slate* `#64748B` y figure.
  - La marque de l'UI (`BrandMark.tsx`) est un bouclier dessiné à la main ; la planche définit un logo en quatre variantes (couleur et mono, clair et sombre), déjà présent dans `web/packages/icons/assets/logo/`.
  - Polices : la maquette utilise Inter ; les tokens déclarent la pile système (`system-ui, …`).

## Priorités proposées

1. **Nouvelle demande** : état d'envoi en cours (bouton désactivé, libellé « Envoi en cours… ») — évite les demandes en double.
2. **Demandes** : ne plus proposer « Approuver » au demandeur (le serveur refuse déjà).
3. **Maquette Comptes** : corriger dans Figma la rotation, la désactivation et les épinglages, livrés et non « Prévu ».
4. **Nouvelle demande** : erreurs par champ, zone de texte pour la justification, compteur du ticket, Annuler, textes d'aide.
5. **Tokens** : décider entre la palette Figma et celle des tokens, et entre Inter et la pile système.
6. Ensuite : tableau des demandes, panneau de détail des comptes, lecteur de terminal SSH, textes manquants d'Audit.
