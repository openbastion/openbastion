# ADR-0132 — Le profil d'écran RDP se règle par compte, et l'opérateur choisit dans ses limites

**Statut** `Accepté` · 2026-11-20 · décisions du propriétaire du projet ce jour-là :
- « je veux que l'utilisateur ait la possibilité de changer de canal par défaut de son flux, codec etc. » ;
- qui choisit : « Admin par compte + opérateur » ;
- quels réglages : le canal d'écran, les codecs du pipeline, la profondeur de couleur ;
- après le constat sur les codecs (ci-dessous) : « Canal + profondeur d'abord ».

**Contexte** — Depuis ADR-0101 (incrément 6), le pipeline graphique (`SCREEN_RDPGFX`) est allumé par défaut. Le seul réglage est un interrupteur de déploiement, pour toutes les sessions d'un proxy. Une cible qui affiche mal par le pipeline ne peut pas être remise sur l'ancien chemin bitmap sans priver toutes les autres du pipeline. La profondeur de couleur est figée : le client demande 24 bits et « veut 32 bits » (`RNS_UD_CS_WANT_32BPP_SESSION`).

**Constat sur les codecs** (MS-RDPEGFX, révision du 11 mai 2026, §2.2.2.1, §2.2.2.2, §2.2.3.1 à 2.2.3.x) :
- le serveur choisit le codec de chaque `WireToSurface` ;
- le client n'écarte que l'AVC (`AVC_DISABLED`, déjà annoncé) et, en versions 8 et 8.1 seulement, le RemoteFX progressif (`THINCLIENT`), au profit du RemoteFX classique (`0x0003`), que le proxy ne décode pas ;
- rien n'écarte ClearCodec ni Planar.

Un choix de codecs fin n'est donc pas réalisable sans un décodeur de plus. Le choix de codec se ramène au choix du canal : pipeline (ClearCodec, Planar, RemoteFX progressif) ou bitmap (Interleaved RLE, planar RDP 6, ordres graphiques).

## Décision

1. **Le profil d'écran d'un compte RDP** (`screenProfile`), au Vault, avec le compte :
   - `channels` : sous-ensemble non vide de `graphics` (pipeline graphique) et `bitmap` (mises à jour bitmap) ;
   - `defaultChannel` : l'un d'eux ;
   - `colorDepths` : sous-ensemble non vide de `16` et `32` ;
   - `defaultColorDepth` : l'une d'elles.

   Sans profil, tout est permis : défaut `graphics` et `32`, c'est-à-dire le comportement actuel. Un compte VNC n'a pas de profil (`400`).
2. **Qui le règle** : l'administrateur du compte, par `PUT /vault/accounts/{id}/screen-profile`. La politique porte sur `vault:account-admin:{id}`, action `vault:account:screen-profile`. Le changement est écrit à l'audit (`vault.screen_profile_set`) **avant** d'être fait ; sans audit, rien ne change. Un refus est écrit au mieux, comme `vault.approval_set` (ADR-0067). La lecture du compte (`GET`) rend le profil.
3. **Le choix de l'opérateur**, à l'ouverture de l'écran : `POST /sessions/{id}/connect` prend un corps facultatif `{"screen": {"channel": "graphics|bitmap", "colorDepth": 16|32}}`.
   - Un champ absent prend le défaut du compte.
   - Une valeur inconnue donne `400`.
   - Une valeur hors des limites du compte donne `403`, sans connexion.
   - Le Broker lit le profil au Vault, résout le choix, l'écrit dans l'événement d'audit de la connexion et le transmet au proxy avec le ticket. Le navigateur n'en est jamais la source de vérité.
4. **Le proxy applique le choix à la session** :
   - `graphics` annonce le pipeline, `bitmap` ne l'annonce pas ;
   - `16` demande 16 bits sans « veut 32 bits », `32` garde la demande actuelle ;
   - Windows peut plafonner la profondeur (ADR-0086) ;
   - `SCREEN_RDPGFX=false` reste un plafond de déploiement : `graphics` choisi devient `bitmap`, et le proxy le journalise.
5. **Capacité de l'Admin UI** (ADR-0131) : `accounts.screenProfile` (préfixe `vault:account-admin:`, action `vault:account:screen-profile`). Le formulaire du profil est grisé sans elle. Le choix de l'opérateur n'a pas de capacité propre : il hérite du droit d'ouvrir l'écran, qui reste réservé au demandeur.
6. **Ce qui n'est pas choisi** : les codecs du pipeline, un à un. Exclure le RemoteFX progressif demanderait un décodeur RemoteFX classique (MS-RDPRFX) éprouvé contre les cinq Windows ; refuser un codec à réception couperait la session sans que Windows le sache. Ce sera une décision ultérieure si le besoin vient.

## Incréments

1. Contrat et Vault :
   - le profil au domaine, au stockage (migration idempotente) et sous `PUT` ;
   - la Gateway relaie la route ;
   - OpenAPI, capacité `accounts.screenProfile`, audit.
2. Broker et proxy :
   - le corps de `connect` validé contre le profil ;
   - le choix au ticket et appliqué au codec de la session ;
   - l'audit ;
   - des tests sur processus réels.
3. Admin UI : le formulaire du profil sur un compte RDP, et le sélecteur à « Ouvrir l'écran ».
4. Contre les cinq Windows, en navigateur : `bitmap` et `16` choisis, puis vérifiés à l'écran, dans l'enregistrement relu et dans la ligne du proxy.

## Mise en œuvre

- **Incrément 1** (PR #244) : profil au Vault, route, Gateway, capacité, OpenAPI.
- **Incrément 2** :
  - Gateway : corps facultatif de `connect`, lu sans que l'appelant en vienne (il reste celui du jeton). Un corps illisible ou un `screen` mal typé donne `400`. Les autres champs sont ignorés, comme avant que le corps serve (choix renversable : les refuser romprait un client qui en envoie).
  - Broker (`domain.ResolveScreen`) : profil lu au Vault pour une session RDP ; un Vault muet donne `503`, jamais « tout permis ». Le choix est résolu avant tout scope ; un choix pour un autre protocole donne `400`. Le résultat est écrit à `session.connect` (`screen_channel`, `color_depth`) et passé au proxy (`EstablishSessionRequest`, champs 11 et 12).
  - Proxy : refuse un choix inconnu, ou hors RDP (`400`, avant tout ticket). Le choix est porté par le ticket ; à l'ouverture, la session a son propre codec (`RDPCodec.WithScreen`), celui du proxy restant inchangé. Un codec qui ne peut pas appliquer le choix n'ouvre pas la session. La ligne `session … screen: channel …, … bpp asked` dit ce qui est demandé ; le plafond `SCREEN_RDPGFX=false` est journalisé.
  - `pkg/rdp` (`MCSClientSettings.ColorDepth`) : `16` demande `postBeta2ColorDepth = RNS_UD_COLOR_16BPP_565` et `highColorDepth = 16`, sans `WANT_32BPP`, comme FreeRDP le fait pour `/bpp:16`. `supportedColorDepths` reste inchangé (ADR-0071). Toute autre valeur que 0, 16 ou 32 n'envoie rien.
  - Non éprouvé contre Windows : ce sera l'incrément 4.
- **Incrément 3** (Admin UI) :
  - « Profil d'écran » apparaît sur un compte RDP seulement, grisé sans la capacité `accounts.screenProfile`. Il ouvre un dialogue : canaux et profondeurs permis, défauts. Les erreurs que le Vault refuserait (ensemble vide, défaut hors de l'ensemble) sont dites avant l'envoi, et l'enregistrement est bloqué. « Retirer le profil » envoie `null`. Un refus du serveur s'affiche dans le dialogue.
  - Sous « Ouvrir l'écran » d'une session RDP active, et pour son demandeur seulement : canal et profondeur, chacun sur « Défaut du compte » par défaut. Un choix laissé au défaut n'est pas envoyé. Une reconnexion redemande le même choix.
  - La page ne lit pas le profil du compte (un opérateur peut ne pas avoir le droit de lire le compte) : toutes les valeurs sont proposées, et le Broker répond `403` à un choix hors du profil, affiché comme les autres refus (choix renversable : une route de lecture du profil pour l'opérateur permettrait de griser ces valeurs).

- **Incrément 4** (CI Windows, `TestScreenFlow_RDPScreenChoiceInAHeadlessBrowser`, PR #250) : le compte ne permet que `bitmap` ; `graphics` demandé donne `403`. L'opérateur choisit `bitmap` et `16` dans la page, ouvre l'écran et tape dans Notepad. Mesuré sur les cinq Windows (2019 et 2022, 16 et 32 bpp, session console, fr-FR) :
  - chaque fois, `16 bpp asked` et 16 bpp choisi par la cible, y compris sur le job dont la politique permet 32 ;
  - aucun pipeline graphique proposé ;
  - 19 à 25 images relues par l'API publique, dont 5 à 7 images clés à 698 × 888, la taille montrée.

  Le proxy écrit maintenant `the target opened the screen at N bpp (M asked)` à chaque ouverture.

## Conséquences

- (+) Une cible fragile passe sur le chemin bitmap sans toucher aux autres, et l'opérateur choisit pour sa session dans ce que l'administrateur permet.
- (+) Le choix est vérifié côté serveur et audité ; le proxy reste fermé : un choix absent du ticket est le défaut du compte, jamais une valeur du navigateur.
- (−) Pas de choix de codec fin (point 6).
- (−) La profondeur demandée n'est qu'une demande : une stratégie de groupe de la cible la plafonne.
- (−) Une route publique et un champ de compte de plus ; aucun contrat existant n'est rompu, le corps de `connect` restant facultatif.

## Alternatives envisagées

- **Opérateur seul, par préférence** : l'administrateur ne pourrait pas adapter le choix à une cible. Écartée par le propriétaire.
- **Admin par compte seul** : moins souple pour l'opérateur. Écartée par le propriétaire.
- **Liste de codecs refusés à réception** : coupe la session sans que Windows le sache. Écartée par le propriétaire.
- **Décodeur RemoteFX classique pour exclure le progressif** : un incrément du niveau d'ADR-0101, sans besoin exprimé. Reporté.
