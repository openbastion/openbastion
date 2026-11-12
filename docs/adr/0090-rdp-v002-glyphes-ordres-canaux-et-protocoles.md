# ADR-0090 — RDP en v0.0.2 : glyphes, ordres graphiques, canaux virtuels et protocoles, par incréments prouvés

**Statut** `Proposé` · 9 novembre 2026 · demandé par le propriétaire du projet le 9 novembre 2026 : « Propose quand même un ADR pour implémenter glyphes, les autres ordres et protocoles RDP à mettre dans le roadmap de la v0.0.2 ». Il fixe un **plan**, pas un engagement de calendrier. Chaque incrément ouvrant une surface nouvelle aura son propre ADR de conception.

## Contexte

En v0.0.1, le client RDP d'ADR-0071 est volontairement étroit.

**Ce qu'il annonce** :
- aucun ordre graphique, aucun cache de glyphes ni de bitmaps ;
- aucun canal virtuel ;
- l'entrée en scancodes slow-path seulement.

**Ce qu'il décode** : les bitmaps (RAW, Interleaved RLE en 15 et 16 bpp, RDP 6.0 planar en 32 bpp), les fragments Fast-Path et la réactivation.

**Pourquoi c'est suffisant pour la v0.0.1.** Tous les critères de sortie de l'incrément 3 sont tenus. Le texte, rendu en bitmaps par la cible, est lisible (ADR-0089). RDP s'ouvre derrière `RDP_ENABLED` (ADR-0088).

**Ce que cette étroitesse coûte** :
- **Débit cible → proxy** : celui des bitmaps, jamais mesuré.
- **Clavier** : seules les touches physiques passent. Un caractère absent de la disposition de la cible ne se tape pas (ADR-0088).
- **Rien d'autre que l'écran** : ni presse-papiers, ni fichiers, ni impression, ni son, ni redimensionnement à la demande de l'opérateur.
- **Pas de passerelle ni de ferme** : ni RD Gateway, ni redirection de ferme RDS, ni Kerberos ; NTLMv2 seulement.
- **Pointeur** : non dessiné.

La v0.0.2 de la feuille de route vise la couverture complète des familles de cibles et les forensics avancés : capture du presse-papiers, des transferts de fichiers et de l'impression.

**Ce qui ne change pas.** Les invariants qui gouvernent toute extension :
- **ADR-0069 §6** : aucun canal secondaire ouvert sans une décision qui définit son enregistrement, sa protection et son audit ;
- **ADR-0071 §5** : toute capacité annoncée est décodée et bornée, ou refusée ; jamais acceptée à moitié ;
- **ADR-0070** : enregistrer ou refuser ;
- **ADR-0039** : le secret n'est envoyé qu'à la cible épinglée.

## Décision proposée

Inscrire en v0.0.2 les cinq lots ci-dessous, dans cet ordre. Chacun est une suite d'incréments livrés par PR. Chaque incrément :
- annonce sa capacité, la décode avec des bornes explicites, et refuse tout le reste ;
- a ses tests d'attaque, ses contre-épreuves et ses mutations, et son fuzzer en CI ;
- est prouvé contre FreeRDP 3 et contre Windows Server 2022 (matrice du CI Windows) ;
- reste éteint par défaut quand il élargit ce que l'opérateur peut faire sur la cible.

### Lot A — Mesurer d'abord (prérequis)

Mesurer, contre Windows, le débit cible → proxy, le coût d'encodage PNG, la latence d'acquittement et la mémoire, sur des écrans types : bureau, texte dense, défilement, vidéo. C'est l'incrément 5 d'ADR-0071.

**Sortie** : des chiffres publiés, et la décision de ce que les lots B et C apportent réellement. ADR-0089 reste la règle tant que ces chiffres ne l'ont pas renversée.

#### Résultats du lot A (11 novembre 2026, premier incrément)

**Banc** : `TestRDPWindows_Measure` et `TestRDPInterop_Measure` (`services/proxy/rdp-vnc-proxy/internal/engine`), sur le proxy tel qu'il tourne par défaut : pointeur dessiné, cadence de 50 ms. Les octets de la cible sont comptés à la lecture TLS (`CredSSPClientSession.ServerBytes`). Les images sont celles que le codec remet au relais, donc celles que le Video Recorder stocke. L'encodage est la médiane de cinq ré-encodages de la dernière image. La mémoire est le pic du tas Go, mesuré sur tout le processus de test. CI Windows du 11 novembre 2026 (run 43068035637), cinq cibles 1280 × 800 sur le même runner que le proxy ; FreeRDP 3 en local.

| Scène | Cible → proxy | Images | PNG par image | Enregistré | Encodage |
|---|---|---|---|---|---|
| Repos, 10 s (Windows) | **0** | 0 | — | 0 | — |
| Repos, 5 s (FreeRDP) | 2 170 Kio/s, des repeints identiques | 0,4/s | 19 Ko | 7,5 Kio/s | 21 ms |
| Frappe dans le Bloc-notes | 11 à 80 Kio/s | 13 à 17/s | 30 à 186 Ko | 420 à 2 370 Kio/s | 9 à 25 ms |
| Fenêtre de texte repeinte (Ctrl+Début) | 15 à 59 Ko en tout | 1 à 2 | 36 à 202 Ko | — | 11 à 27 ms |
| Défilement (20 pages) | 100 à 410 Kio/s | 7 à 8/s | 36 à 202 Ko | 230 à 1 440 Kio/s | 11 à 25 ms |
| Pointeur, 50 déplacements | **0** | 13 à 17/s | 36 à 202 Ko | 500 à 2 650 Kio/s | 12 à 39 ms |

- **Latence touche → image** (proxy et cible sur le même hôte, sans le réseau de l'opérateur ni l'acquittement) : médiane 37 à 84 ms, 90ᵉ centile 49 à 96 ms selon la cible. FreeRDP : médiane 63 ms, 90ᵉ centile 105 ms.
- **Mémoire** : pic du tas de 6 à 20 Mio pour tout le processus de test, une session ouverte.
- **Taille des images** : elle dépend du bureau, pas du protocole. Avec un fond noir, une image fait 30 à 37 Ko ; avec le dégradé bleu de Windows (cibles « console » et fr-FR), 185 à 202 Ko.

**Ce que les chiffres disent :**
1. **Le lien cible → proxy n'est pas le coût.** Au repos, Windows n'envoie rien. En frappe, il envoie 11 à 80 Kio/s, et une fenêtre de texte entière se repeint en 15 à 59 Ko. Les ordres graphiques et les caches (lot B), ou RDPGFX (lot C), réduiraient un débit déjà faible. **Aucun chiffre ne les justifie aujourd'hui** : ADR-0089 reste la règle.
2. **Le coût est l'enregistrement d'images entières.** Chaque changement, même d'un caractère ou d'une position du pointeur, produit un PNG complet. Le volume enregistré est 6 à 60 fois celui que la cible envoie : jusqu'à 2,6 Mio/s pendant que la souris bouge sur un bureau à fond d'écran. Ce levier est hors de cet ADR. Il passerait par des images partielles, c'est-à-dire les seuls rectangles changés, dans le flux écran et dans le Video Recorder : un changement de contrat qui demande sa propre décision.
3. **L'encodage PNG coûte 9 à 27 ms par image** sur le runner de CI, jusqu'à 39 ms. À 15 images par seconde, une session active occupe environ un tiers d'un cœur. C'est la limite de capacité à mesurer ensuite, avec plusieurs sessions à la fois.

**Mesuré ensuite (12 novembre 2026) : l'acquittement du Video Recorder, seul et à plusieurs sessions.** `TestVideoRecorderAckLatency` (proxy, `RECORDER_MEASURE=1`) fait tourner le vrai Recorder sur PostgreSQL et le vrai client du proxy sous mTLS. Chaque session enregistre 60 images à 50 ms d'écart, une image par segment comme le proxy. Hôte de 6 cœurs, tout sur la même machine. Le stockage objet est celui, en mémoire, de l'épreuve d'enregistrement : la latence propre de S3 n'y est pas.

| Image | Sessions | Acquittement p50 | p95 | max |
|---|---|---|---|---|
| Partielle, 1,5 Ko | 1 / 5 / 10 | 15 / 18 / 31 ms | 23 / 49 / 58 ms | 65 / 71 / 85 ms |
| Clé, 33 Ko | 1 / 5 / 10 | 16 / 21 / 31 ms | 29 / 32 / 59 ms | 69 / 67 / 95 ms |
| Clé, 184 Ko | 1 / 5 / 10 | 19 / 31 / 80 ms | 30 / 102 à 463 / 281 ms | 40 / 459 à 1 289 / 946 à 1 205 ms |

- L'acquittement ajoute 15 à 30 ms en médiane avant qu'une image soit montrée, jusqu'à 10 sessions, pour les images partielles (le cas par défaut, ADR-0092) comme pour les petites images clés.
- **Les grosses images clés** (bureau à fond d'écran) font grimper la queue dès 5 sessions : de 0,1 à 0,5 s au 95ᵉ centile, et jusqu'à 1,3 s au maximum. Deux passages ont donné des queues différentes : c'est bruité. Avec les images partielles, une image clé ne revient qu'à l'ouverture, au redimensionnement et toutes les 10 s, mais c'est la limite de capacité à surveiller.
- **Avec un vrai S3** : voir ci-dessous.
- **Au-delà de 10 sessions** : voir plus bas.
- **Scène vidéo** : voir plus bas.
- **Pas encore mesuré** : un S3 distant ou sous TLS.

**Mesuré ensuite (12 novembre 2026) : le même acquittement, avec un vrai S3.** Même épreuve, mais le Recorder écrit dans un SeaweedFS 4.52 (`RECORDER_MEASURE_S3_ENDPOINT`) : un nœud unique, en conteneur sur le même hôte, en HTTP clair. Deux passages S3, et un passage en mémoire juste avant, comme témoin.

| Image | Sessions | Mémoire p50 / p95 / max | S3 p50 | S3 p95 | S3 max |
|---|---|---|---|---|---|
| Partielle, 1,5 Ko | 1 / 5 / 10 | 12 / 29 / 97 · 14 / 41 / 83 · 25 / 110 / 251 ms | 12 à 29 / 14 à 37 / 31 à 74 ms | 17 à 71 / 26 à 155 / 87 à 417 ms | 23 à 450 / 71 à 676 / 194 à 1 147 ms |
| Clé, 33 Ko | 1 / 5 / 10 | 12 / 32 / 83 · 11 / 23 / 65 · 22 / 69 / 138 ms | 17 à 25 / 30 à 35 / 41 à 45 ms | 24 à 58 / 141 à 185 / 185 ms | 40 à 131 / 308 à 866 / 489 à 2 397 ms |
| Clé, 184 Ko | 1 / 5 / 10 | 25 / 59 / 129 · 18 / 59 / 87 · 33 / 136 / 245 ms | 18 à 45 / 25 à 39 / 44 à 61 ms | 36 à 117 / 75 à 151 / 124 à 164 ms | 77 à 226 / 146 à 471 / 323 à 362 ms |

- **La médiane tient** : 12 à 74 ms avec S3, contre 11 à 33 ms en mémoire. S3 ajoute de 0 à 50 ms en médiane, le plus à 10 sessions.
- **La queue s'allonge** : le 95ᵉ centile monte jusqu'à 0,4 s, et le maximum dépasse la seconde dans deux cas (1,1 s et 2,4 s, à 10 sessions). L'opérateur verrait alors l'écran figé pendant ce temps.
- **Très bruité** : d'un passage S3 à l'autre, le même cas varie d'un facteur 2 à 20 sur le maximum. Le premier passage, sur un SeaweedFS tout juste démarré, est le plus lent. Deux passages ne suffisent pas à classer les cas entre eux.
- **Ce n'est pas un plafond** : SeaweedFS sur le même hôte n'a ni réseau ni TLS. Un S3 distant ajoute au moins son aller-retour à chaque image. Il faudra le mesurer sur la cible de déploiement.
- **Pas de décision à prendre ici** : rien ne justifie encore de regrouper les images à l'enregistrement (ADR-0093, option B écartée). La queue au-delà d'une seconde est à surveiller sur un vrai déploiement.
- Ces deux passages précèdent le correctif du pool ci-dessous : une partie de leur queue venait sans doute de lui.

**Mesuré ensuite (12 novembre 2026) : 20 et 50 sessions, et une perte d'images trouvée.** `RECORDER_MEASURE_SESSIONS` fixe le nombre de sessions simultanées. À 50 sessions, en mémoire, le Recorder perdait des images : avec les grosses images clés, 48 sessions sur 50 ont eu une image non acquittée (l'épreuve arrête une session à sa première perte), toutes en `cannot assign requested address`. Une image perdue coupe sa session : le proxy ne montre pas ce qui n'est pas enregistré.
- **Cause** : `database/sql` garde par défaut 2 connexions inactives et en ouvre autant qu'on lui en demande. À 50 sessions, le Recorder ouvrait et fermait une connexion PostgreSQL presque à chaque image, jusqu'à épuiser les ports de l'hôte.
- **Correctif** : les sept services qui ouvrent PostgreSQL gardent 10 connexions, ouvertes au plus et gardées inactives. Sept services restent ainsi sous les 100 connexions par défaut de PostgreSQL. 10 a fait aussi bien que 25 à l'essai.

| 50 sessions | Avant (pool par défaut) p50 / p95 / max | Après, en mémoire (2 passages) p50 / p95 / max | Après, S3 (2 passages) p50 / p95 / max |
|---|---|---|---|
| Partielle, 1,5 Ko | 50 / 127 / 314 ms · 139 / 390 / 1 980 ms | 12 à 19 / 39 à 46 / 95 à 259 ms | 51 à 94 / 152 à 238 / 384 à 547 ms |
| Clé, 33 Ko | 46 / 136 / 610 ms · 240 / 622 / 1 677 ms | 14 à 21 / 35 à 47 / 175 à 204 ms | 59 à 235 / 161 à 1 031 / 457 à 2 851 ms |
| Clé, 184 Ko | 147 / 712 / 948 ms, **48 sessions sur 50 coupées** | 59 à 74 / 612 à 642 / 807 à 817 ms | 164 à 218 / 535 à 691 / 2 163 à 3 192 ms |

- **Après le correctif, plus aucune image perdue**, à 10, 20 et 50 sessions, en mémoire comme avec S3, sur quatre passages.
- **En mémoire**, les images partielles et les petites images clés restent sous 20 ms en médiane à 50 sessions. À 20 sessions, médiane de 8 à 18 ms.
- **Avec S3 à 50 sessions**, la médiane monte de 50 à 235 ms et le maximum atteint 2 à 3 s pour les images clés. Le SeaweedFS à nœud unique devient le goulet. Une session active voit ces délais à chaque image clé, et à chaque image si l'écran change beaucoup.
- **Limites** : un seul hôte de 6 cœurs pour tout (Recorder, PostgreSQL, S3, client), sans réseau ni TLS vers S3 ; peu de passages.

**Mesuré ensuite (12 novembre 2026) : une scène vidéo contre Windows.** `rdp-video.ps1` joue, à la demande du test par le partage, 10 s de blocs de 8 pixels de couleur au hasard, renouvelés 25 fois par seconde sur tout l'écran : le pire cas pour PNG, un majorant pour une vidéo. CI Windows de la PR #149 (exécution 43245190987), cinq cibles 1280 × 800, en images entières puis partielles. L'écran ne change que pendant les 10 s de lecture : les débits ci-dessous sont rapportés à ces 10 s. La scène elle-même dure 12 à 20 s, ouverture de la fenêtre et retour au calme compris. Au premier passage, chaque demande jouait deux fois (deux noms pour le même partage) : les débits concordaient, les nombres d'images étaient doublés.

| Cible | Cible → proxy | Images en 10 s | PNG par image | Enregistré | Encodage |
|---|---|---|---|---|---|
| 2019, 16 bpp | 1 090 à 1 107 Kio/s | 135 à 136 | 90 à 93 Ko | 1 200 à 1 228 Kio/s | 35 ms |
| 2022, 16 bpp (trois cibles) | 712 à 846 Kio/s | 115 à 127 | 90 à 94 Ko | 1 010 à 1 170 Kio/s | 17 à 43 ms |
| 2022, 32 bpp | 2 868 à 3 048 Kio/s | 130 à 132 | 97 à 101 Ko | 1 254 à 1 281 Kio/s | 20 à 21 ms |

- **Le lien cible → proxy devient un coût**, pour la première fois : 0,7 à 3,0 Mio/s, contre 11 à 80 Kio/s en frappe. À 32 bpp, Windows envoie trois à quatre fois plus qu'à 16 bpp pour la même scène.
- **L'enregistrement reste du même ordre** : 1,0 à 1,3 Mio/s, un peu plus que ce que la cible envoie à 16 bpp. Tout l'écran change à chaque image : les images partielles n'apportent rien (presque toutes sont des images clés), comme prévu par ADR-0092.
- **La cadence plafonne sous 20 images/s** : 11,5 à 13,6 images par seconde de vidéo, pour 25 changements par seconde à l'écran et un plafond de 20 (une image toutes les 50 ms). L'encodage, 17 à 43 ms par image, en explique une partie ; la cadence que Windows envoie n'a pas été mesurée à part.
- **Ce que ça décide** : rien de nouveau pour les lots B et C. Une vidéo réelle serait plus légère que ce bruit. Si l'on voulait réduire le lien cible → proxy en vidéo, c'est RDPGFX (lot C) qui le ferait, et ses codecs sans perte resteraient lourds sur un tel contenu. Le lot A est clos, sauf le S3 distant.

### Lot B — Ordres graphiques

1. **Ordres primaires déjà décodés, à annoncer** : DstBlt, PatBlt, ScrBlt, OpaqueRect et leurs variantes Multi, LineTo, Polyline, PolygonSC, EllipseSC. Leurs profils stricts sont à élargir là où Windows en sort : bornes, deltas, `ZEROBOUNDSDELTAS`, champs omis.
2. **Caches** : cache de pinceaux (Cache Brush), cache de bitmaps v2 et v3 (Cache Bitmap rév. 2 et 3), puis MemBlt et Mem3Blt.
3. **Formes avec pinceau** : PolygonCB et EllipseCB ; SaveBitmap.
4. **Glyphes** : `TS_GLYPHCACHE_CAPABILITYSET`, Cache Glyph rév. 1 et 2, GlyphIndex, FastIndex, FastGlyph, cache de fragments.
5. **Bitmaps hors écran** (Alternate Secondary Orders) : seulement si le lot A le justifie.

**Bornes** : par cache (entrées, octets), par ordre, et par mise à jour, comme `maxRDPBitmapUpdateRects`. Toute référence à une entrée de cache absente ferme la session.

**Sortie** : l'image rendue par ordres est identique, au pixel près, à celle d'une session en bitmaps seuls sur les mêmes écrans types, à 16 et 32 bpp. Le débit est mesuré avant et après.

### Lot C — Pipeline graphique (RDPGFX)

Les canaux virtuels dynamiques (`DRDYNVC`, lot D) sont un prérequis. Puis `Microsoft::Windows::RDS::Graphics` avec les codecs sans perte : Planar, ClearCodec, RemoteFX progressif en mode sans perte si mesurable. AVC/H.264 est exclu : une image avec perte rejouée n'est pas l'image d'origine (ADR-0070), et ce serait une dépendance de décodeur. Cet incrément aura son propre ADR.

**Sortie** : profondeur 32 bpp sans stratégie côté cible, débit mesuré, rejeu identique.

### Lot D — Canaux virtuels, chacun sous ADR-0069 §6

**Socle** : canaux statiques (MCS) et dynamiques (`DRDYNVC`), avec liste fermée des canaux annoncés et bornes par canal. Puis, chacun avec un ADR qui fixe ce qui est enregistré, chiffré et audité, et un interrupteur éteint par défaut :

1. **Display Control** : redimensionnement à la demande de l'opérateur ; le flux suit déjà un changement de taille (incrément 72).
2. **Presse-papiers (`CLIPRDR`)** : texte d'abord, dans chaque sens selon une politique. Contenu enregistré et chiffré avec la session, événement d'audit par transfert ; c'est la « capture clipboard » des forensics v0.0.2.
3. **Redirection de lecteurs (`RDPDR`)**, pour les transferts de fichiers : lecture seule ou écriture selon politique, fichiers enregistrés (empreinte et contenu chiffré), audit par fichier.
4. **Impression (`RDPDR` imprimante)** : document capturé et audité.
5. **Son (`RDPSND`)** : seulement s'il est demandé ; son enregistrement reste à décider.

Restent fermés, sans exception : cartes à puce, ports série et parallèles, USB, caméra, saisie audio.

### Lot E — Protocole

1. **Entrée** :
   - Fast-Path Input ;
   - Unicode Keyboard Event, qui lève la limite d'ADR-0088 (un caractère que la disposition de la cible ne donne pas), derrière une politique ;
   - souris étendue (molette horizontale) ;
   - Synchronize Event à la perte de focus, s'il est mesuré utile.
2. **Pointeur** : dessiné dans l'image enregistrée, ou transmis à part. ADR à décider, puisque l'image rejouée doit rester l'image montrée.
3. **Reconnexion automatique** (cookie ARC) : reprise sans nouveau scope Vault dans la durée de la session, sous ADR.
4. **Redirection de ferme RDS** (Server Redirection PDU) : refusée aujourd'hui, à n'accepter que vers une cible épinglée du même compte (ADR-0039).
5. **Kerberos dans CredSSP** : à côté de NTLMv2, pour les domaines qui désactivent NTLM. ADR propre ; le secret reste au Vault.
6. **RD Gateway** (RDP sur HTTPS ou WebSocket) : atteindre une cible derrière une passerelle, avec l'épinglage de la passerelle et de la cible.
7. **Compression bulk** (MPPC, NCRUSH, XCRUSH) : seulement si le lot A montre un débit gênant.
8. **Licences complètes** (CAL par utilisateur ou par appareil) : contre une ferme RDS sous licence.

### Ordre et dépendances

Lot A, puis B (sans dépendance externe), puis D-socle, puis C et le reste de D, et E en parallèle. Un lot ne commence que si le précédent a ses chiffres ou ses preuves.

## Conséquences

- (+) La v0.0.2 a un plan RDP explicite, ordonné, borné par les invariants existants. Chaque surface nouvelle passe par un ADR, des tests d'attaque et la matrice Windows.
- (+) Les forensics v0.0.2 (presse-papiers, fichiers, impression) ont leur chemin côté RDP.
- (−) C'est le plus gros chantier protocolaire du projet. Le lot B à lui seul ajoute plusieurs parseurs exposés à la cible, et le lot C un pipeline entier. Aucun calendrier n'est promis.
- (−) Chaque canal ouvert élargit ce qu'un opérateur peut faire sur la cible, ou en sortir. Les interrupteurs éteints par défaut et les politiques en sont la contrepartie, à la charge de l'exploitant.
- (−) La matrice Windows du CI s'alourdit (écrans types, mesures) ; son coût de calcul augmente.
- (−) ADR-0089 reste la règle de la v0.0.1. Ce plan ne la renverse que lot par lot, sur mesure.

## Alternatives envisagées

- **Tout implémenter d'un bloc, comme un client complet** : écartée. La surface ne serait ni bornée ni prouvée incrément par incrément, et un canal ouvert sans décision d'enregistrement violerait ADR-0069 §6.
- **Adopter une bibliothèque RDP tierce** (FreeRDP en cgo, grdp, gordp) : écartée par ADR-0071 et ADR-0084. Ni l'épinglage avant le secret, ni les points d'enregistrement, ni le sous-ensemble fermé ; la dépendance et sa surface seraient à auditer en entier.
- **AVC/H.264 pour le débit** : écartée. Le rejeu avec perte n'est pas l'image d'origine, et le décodeur serait une dépendance lourde.
- **Ne rien planifier au-delà d'ADR-0089** : écartée à la demande du propriétaire. Les forensics v0.0.2 exigent au moins les lots D et E.
