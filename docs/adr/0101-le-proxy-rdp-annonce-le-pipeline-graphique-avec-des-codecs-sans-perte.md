# ADR-0101 — Le proxy RDP annonce le pipeline graphique (RDPGFX) avec des codecs sans perte seulement

**Statut** `Accepté` · 13 novembre 2026 · accepté le même jour par le propriétaire du projet : « ADR-0101 l'interrupteur, éteint par défaut le temps des incréments prouvés contre les cinq cibles Windows, comme pour ADR-0095 et ADR-0096 ». L'option retenue est A, la décision proposée (codecs sans perte seulement), le propriétaire n'en ayant pas nommé d'autre.

## Contexte

Le client RDP n'annonce pas le pipeline graphique (`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL`). Conséquences mesurées :
- un Windows laissé par défaut plafonne la session à 16 bpp (ADR-0086) ;
- l'écran arrive en mises à jour bitmap de l'ancien protocole (Interleaved RLE, RDP6 planar), avec une partie des ordres graphiques (ADR-0090, lot B).

Le lot A d'ADR-0090 a montré que le lien cible → proxy n'est pas le coût : c'est l'enregistrement des images. RDPGFX ne se justifie donc pas par le débit. Il se justifie par trois choses :
- la profondeur 32 bpp sans stratégie côté cible ;
- l'avenir : Windows privilégie RDPGFX, et l'ancien chemin pourrait se dégrader ;
- les canaux de la v0.0.2.

Le prérequis est fait : `drdynvc` et les canaux dynamiques sur une liste fermée (ADR-0095).

MS-RDPEGFX, ce qu'il faudrait :
- le canal `Microsoft::Windows::RDS::Graphics` dans la liste fermée ;
- l'échange de capacités ;
- les surfaces : création, suppression, rattachement à la sortie ;
- le remplissage uni, la copie de surface à surface, le cache de surfaces ;
- `WireToSurface` avec un codec ;
- les trames de début et de fin, et l'acquittement de trame.

Les codecs que Windows peut choisir :
- non compressé ;
- Planar, que le client décode déjà en grande partie (RDP 6.0 planar) ;
- ClearCodec (sans perte, avec des sous-codecs) ;
- RemoteFX progressif (avec perte selon la quantification) ;
- AVC420 et AVC444 (H.264, avec perte).

## Options

- **A. RDPGFX, codecs sans perte seulement** : n'annoncer que les capacités qui permettent le non compressé, Planar et ClearCodec, et refuser tout autre codec.
- **B. RDPGFX avec RemoteFX progressif ou AVC** : plus économe, mais l'image rejouée n'est plus l'image affichée bit à bit si le codec perd. Contraire à ADR-0070 (« enregistrer ce qui a été montré ») et, pour AVC, une dépendance de décodeur vidéo.
- **C. Statu quo** : l'ancien chemin bitmap, avec ses limites de profondeur.

## Décision proposée

**A**, par incréments prouvés contre les cinq cibles Windows :
1. **Canal et capacités** : le canal entre dans la liste fermée d'ADR-0095. Le client annonce une version de capacités qui permet de désactiver AVC, et refuse toute capacité qui imposerait un codec avec perte.
2. **Surfaces et commandes sans codec** : remplissage uni, copie, cache.
3. **`WireToSurface`**, codecs non compressé et Planar.
4. **ClearCodec**, avec ses sous-codecs bornés et fuzzés.
5. **Sortie** : profondeur 32 bpp sans stratégie, image rejouée identique à l'image montrée, débit mesuré.

Tout PDU ou codec hors de cette liste ferme la session, comme aujourd'hui. Le chemin bitmap actuel reste celui d'une cible qui refuse RDPGFX.

## Mise en œuvre

### Incrément 1 — canal, capacités et décompression (13 novembre 2026)

- **Réglage** : `MCSClientSettings.GraphicsPipeline` pose `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (0x0100) dans les capacités précoces ; il exige `DynamicChannels`. Éteint, le Connect-Initial est inchangé à l'octet. Rien ne l'allume dans le service : l'interrupteur de service viendra avec l'incrément qui dessine une image.
- **Canal** : `Microsoft::Windows::RDS::Graphics` entre dans la liste fermée d'ADR-0095. Un message réassemblé y est borné à 16 Mio, contre 64 Kio sur les autres canaux : le pipeline porte des bitmaps entiers.
- **Capacités annoncées**, de la plus récente à la plus ancienne : 10.7, 10.6, 10.5, 10.4, 10.2 et 10, toutes avec `AVC_DISABLED` et `SMALL_CACHE` (10.7 avec aussi `SCALEDMAP_DISABLE`) ; puis 8.1 et 8, avec `SMALL_CACHE` seul. 10.1 et 10.3 ne sont pas annoncées : la première n'a pas `AVC_DISABLED`, la seconde n'a pas `SMALL_CACHE`, donc un cache de 100 Mo.
- **Confirmation** : la cible doit confirmer une version annoncée, avec exactement les drapeaux annoncés pour elle. Tout PDU avant la confirmation, une seconde confirmation, ou une commande que la cible n'envoie pas (acquittements, offre de cache, annonce de capacités, commande non définie) ferme la session.
- **`Sp` d'un PDU DATA** : MS-RDPEDYC 2.2.3.2 le dit inutilisé, mais les cinq Windows de la CI le posent à 2 sur le canal graphique (CI de la PR #194). Il n'est plus lu ; la longueur du message reste celle du PDU.
- **Décompression (ajoutée à l'incrément 1)** : tout message de la cible arrive dans un `RDP_SEGMENTED_DATA`, compressé en RDP 8.0 (ZGFX, MS-RDPEGFX 3.1.9.1). Sans elle, aucune confirmation ne se lit. L'historique fait 2 500 000 octets par canal. Bornes : 65 535 octets par segment, 16 Mio par message, aucune correspondance avant le début de l'historique. Les bits réservés de l'en-tête sont ignorés : ils ne changent rien au décodage.
- **Prouvé** :
  - les exemples de la spécification, chaque ligne de la table des jetons, chaque classe de distance à ses deux bornes et chaque classe de longueur, après le tour de l'historique ;
  - 23 refus du décompresseur et 20 du pipeline ;
  - deux fuzzers (`FuzzZGFXSegmentedData`, `FuzzRDPGraphicsPipelineRead`) ;
  - 24 mutations tuées.
- **Mesuré contre FreeRDP 3** (`TestRDPInterop_GraphicsPipeline`) :
  - FreeRDP confirme la version 10.7 avec les drapeaux annoncés ;
  - en 10 s : 325 messages, 4,98 Mo décompressés sans faute ;
  - une surface de 1280 x 800 (`XRGB_8888`), puis 321 trames, toutes en `WireToSurface2`, codec **RemoteFX progressif (0x0009)**.
- **Mesuré contre les cinq Windows** (`TestRDPWindows_GraphicsPipeline`, CI de la PR #194, 20 s au bureau ouvert, sans saisie) :
  - les cinq confirment la version **10.6** avec les drapeaux annoncés (`AVC_DISABLED | SMALL_CACHE`) ; aucune ne prend 10.7 ;
  - une surface de 1280 x 800 en `ARGB_8888` (0x21), rattachée par `MapSurfaceToScaledOutput` (0x0017) : la version 10.6 n'a pas `SCALEDMAP_DISABLE`, cette commande y est donc légitime ;
  - les images : **ClearCodec (0x0008)** pour 21 à 29 `WireToSurface1`, et **RemoteFX progressif (0x0009)** pour 1 ou 2 `WireToSurface2` par session, suivis d'un `DeleteEncodingContext` ;
  - le cache sert beaucoup : 8 à 16 `SurfaceToCache` et 727 à 1010 `CacheToSurface` par session ; 3 à 5 `SolidFill` ; 5 à 9 trames ;
  - 17 à 85 Ko reçus, sans faute de décompression.
- **Ce que cela annonce** : aucune capacité n'éteint RemoteFX ni RemoteFX progressif (MS-RDPEGFX 2.2.3), et Windows envoie bien du RemoteFX progressif, même si c'est rare, à côté de ClearCodec. L'option A ne tient donc pas telle quelle (voir « RemoteFX progressif » ci-dessous).

### RemoteFX progressif : décodé, et enregistré tel qu'il a été montré (14 novembre 2026)

**Décision** : je l'ai prise par délégation du propriétaire, qui a écrit le 14 novembre 2026 : « pour les approbations qui demanderaient mon accord, choisis les options qui te semble les plus recommandées ». Elle est renversable.

- **Ce qui est décidé** : une image en RemoteFX progressif (0x0009) est décodée par le proxy. L'opérateur voit l'image décodée, et l'enregistrement garde la même image, à l'octet.
- **Pourquoi** : la garantie d'ADR-0070, « enregistrer ce qui a été montré », porte sur le lien entre ce que l'opérateur voit et ce que l'auditeur relit, et ce lien reste exact. Ce qui n'est plus exact, ce sont les pixels de la cible avant compression. C'est déjà le cas aujourd'hui de l'ancien chemin à 16 bpp, que Windows impose par défaut (ADR-0086).
- **Ce qui reste refusé** : H.264 (AVC), écarté par les capacités, et RemoteFX non progressif (0x0003), que Windows n'a pas envoyé. Une session qui en reçoit est fermée, comme pour tout codec hors liste.
- **Un incrément de plus** : RemoteFX progressif est décodé après ClearCodec (incrément 4 bis), avec ses bornes, ses fuzzers et ses mutations, comme chaque codec.
- **Alternatives écartées** :
  - refuser la session : les cinq Windows de la CI envoient une ou deux de ces images à chaque session, et le pipeline graphique deviendrait inutilisable ;
  - revenir à l'ancien chemin : le pipeline se négocie à la connexion, donc il faudrait se reconnecter en cours de session, et l'opérateur verrait l'écran se couper.

### Incrément 2 — surfaces, remplissage, copies, cache et trames (14 novembre 2026)

- **Fait** : `RDPGraphicsCompositor` (`pkg/rdp/graphics_surface.go`) dessine ce que la cible envoie sans codec :
  - la remise à zéro de la sortie (`ResetGraphics`) ;
  - la création et la suppression des surfaces, et leur rattachement à la sortie. Le rattachement « mis à l'échelle » n'est admis qu'à l'échelle 1, la seule que Windows a envoyée ;
  - le remplissage uni, la copie de surface à surface (chevauchement compris), et le cache : mise en cache, copie depuis le cache, éviction ;
  - les débuts et fins de trame. À chaque fin, les surfaces rattachées qui ont changé sont copiées dans la sortie, opaque (3.3.5.12), et la trame est acquittée.
- **Bornes** :
  - 64 surfaces et 64 Mio de pixels au plus ;
  - le cache de `SMALL_CACHE` : emplacements 1 à 4096, 16 Mio de données ;
  - une sortie d'au plus 16 777 216 pixels et 16 moniteurs.
- **Lecture stricte** : là où la spécification ne dit rien (surface inconnue, rectangle hors de sa surface, emplacement vide, surface créée deux fois, fin d'une trame non commencée), la session est fermée. Les réponses à une offre de cache, que ce client ne fait jamais, et le rattachement à une fenêtre (RAIL) sont refusés aussi.
- **Lecture littérale de `ResetGraphics`** : la sortie est redimensionnée, et les surfaces et le cache restent ; c'est tout ce que dit la spécification.
- **Les codecs** ne sont pas dessinés à cet incrément : ils sont nommés (`ErrRDPGraphicsCodec`).
- **Prouvé** :
  - chaque commande au pixel près ;
  - 40 refus ;
  - un fuzzer (`FuzzRDPGraphicsCompositor`) ;
  - 20 mutations tuées.
- **Contre FreeRDP 3** : 322 trames dessinées et acquittées en 10 s, sans faute. FreeRDP n'envoie que du RemoteFX progressif : ici, seules ses commandes sans codec sont dessinées.
- **Contre les cinq Windows** (CI de la PR #196) : la lecture stricte tient, sans aucune faute. Chaque session dessine et acquitte 6 à 9 trames en 20 s, avec jusqu'à 196 mises en cache et 1 101 copies depuis le cache.

### Ordre des incréments revu (14 novembre 2026)

**Décision** : prise par délégation du propriétaire, renversable.

- **Le constat** : les cinq Windows de la CI n'envoient ni image non compressée, ni Planar. Ils envoient ClearCodec et RemoteFX progressif, et FreeRDP n'envoie que du RemoteFX progressif. L'incrément 3 prévu, « non compressé et Planar », ne pourrait donc être éprouvé contre aucune vraie cible.
- **Le nouvel ordre** :
  - incrément 3 : ClearCodec, avec le non compressé, dont la spécification est claire ;
  - incrément 4 : RemoteFX progressif ;
  - incrément 5 : la sortie, inchangée.
- **Planar** reste refusé, par son nom (`ErrRDPGraphicsCodec`), tant qu'aucune cible ne l'envoie. Sa spécification ne dit pas dans quel sens se lisent ses lignes dans le pipeline graphique, et seule une vraie cible pourra trancher.

### Incrément 3 — ClearCodec et le non compressé (14 novembre 2026)

- **Fait** : `pkg/rdp/graphics_clearcodec.go` décode ClearCodec (MS-RDPEGFX 2.2.4.1). Les trois calques sont dessinés dans l'ordre sur le rectangle de la surface :
  - résiduel : des séries d'une couleur ;
  - bandes : des colonnes de pixels (« V-bars »), tirées de deux caches de 32 768 et 16 384 entrées, ou construites ;
  - sous-codecs : pixels bruts, ou RLEX, c'est-à-dire des séries et des suites dans une petite palette.

  S'y ajoutent les glyphes (4 000 emplacements de 1 024 pixels au plus) et le numéro de séquence, qui doit suivre. Les pixels sont lus en bleu, vert, rouge ; l'alpha de la surface reste tel quel (3.3.5.1). `WireToSurface1` est lu et borné, avec un rectangle obligatoirement dans sa surface. Le non compressé (0x0000) est décodé aussi.
- **Où la spécification se tait**, la lecture de FreeRDP, notée comme telle dans le code :
  - une suite RLEX va de son indice de départ à son indice d'arrêt inclus ;
  - une palette d'une couleur a des indices d'un bit ;
  - le curseur des petites V-bars revient à zéro après 16 384.

  Une mauvaise lecture se verrait sur l'écran de la CI, ou casserait le compte exact de pixels que chaque calque doit remplir.
- **Corrigé contre Windows** (premier passage de la CI de la PR #197) : les cinq Windows envoient des petites V-bars sans pixel (`yOn == yOff`), puis les reprennent du cache. Le décodeur les gardait comme un emplacement vide, et refusait la reprise. Elles sont désormais gardées comme les autres, et un test les couvre.
- **Non décodé** : le sous-codec NSCodec (0x01), refusé par son nom. Le test de bout en bout compte les codecs non dessinés au lieu de s'arrêter : la CI dira si Windows l'emploie.
- **Mémoire** : au plus 16 Mio de glyphes, 7,7 Mio de V-bars et 1,3 Mio d'index par canal ouvert.
- **Prouvé** :
  - chaque calque et chaque cache, au pixel près ;
  - 40 refus ;
  - un fuzzer (`FuzzClearCodec`) ;
  - 22 mutations tuées.
- **Non éprouvé contre une vraie cible** : le non compressé, que ni Windows ni FreeRDP n'envoient. L'ordre des octets d'un pixel (bleu, vert, rouge, alpha, comme `RDPGFX_COLOR32`) n'est pas écrit dans la spécification.

- **Contre les cinq Windows** (CI de la PR #197) :
  - 17 à 33 bitmaps ClearCodec par session, décodés sans faute ;
  - l'image composée (`graphics-pipeline.png`) montre l'écran juste : Notepad et le texte collé (« é € » compris), la barre des tâches, les icônes et l'horloge ;
  - il manquait sous 2022 un rectangle de la barre des tâches et des icônes du bureau. Ce sont les parties en NSCodec, qu'emploient 4 cibles sur 5, une à quatre fois par session, et en RemoteFX progressif.

### Incrément 3 bis — NSCodec dans ClearCodec (14 novembre 2026)

- **Fait** : `pkg/rdp/graphics_nscodec.go` décode le sous-codec 0x01 (MS-RDPNSC), c'est-à-dire :
  - les plans de luminance, de chrominance orange et verte, et d'alpha, bruts ou en séries (fin des quatre derniers octets en clair) ;
  - la chrominance réduite de `ColorLossLevel` bits, et sous-échantillonnée sur des plans élargis à 8 colonnes et 2 lignes.
- **Couleur, corrigée deux fois** : la conversion est celle de FreeRDP (`nsc_decode`). Chaque octet de chrominance est décalé de `ColorLossLevel - 1` bits, et alors seulement lu comme signé, puis R = Y + Co - Cg, G = Y + Cg, B = Y - Co - Cg, sans inversion.
  - **Premier passage** (PR #198) : l'octet était lu comme signé avant le décalage, ce qui perdait le signe d'une moitié des valeurs. Le fond bleu de Windows 2022 est sorti orange.
  - **Ma deuxième lecture** : j'avais conclu à tort que la spécification avait raison d'exiger une inversion rouge-bleu. Elle a masqué l'erreur sur les pixels où l'écran a été regardé, mais le fond est sorti vert au passage de la PR #199.
  - **La cause** a été trouvée en rejouant en local les messages bruts de cette session. Au message 8, le pixel Y 107, Co 37, Cg 63 (`ColorLossLevel` 3) est le bleu (3, 103, 219). Un test le garde, et l'ancien calcul y redonne exactement le vert de la CI.
- **Lecture de FreeRDP** : l'octet qui précède les quatre derniers d'un plan est un littéral, même s'il est égal au suivant.
- **Constat** : la borne de ClearCodec (3 octets par pixel au plus pour un sous-codec) exclut tout NSCodec à plans bruts, dont l'en-tête seul ajoute 20 octets. Windows n'envoie donc dans ClearCodec que des plans en séries ou sous-échantillonnés.
- **L'alpha** est lu et borné, mais pas dessiné : ClearCodec dessine le rouge, le vert et le bleu.
- **Prouvé** :
  - les couleurs, le sous-échantillonnage et les séries, au pixel près ;
  - 18 refus ;
  - un fuzzer (`FuzzNSCodec`) ;
  - 15 mutations tuées.

### Incrément 4 — RemoteFX progressif (14 novembre 2026)

- **Fait** : `pkg/rdp/graphics_progressive.go` décode `WireToSurface2` en RemoteFX progressif (MS-RDPEGFX 2.2.4.2) :
  - les blocs SYNC, CONTEXT, FRAME_BEGIN, REGION et FRAME_END ;
  - les tuiles de 64 x 64, simples, en premier passage ou en passe de raffinement ;
  - par composante (Y, Cb, Cr) : RLGR1, le cumul des écarts LL3, la déquantification par sous-bande ;
  - pour les raffinements : les bits bruts là où le signe d'un coefficient est connu, Simplified-RL là où il est nul ;
  - les deux ondelettes inverses : « Reduce-Extrapolate » et celle d'origine de RemoteFX ;
  - la conversion YCbCr vers RGB en virgule fixe.

  Chaque tuile est dessinée dans les rectangles de sa région, bornée à sa surface. L'état progressif est gardé par surface, et oublié avec elle.
- **Référence** : la spécification ne donne ses algorithmes qu'en figures (adaptation de RLGR, équations des ondelettes, matrice de couleur). Le code suit l'arithmétique entière de FreeRDP 3.15 (`progressive.c`, `rfx_rlgr.c`, `rfx_dwt.c`, `prim_colors.c`), lu comme référence et écrit à neuf. L'image produite est donc celle que FreeRDP montre.
- **Bornes** : 1 024 tuiles gardées par canal (48 Kio chacune), 7 tables de quantification au plus, des quantifications progressives de 0 à 8. Les deux flux d'une passe de raffinement doivent être lus jusqu'au bout.
- **Prouvé** :
  - RLGR1 et Simplified-RL sur des flux calculés à la main depuis leurs règles ;
  - les deux ondelettes sur une image unie, et la couleur sur une valeur connue ;
  - un premier passage puis une passe de raffinement ;
  - 23 refus et un fuzzer (`FuzzRDPGraphicsProgressive`) ;
  - **une trame réelle de FreeRDP rejouée** (`testdata/graphics/freerdp-progressive`, 88 Kio) : la fenêtre xterm de l'écran de test, vérifiée à l'œil, puis épinglée par son empreinte SHA-256 ;
  - **une session réelle de Windows Server 2022 rejouée** (`testdata/graphics/windows-2022`, 17 messages, 144 Kio, tirés de l'artefact de la CI de la PR #199). On y trouve ClearCodec avec NSCodec, et RemoteFX progressif en « Reduce-Extrapolate », avec ses raffinements. Le bureau entier (fond, filigrane, barre des tâches, Notepad), vérifié à l'œil, est épinglé par son empreinte ;
  - 30 mutations tuées. Trois survivent, sans effet sur les données de référence : la dernière colonne de l'ondelette d'origine (nulle sur les bords unis de la trame FreeRDP) et deux constantes de couleur décalées d'une unité (l'arrondi ne change pas).
- **Contre FreeRDP 3** : 183 trames en 10 s décodées sans faute. FreeRDP emploie l'ondelette d'origine ; on voit aux coins des tuiles les artefacts que la spécification lui attribue (3.2.8.1.2.2).
- **Contre les cinq Windows** (CI de la PR #199) : plus aucune image non dessinée, et aucune faute. La CI dépose désormais les messages bruts du canal graphique dans l'artefact (`graphics-messages/`). C'est en les rejouant en local que l'erreur de couleur de NSCodec a été trouvée.

### Incrément 5 — le pipeline au proxy écran, derrière `SCREEN_RDPGFX` (14 novembre 2026)

- **Interrupteur** : `SCREEN_RDPGFX`, **éteint par défaut**, lu par `switchFromEnv` comme les autres. Allumé, le codec RDP annonce `drdynvc` et le pipeline graphique, et ouvre son canal à côté du contrôle d'affichage.
- **Raccord** : les messages du canal sont lus par le goroutine qui lit l'écran. Ce lecteur tourne désormais à part (`rdpGraphics`), et les mises à jour bitmap comme les trames du pipeline arrivent au lecteur du proxy dans l'ordre où elles sont faites. Une trame terminée devient une mise à jour bitmap ordinaire : un rectangle RGBA de la zone changée, sur un bureau de la taille de la sortie (`FrameUpdate`). Elle est acquittée dès qu'elle est remise. Le relais, les images partielles, le redimensionnement et l'enregistrement ne voient pas de différence. Une cible qui n'ouvre pas le canal continue en mises à jour bitmap.
- **Prouvé sans réseau** : la session Windows Server 2022 de la référence (17 messages) passe par les fonctions de rappel du moteur, puis par le framebuffer du proxy. L'écran qu'il encode est celui du compositeur, au pixel près. Chacune des 9 trames terminées est acquittée, et les capacités sont annoncées à l'ouverture.
- **Contre FreeRDP 3** (`TestRDPInterop_ScreenThroughTheGraphicsPipeline`) : le codec complet, tel que le proxy le lance. Les 240 trames du pipeline donnent 4 images montrées, et les touches tapées dans xterm changent l'écran.
- **Contre les cinq Windows** : `TestRDPWindows_ScreenThroughTheGraphicsPipeline` fait la même chose dans Notepad, pipeline allumé puis éteint, et compare les octets reçus de la cible. Les écrans vont dans l'artefact (`graphics-on-*.png`, `graphics-off-*.png`). Le chiffre est dans la CI de la PR.
- **Reste avant d'allumer `SCREEN_RDPGFX` par défaut** : la vérification dans un vrai navigateur contre les cinq Windows, l'enregistrement relu, et la décision du propriétaire, comme pour ADR-0095 et ADR-0096.

## Ce qui demande ton go

- l'option A et son ordre ;
- l'interrupteur, éteint par défaut le temps des incréments, comme pour ADR-0095 et ADR-0096.

## Conséquences

- (+) 32 bpp par défaut ; un chemin graphique durable.
- (−) Le plus gros parseur exposé à la cible (ClearCodec surtout) : bornes, fuzzing et mutations sur chaque sous-codec.
- (−) Si Windows impose un codec avec perte pour une raison donnée, cette session reste sur l'ancien chemin, ou est refusée.

## Alternatives envisagées

- **B, codecs avec perte** : écartée (ADR-0070), et pour AVC une dépendance de décodeur.
- **Le cache de glyphes de l'ancien chemin** : déjà écarté (ADR-0089) ; RDPGFX ne le demande pas.
