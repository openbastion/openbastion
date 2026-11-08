# ADR-0083 — Le client RDP décode 15 et 16 bpp, pour les cibles Windows laissées par défaut

**Statut** `Accepté, mise en œuvre en cours` · 2026-11-08 · go du propriétaire du projet le 2026-11-08 : « Option 1, décode le 15/16 bpp »

**Contexte** — ADR-0071 valide le client RDP contre un vrai Windows Server 2022 (dockur/windows en CI, `.github/workflows/windows-rdp.yml`). Les passages #29 et #30 l'ont mesuré :

- laissé par défaut, ce Windows a `RDP-Tcp\ColorDepth` à 3 (16 bpp) et `fInheritColorDepth` à 0 ;
- à un client qui n'annonce pas le pipeline graphique (MS-RDPEGFX), il propose alors une session en 16 bpp (`preferredBitsPerPixel` `0x0010` dans le Demand Active) ;
- le client ne décodait que 32 bpp et refusait donc la session, comme voulu (fail-closed) ;
- avec 24 et 32 bpp seuls dans `supportedColorDepths`, Windows n'avait aucune profondeur commune et coupait la connexion dès le Connect-Initial (passages #24 à #26).

Il faut autoriser 32 bpp sur la cible (stratégie « Limit maximum color depth ») pour que l'échange de capacités passe (#30). Mais une cible réelle laissée par défaut ne le fait pas : sans cette décision, OpenBastion ne s'y connecte pas. mstsc et FreeRDP y échappent en annonçant le pipeline graphique.

Le passage #31 montre un second refus, au Confirm Active : Set Error Info `0x000010EA` (`ERRINFO_BADCAPABILITIES`). Or MS-RDPBCGR 2.2.7.1.2 dit que `bitmapCompressionFlag` « MUST be set to TRUE », et le client l'envoyait à 0.

Invariants touchés : aucun. Le décodage est côté proxy, sur des données de la cible, qui ne sont pas fiables. Il hérite des bornes d'ADR-0071 (taille des PDU, surface du bureau, rectangles) et de son fail-closed.

**Décision**

1. **Profondeur de session.** Le client annonce 15, 16, 24 et 32 bpp et demande 32 bpp (`WANT_32BPP`, `highColorDepth` 24). Il accepte du Demand Active une session en **15, 16 ou 32 bpp**. Il refuse 8 et 24 bpp, et toute autre valeur : ces décodeurs ne sont pas écrits. Le Confirm Active reprend la profondeur choisie par le serveur.
2. **Compression annoncée.** `bitmapCompressionFlag` vaut TRUE, comme l'exige MS-RDPBCGR. À 32 bpp, un bitmap compressé est du RDP 6.0 planar (déjà décodé). À 15 et 16 bpp, c'est de l'Interleaved RLE (point 4).
3. **Bitmaps non compressés à 15 et 16 bpp.** RGB555 et RGB565 petit-boutiste, lignes de bas en haut, chaque ligne complétée à un multiple de 4 octets. La taille attendue se calcule à partir de la largeur et de la hauteur annoncées, et toute autre longueur est refusée.
4. **Interleaved RLE à 15 et 16 bpp** (MS-RDPBCGR 2.2.9.1.1.3.1.2.4 et 3.1.9). Implémentation originale, d'après la spécification seule (ADR-0081). La sortie est allouée une fois, à la taille de la largeur et de la hauteur annoncées, elles-mêmes bornées. Chaque code est vérifié avant écriture : longueur de course, octets d'entrée disponibles, débordement de la sortie. Il en va de même pour chaque code de premier plan, d'arrière-plan, de mélange, de remplissage, de couleur, d'image FG/BG, pour les codes spéciaux et pour les longueurs MEGA_MEGA. Un flux qui ne remplit pas exactement le bitmap, ou qui le dépasse, est refusé. L'en-tête `TS_CD_HEADER` n'est pas attendu, puisque le client annonce `NO_BITMAP_COMPRESSION_HDR`. Un en-tête présent doit être cohérent, comme à 32 bpp.
5. **Rectangle de destination.** Chaque `TS_BITMAP_DATA` porte la profondeur de la session, sinon il est refusé. La largeur du bitmap peut dépasser celle de la destination, mais seulement du complément à 4 pixels ; la hauteur doit être égale. Un bitmap plus grand ferait décoder ce qui n'est jamais montré, et il est refusé. Seul le rectangle de destination est copié, et il doit tenir dans le bureau. Une mise à jour porte au plus 4096 rectangles : Windows envoie l'écran entier d'un coup, en tuiles de 64 × 64, soit 260 pour 1280 × 800 au passage #36. Sa taille la borne encore, à 19 octets au moins par rectangle. Les ordres gardent leur borne de 64.
6. **Conversion.** Le framebuffer RGBA reçoit chaque pixel étendu par réplication de bits : 5 bits vers 8, et 6 bits vers 8 pour le vert en 565. L'enregistrement et le flux écran ne changent pas : ils restent en PNG RGBA.
7. **Ce qui reste refusé.** 8 et 24 bpp ; le pipeline graphique ; les ordres graphiques, jamais activés à l'exécution (s'ils l'étaient un jour, leurs couleurs devraient suivre la profondeur de la session) ; un pointeur dans une autre profondeur que celle qu'il annonce lui-même.
8. **Cible de test.** La cible Windows du CI revient à ses réglages par défaut (16 bpp), le cas réel. FreeRDP 3, dans le même workflow, garde le chemin 32 bpp.

**Conséquences**

- (+) Une cible Windows laissée par défaut est servie sans réglage de l'opérateur, dans la limite du 16 bpp. Le chemin 32 bpp ne change pas.
- (+) Mesuré : `bitmapCompressionFlag` à TRUE fait accepter le Confirm Active par Windows (passage #32 : refusé à FALSE, accepté à TRUE, seul changement). Le décodeur (`pkg/rdp/bitmap_interleaved.go`) a 24 vecteurs construits d'après la spécification, un par ordre RLE et par cas de longueur étendue, de première ligne et de pixel inséré entre deux fonds ; 18 tests d'attaque (course plus longue que le bitmap, entrée tronquée à chaque champ, ordre spécial ou blanc au-delà du bitmap, flux trop court, codes non définis) ; la conversion RGB555/RGB565 ; le non compressé de bas en haut aux lignes complétées ; l'en-tête `TS_CD_HEADER` ; la profondeur discordante, le rognage et le rectangle trop grand ; les ordres refusés hors 32 bpp. 17 mutations du décodeur et de l'analyse sont tuées (pixel inséré, borne avant écriture, ordre des bits, longueurs étendues, ×8 des images FG/BG, remplissage incomplet, paires du tramé, fin de première ligne, blanc à 15 bpp, lignes complétées, réplication du vert, sens des lignes, largeur impaire, profondeur, rectangle, en-tête). Le fuzzer `FuzzDecodeInterleavedRLE16` a tourné 60 s sans échec (1,2 million d'exécutions). Les tests qui supposaient 15 et 16 bpp refusés, et la compression à FALSE, ont été changés avec la décision.
- (+) Reste à mesurer : la session réelle contre Windows par défaut en CI, l'écran qui change après saisie, et les captures jugées à l'œil.
- (−) 16 bpp, c'est 65 536 couleurs : l'écran et l'enregistrement d'une telle cible perdent en fidélité, et un dégradé peut se voir en bandes. C'est le choix de la cible, que l'opérateur peut lever en autorisant 32 bpp.
- (−) Une cible plafonnée à 24 bpp ou 8 bpp reste refusée.
- (−) Le décodeur RLE est une nouvelle surface d'analyse de données non fiables. Les bornes et le fuzzing la contiennent, ils ne la suppriment pas.
- (−) Aucun vecteur de référence publié par Microsoft n'est repris tel quel. Hors des vecteurs construits ici, la justesse se prouve contre Windows.

**Alternatives envisagées**

- **Pipeline graphique (MS-RDPEGFX)** : c'est ce que font mstsc et FreeRDP, et il donne du 32 bpp quel que soit le plafond hérité. Écarté pour cet incrément : il demande les canaux virtuels dynamiques et plusieurs codecs (planar progressif, ClearCodec, RemoteFX, AVC), un chantier bien plus large et une surface d'analyse plus grande. Il reste ouvert pour plus tard.
- **Exiger 32 bpp de la cible et le documenter** : rien à coder, mais une contrainte de déploiement que les cibles par défaut ne remplissent pas. L'échec serait silencieux pour l'opérateur jusqu'au premier essai.
- **Décoder aussi 24 et 8 bpp** : aucune cible mesurée ne les propose. On attend un cas réel plutôt que d'ajouter du code non éprouvé.
