# ADR-0091 — Le pointeur est dessiné dans l'image, celle que l'opérateur voit et que l'auditeur rejoue

**Statut** `Accepté` · 11 novembre 2026 · go du propriétaire du projet pour l'écrire le 11 novembre 2026 : « Go pour l'ADR du pointeur » ; accepté le même jour : « Go pour l'option A ». L'option A, l'interrupteur allumé par défaut et `cursor: none` dans l'Admin UI sont acceptés.

## Contexte

ADR-0071 (incrément 3) range « pointeur » parmi le contenu de l'écran RDP ; ADR-0090 (lot E) renvoie sa forme à un ADR. Aujourd'hui :

- **RDP** : les mises à jour de pointeur sont reconnues puis **ignorées** (`pkg/rdp/mcs_bitmap.go`). Ce sont les codes Fast-Path 5 (caché), 6 (défaut), 8 (position), 9 (couleur), 10 (en cache), 11 (nouveau), et le PDU slow-path 0x1b.
- **VNC** : le client demande l'encodage `Cursor` (-239), puis **jette** ses pixels et son masque (`pkg/vnc/client.go`).
- **Admin UI** : le canvas affiche la flèche du navigateur (`cursor: default`), pas la forme de la cible : ni le curseur texte au-dessus d'un champ, ni le sablier.
- **Enregistrement** : les images acquittées ne contiennent **aucun pointeur**. Un auditeur qui rejoue une session voit l'effet des clics, pas où ils ont eu lieu, ni ce que l'opérateur a survolé.

**Ce qui ne change pas.** ADR-0071 §4 : l'image affichée est, à l'octet près, l'image acquittée par le Video Recorder ; ADR-0070 : enregistrer ou refuser. Un pointeur montré à l'opérateur mais absent de l'enregistrement, ou l'inverse, romprait cette égalité.

## Options

**A. Le pointeur dessiné dans l'image (recommandée).** Le proxy compose, au moment d'encoder chaque image (`RDPFramebuffer.Frame`, et son équivalent VNC), le pointeur à sa position par-dessus le bureau. Il ne l'écrit pas dans le framebuffer.
- La forme est celle que la cible annonce : RDP couleur, nouveau, en cache, ou caché ; VNC `Cursor`. Défaut : une flèche intégrée au proxy.
- La position est la dernière que l'opérateur a envoyée (son entrée), ou que la cible impose (Fast-Path 8, et la position portée par une mise à jour VNC).
- Le flux écran ne change pas : l'image porte le pointeur, et l'enregistrement aussi.

**B. Le pointeur à part, dans le flux et dans l'enregistrement.**
- Un nouveau message `CURSOR` dans `openbastion.screen.v1` : forme en PNG, point chaud, position.
- Un nouveau type d'élément dans le segment vidéo, et un lecteur qui le recompose.
- Moins d'images, mais deux contrats changent, et le rejeu n'est plus « l'image acquittée telle quelle ».

**C. Rien.** Le navigateur garde sa flèche, l'enregistrement reste sans pointeur. C'est la limite actuelle, assumée et documentée.

## Décision : A

1. **Le pointeur fait partie de l'image** montrée et enregistrée. Il est composé à l'encodage seulement : le framebuffer ne le garde pas, et les ordres et bitmaps suivants n'en héritent pas.
2. **Forme** : celle de la cible, décodée et bornée.
   - RDP : `TS_COLORPOINTERATTRIBUTE` et `TS_POINTERATTRIBUTE` en 24 et 32 bpp, masques XOR et AND, au plus 32 × 32 pixels, la borne de MS-RDPBCGR 2.2.9.1.1.4.4 quand le client n'annonce pas de grands pointeurs (corrigé le 11 novembre 2026, le texte d'origine disait 96 × 96). Un cache de pointeurs est annoncé avec une taille bornée, 25 entrées comme FreeRDP. Une référence à une entrée absente ferme la session. Le point chaud est borné comme la forme (< 32), non par elle : FreeRDP en envoie un hors de la forme (corrigé le 11 novembre 2026).
   - VNC : `Cursor`, 32 bpp, bitmask 1 bit, mêmes bornes.
   - Une forme invalide ferme la session, comme tout PDU hors profil.
3. **Position** : la dernière connue, venant de l'opérateur ou de la cible. Elle est bornée par le bureau ; le point chaud est respecté.
4. **Cadence** : un déplacement du pointeur change l'image et part à la cadence `SCREEN_FRAME_INTERVAL_MS` (ADR-0071 §8). Aucun flux d'images par pixel parcouru.
5. **Admin UI** : le canvas cache la flèche du navigateur (`cursor: none`) au-dessus de l'écran, pour que l'opérateur ne voie pas deux pointeurs. Le pointeur qu'il voit est celui de l'image, avec la latence d'un aller-retour par le proxy et l'acquittement. **Amendé le 11 novembre 2026** : l'Admin UI ne cache sa flèche que si le `HELLO` le lui dit. Le bit 0 de l'octet qui suit le protocole, jusque-là réservé à zéro, signifie « le pointeur est dans les images ». Avec le réglage éteint, ou en VNC tant que l'incrément 3 n'est pas fait, la flèche du navigateur reste. Le propriétaire a choisi cette voie (« Drapeau dans HELLO ») plutôt qu'un réticule local ou `cursor: none` pour tout RDP.
6. **Interrupteur** : `SCREEN_DRAW_POINTER`, allumé par défaut. Éteint, c'est le comportement d'aujourd'hui, flèche du navigateur et pointeur absent de l'enregistrement, pour l'installation qui préfère la réactivité au témoignage.

## Conséquences

- (+) L'auditeur voit où l'opérateur a pointé et cliqué, et la forme que la cible montrait. Le rejeu reste l'image acquittée, octet pour octet.
- (+) Ni l'API de rejeu ni le Video Recorder ne changent. Le flux écran gagne un drapeau dans `HELLO` (§5, amendé) : un `HELLO` sans ce drapeau reste celui d'avant, mais un décodeur antérieur refuse celui qui le porte. L'Admin UI et le proxy sont livrés ensemble.
- (−) Un nouveau parseur exposé à la cible : formes RDP et VNC, cache RDP. Il aura des bornes, des tests d'attaque et un fuzzer, comme les autres.
- (−) Plus d'images : chaque déplacement en produit une, à la cadence. Le volume enregistré augmente d'autant pendant que la souris bouge. Non mesuré ; à mesurer avec le lot A d'ADR-0090.
- (−) L'opérateur voit son pointeur avec la latence du proxy : encodage, acquittement, réseau. Sur une liaison lente, il sera en retard sur sa main. L'option éteinte rend la flèche locale.
- (−) Un enregistrement fait avant ce changement n'a pas de pointeur : le rejeu le dit par son absence, sans marqueur.

## Alternatives envisagées

- **B, le pointeur à part** : écartée. Deux contrats changent (flux écran et segments vidéo), et le rejeu devient une recomposition, qui n'est plus l'image acquittée (ADR-0071 §4). Elle ne vaudrait que si le volume d'images de A, une fois mesuré, se révélait insupportable.
- **C, rien** : écartée comme cible, gardée comme option éteinte. Un PAM qui enregistre l'écran sans le pointeur prive l'auditeur de la moitié du geste.
- **Dessiner le pointeur dans le framebuffer lui-même** : écartée. Les mises à jour suivantes de la cible recouvriraient des pixels déjà modifiés, et le framebuffer cesserait d'être l'écran de la cible.

## Incréments

1. **Fait** : parseurs Fast-Path et slow-path, formes 24 et 32 bpp, cache de 25 formes, dessin sur une copie du bureau, flèche par défaut (`pkg/rdp/pointer.go`). Le tout est prouvé par des tests, un fuzzer et 24 mutations tuées. Rien n'est branché pour l'instant.
2. **Fait** : branchement RDP. La capacité est annoncée à 25 quand le pointeur est dessiné, `ReadBitmapUpdate` rend les mises à jour de pointeur, et le moteur suit celles de la cible et la position de l'opérateur. Il dessine le pointeur dans chaque image (`FrameWithPointer`) au rythme de la cadence. Une réactivation vide le cache. `SCREEN_DRAW_POINTER` est allumé par défaut. Éprouvé contre FreeRDP (le serveur de test n'envoie aucun pointeur : flèche du proxy), et contre Windows en CI : Windows Server 2022 envoie 9 à 12 mises à jour à l'ouverture, toutes acceptées. **Élargi par la mesure** : Windows Server 2019 envoie des formes monochromes (1 bpp, 32 × 32). Elles sont décodées depuis le 11 novembre 2026, masques lus de haut en bas comme FreeRDP le fait contre Windows. Le §2, qui ne retenait que 24 et 32 bpp, est élargi en ce sens ; c'est un choix renversable.
3. VNC : l'encodage `Cursor` est suivi et dessiné de la même façon.
4. **Fait** : drapeau `HELLO` (`screenstream.HelloPointerDrawn`, `proxycore.PointerDrawer`), posé par la session RDP qui dessine le pointeur. L'Admin UI le lit et met alors `cursor: none`. Prouvé de bout en bout sur processus réels (RDP : drapeau à 1 ; VNC : à 0).
