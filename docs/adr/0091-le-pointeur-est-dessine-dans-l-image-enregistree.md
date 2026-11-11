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
   - RDP : `TS_COLORPOINTERATTRIBUTE` et `TS_POINTERATTRIBUTE` en 24 et 32 bpp, masques XOR et AND, au plus 96 × 96 pixels sans annonce de grands pointeurs. Un cache de pointeurs est annoncé avec une taille bornée, 25 entrées comme FreeRDP. Une référence à une entrée absente ferme la session.
   - VNC : `Cursor`, 32 bpp, bitmask 1 bit, mêmes bornes.
   - Une forme invalide ferme la session, comme tout PDU hors profil.
3. **Position** : la dernière connue, venant de l'opérateur ou de la cible. Elle est bornée par le bureau ; le point chaud est respecté.
4. **Cadence** : un déplacement du pointeur change l'image et part à la cadence `SCREEN_FRAME_INTERVAL_MS` (ADR-0071 §8). Aucun flux d'images par pixel parcouru.
5. **Admin UI** : le canvas cache la flèche du navigateur (`cursor: none`) au-dessus de l'écran, pour que l'opérateur ne voie pas deux pointeurs. Le pointeur qu'il voit est celui de l'image, avec la latence d'un aller-retour par le proxy et l'acquittement.
6. **Interrupteur** : `SCREEN_DRAW_POINTER`, allumé par défaut. Éteint, c'est le comportement d'aujourd'hui, flèche du navigateur et pointeur absent de l'enregistrement, pour l'installation qui préfère la réactivité au témoignage.

## Conséquences

- (+) L'auditeur voit où l'opérateur a pointé et cliqué, et la forme que la cible montrait. Le rejeu reste l'image acquittée, octet pour octet.
- (+) Aucun contrat public ne change : ni le flux écran, ni l'API de rejeu, ni le Video Recorder.
- (−) Un nouveau parseur exposé à la cible : formes RDP et VNC, cache RDP. Il aura des bornes, des tests d'attaque et un fuzzer, comme les autres.
- (−) Plus d'images : chaque déplacement en produit une, à la cadence. Le volume enregistré augmente d'autant pendant que la souris bouge. Non mesuré ; à mesurer avec le lot A d'ADR-0090.
- (−) L'opérateur voit son pointeur avec la latence du proxy : encodage, acquittement, réseau. Sur une liaison lente, il sera en retard sur sa main. L'option éteinte rend la flèche locale.
- (−) Un enregistrement fait avant ce changement n'a pas de pointeur : le rejeu le dit par son absence, sans marqueur.

## Alternatives envisagées

- **B, le pointeur à part** : écartée. Deux contrats changent (flux écran et segments vidéo), et le rejeu devient une recomposition, qui n'est plus l'image acquittée (ADR-0071 §4). Elle ne vaudrait que si le volume d'images de A, une fois mesuré, se révélait insupportable.
- **C, rien** : écartée comme cible, gardée comme option éteinte. Un PAM qui enregistre l'écran sans le pointeur prive l'auditeur de la moitié du geste.
- **Dessiner le pointeur dans le framebuffer lui-même** : écartée. Les mises à jour suivantes de la cible recouvriraient des pixels déjà modifiés, et le framebuffer cesserait d'être l'écran de la cible.
