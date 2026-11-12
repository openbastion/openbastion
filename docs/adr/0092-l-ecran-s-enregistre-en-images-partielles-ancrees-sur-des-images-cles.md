# ADR-0092 — L'écran s'enregistre en images partielles, ancrées sur des images clés

**Statut** `Accepté` · 11 novembre 2026 · demandé par le propriétaire du projet le 11 novembre 2026 : « go pour l'ADR », après la publication des premiers chiffres du lot A d'ADR-0090 ; accepté le même jour : « Go pour l'option A ». La décision change le flux écran (ADR-0071 §4 et §6) et le format des segments du Video Recorder (ADR-0070). L'option A est acceptée, avec ses bornes (64 rectangles, moitié de l'écran, une image clé toutes les 10 s ou 300 images) et l'interrupteur éteint jusqu'à la nouvelle mesure.

## Contexte

Aujourd'hui, chaque changement de l'écran, même d'un caractère ou d'une position du pointeur, devient un **PNG complet** du bureau. C'est ce PNG que le Video Recorder acquitte (ADR-0070), puis que l'opérateur voit et que l'auditeur rejoue (ADR-0071 §4).

Les mesures du lot A d'ADR-0090 (11 novembre 2026, cinq cibles Windows en CI et FreeRDP) montrent que ce format est **le** coût :

| | Cible → proxy | Enregistré |
|---|---|---|
| Repos | 0 | 0 |
| Frappe dans le Bloc-notes | 11 à 80 Kio/s | 420 à 2 370 Kio/s |
| Défilement | 100 à 410 Kio/s | 230 à 1 440 Kio/s |
| Seul le pointeur bouge | 0 | 500 à 2 650 Kio/s |

- Une image fait 30 à 37 Ko sur un fond noir, et 185 à 202 Ko sur le fond bleu de Windows. Le fond d'écran, qui ne change pas, est donc payé à chaque image.
- L'encodage PNG coûte 9 à 27 ms par image, jusqu'à 39 ms. Une session active occupe environ un tiers de cœur.
- Le volume enregistré vaut 6 à 60 fois ce que la cible envoie. Les ordres graphiques et les caches (lots B et C d'ADR-0090) réduiraient le second chiffre, pas le premier.

Les deux cibles savent déjà ce qui a changé. RDP envoie des rectangles (Bitmap Update), et VNC des rectangles d'encodage. Le proxy connaît en plus la zone du pointeur qu'il dessine (ADR-0091).

**Ce qui ne change pas :**
- **ADR-0008** et **ADR-0070** : enregistrer ou refuser. Rien n'est montré avant d'être acquitté.
- **ADR-0071 §4** : ce que l'opérateur reçoit est, octet pour octet, ce que le Video Recorder a acquitté.
- **ADR-0070 §6** : chaque segment est chiffré, et ses données associées lient la session, les séquences et la version du format.
- **ADR-0090, alternative écartée** : pas de codec vidéo avec perte. Le rejeu reste l'image d'origine, au pixel près.

## Options

**A. Images partielles ancrées sur des images clés (recommandée).**
- Une **image clé** est le PNG complet d'aujourd'hui. Une **image partielle** porte seulement les rectangles qui ont changé depuis l'image précédente, chacun en PNG, avec sa position.
- L'opérateur et l'auditeur composent les rectangles sur l'image précédente.
- Une image clé revient régulièrement, ainsi qu'à chaque changement de taille et à chaque reprise. Le rejeu peut donc commencer à n'importe quelle image clé.

**B. Garder les images entières, mais les alléger.** Compression PNG plus rapide, palette, cadence plus lente.
- Le fond d'écran resterait payé à chaque image.
- Une cadence plus lente ferait perdre des états intermédiaires à l'auditeur.

**C. Un codec vidéo** (VP8, H.264, AV1) : déjà écarté par ADR-0090.
- Le rejeu ne serait plus l'image d'origine.
- Le décodeur serait une dépendance lourde et une surface d'attaque.

**D. Ne rien changer.** L'enregistrement continue de coûter 0,4 à 2,6 Mio/s par session active, et un tiers de cœur pour l'encodage.

## Décision : A

1. **Deux sortes d'images dans le flux écran.**
   - `FRAME` reste l'image clé.
   - Un nouveau type, `FRAME_DELTA`, porte une liste de rectangles : position, largeur, hauteur, PNG.
   - La séquence est commune aux deux sortes et reste strictement croissante. Une image partielle s'applique à l'image de séquence précédente, et à elle seule.
2. **Bornes.**
   - Au plus 64 rectangles par image partielle.
   - Chaque rectangle est non vide et contenu dans l'image.
   - Une image partielle fait au plus 4 Mio, comme une image clé.
   - Si l'union des rectangles couvre plus de la moitié de l'écran, le proxy envoie une image clé à la place.
   - Tout écart (rectangle hors image, PNG invalide, image partielle sans image clé avant elle) ferme la session, côté proxy comme côté navigateur.
3. **Images clés obligatoires.**
   - La première image d'une session est une image clé.
   - Une image clé suit aussi chaque changement de taille, chaque réactivation RDP et chaque `DesktopSize` VNC.
   - Une image clé revient au moins toutes les 10 secondes ou toutes les 300 images, au premier atteint. Ces valeurs sont réglables et bornées.
   - L'auditeur peut ainsi se placer n'importe où sans rejouer toute la session.
4. **Le pointeur** (ADR-0091) devient deux petits rectangles : la zone qu'il quitte, repeinte depuis le tampon de la cible, et la zone où il arrive, dessinée.
5. **Contrat du Video Recorder.** Une image partielle voyage dans `VideoFrameData` avec `codec = "png-delta-v1"`. Ce champ existe déjà, donc le schéma Protobuf ne change pas.
   - Le format des segments chiffrés passe en version 2, liée aux données associées (ADR-0070 §6). Un segment de version 1 reste lisible.
   - Le Recorder valide les bornes du §2 avant d'acquitter, comme il valide aujourd'hui une image.
6. **Égalité de l'image montrée et de l'image enregistrée** (ADR-0071 §4). L'opérateur reçoit exactement les octets acquittés : images clés et images partielles.
   - La composition est déterministe : chaque rectangle remplace des pixels, sans mélange.
   - L'image reconstruite par l'auditeur à une séquence donnée est donc, au pixel près, celle que l'opérateur a vue. Un test le prouve sur des sessions réelles, en comparant la composition à une image clé émise à la même séquence.
7. **Admin UI.** Le lecteur en direct et le lecteur de rejeu composent les images partielles sur un canvas. Le rejeu se positionne sur l'image clé la plus proche, puis applique les images partielles.
8. **Interrupteur.** `SCREEN_PARTIAL_FRAMES`, éteint tant que les incréments ne sont pas tous livrés et mesurés, puis allumé par décision. Éteint, le comportement est celui d'aujourd'hui : uniquement des images clés.

## Conséquences

- (+) Le volume enregistré devrait suivre ce qui change à l'écran, et non la taille du bureau. **Estimation, non mesurée** : quelques kilo-octets par frappe ou par déplacement du pointeur, contre 30 à 202 Ko aujourd'hui. Une fois le format livré, le banc du lot A le mesure à nouveau, scène par scène.
- (+) L'encodage porte sur de petits rectangles : le coût CPU par session devrait baisser d'autant. Il sera mesuré.
- (+) Rien ne change pour l'invariant « enregistrer ou refuser » : chaque octet montré a été acquitté.
- (−) Deux contrats changent, flux écran et segments du Recorder (format 2), et l'Admin UI doit composer. Un client tiers du flux écran doit suivre.
- (−) Une image ne se lit plus seule. Une image partielle corrompue ou absente rend fausses les images suivantes jusqu'à la prochaine image clé. Le chiffrement authentifié des segments (ADR-0070 §6) empêche la corruption silencieuse, et l'image clé périodique borne l'étendue d'une perte.
- (−) Le rejeu demande de remonter à l'image clé précédente : jusqu'à 10 secondes d'images partielles à appliquer avant d'afficher.
- (−) Un nouveau décodeur exposé, côté navigateur et côté Recorder. Il aura des bornes, des tests d'attaque et un fuzzer.

## Mise en œuvre envisagée, par incréments

1. **Fait** : le format. `FRAME_DELTA` dans `pkg/screenstream` (encodage, décodage, bornes, fuzzer), et la composition de référence en Go (`Composer`). Un écran recomposé est prouvé égal, octet pour octet, à l'image clé du même moment ; 17 mutations tuées, plus une équivalente.
2. **Fait** : RDP. Plutôt que de suivre chaque opération, `screenstream.FrameEncoder` compare l'image à montrer à la précédente, par tuiles de 32 pixels, et envoie les tuiles changées regroupées en rectangles. La différence couvre donc tout (bitmaps, ordres, pointeur, §4) ; ce mécanisme servira aussi à VNC. Une image identique ne fait pas d'image, et une réactivation force une image clé. Le moteur l'active par `RDPCodec.PartialFrames`, que le runtime n'offre pas encore : le Video Recorder ne stocke pas encore ces images (incrément 3).
3. **Fait** : le Video Recorder et le relais. Une image partielle voyage dans `frame_data` sous la forme de son message `FRAME_DELTA`, avec le codec `png-delta-v1`. Le Recorder la valide avant d'acquitter : message, séquence, horodatage, PNG de la taille de chaque rectangle, et image clé de même taille avant elle, d'un segment à l'autre. Un segment qui en contient est scellé au format 2, les autres restent au format 1, et un segment ne s'ouvre que sous le format que ses images demandent. Le relais n'accepte une image partielle qu'après une image clé et à sa taille, et donne au Recorder sa propre copie des rectangles. Prouvé de bout en bout contre FreeRDP : chaque image montrée, clé ou partielle, est relue octet pour octet, et l'écran que l'auditeur recompose est celui de l'opérateur.

   **Complément (12 novembre 2026) : l'opérateur en retard.** Pour ne jamais bloquer ni l'enregistrement ni l'entrée, le relais remplaçait l'image en attente par la plus récente (ADR-0071 §11). Une image partielle ne peut pas être sautée (§1). L'affichage la met donc en file, au plus 32 images partielles ou 4 Mio. Au-delà, il les abandonne et demande une image clé au codec (`proxycore.KeyFrameRequester`), qui la produit même sur un écran immobile, puis il n'envoie rien d'autre jusqu'à elle. Une image clé remplace toujours ce qui attend. L'opérateur saute d'un écran entier au suivant ; l'enregistrement, lui, garde tout.
4. **Fait** : l'Admin UI.
   - **Décodage** : `FRAME_DELTA`, aussi strict que `pkg/screenstream`.
   - **En direct** : les images sont peintes strictement dans l'ordre. Ce qui précède la dernière image clé reçue est sauté, puisqu'elle remplace tout l'écran. Une image partielle doit suivre l'image reçue avant elle et avoir sa taille, et chaque rectangle doit être un PNG de sa taille ; sinon la session se ferme.
   - **En rejeu** : l'image suivante, si elle est partielle, est posée sur celle du canvas ; toute autre image est recomposée depuis l'image clé qui la précède.
   - **Réglage** : `SCREEN_PARTIAL_FRAMES` est offert par le runtime, éteint par défaut (§8). Le contrat REST admet le codec `png-delta-v1`.
5. **Fait** : VNC. Le client VNC passe par le même `FrameEncoder` que RDP. Il fait une image clé à la demande du relais, même sur un écran immobile et même sans forme de curseur. Une nouvelle taille du bureau donne une image clé. Éprouvé contre le TigerVNC du bac à sable Base44, en images entières et en images partielles. Constat : xterm cache le pointeur pendant la frappe, et TigerVNC ne renvoie sa forme qu'après un mouvement suivant. En images partielles, le premier mouvement ne fait donc pas d'image, à juste titre.
6. **Mesuré** (12 novembre 2026). **Décision du propriétaire, le même jour** : « Après un vrai navigateur ». `SCREEN_PARTIAL_FRAMES` reste éteint par défaut. Il sera allumé dès qu'une session en direct et un rejeu auront été vérifiés dans un vrai navigateur, sur le bac à sable Base44 avec `SCREEN_PARTIAL_FRAMES=true`. **Allumé par défaut le 12 novembre 2026**, après la vérification du propriétaire dans un vrai navigateur, sur le bac à sable Base44 : session en direct et rejeu (« Vérifié dans le navigateur »). `SCREEN_PARTIAL_FRAMES=false` rend les images entières.

## Résultats (12 novembre 2026)

Mêmes scènes et même banc que le lot A d'ADR-0090, dans les deux modes et dans la même session de test. Pointeur dessiné, cadence de 50 ms. « Enregistré » est le débit des images que le Video Recorder stocke.

| Cible | Scène | Images entières | Images partielles |
|---|---|---|---|
| Windows Server 2019 et 2022, 5 cibles (CI, PR #134) | Frappe, enregistré | 450 à 2 700 Kio/s | **8 à 118 Kio/s** |
| | Seul le pointeur bouge, enregistré | 540 à 2 970 Kio/s | **5 à 10 Kio/s** |
| | Encodage d'une image | 14 à 48 ms | **0,1 à 0,5 ms** |
| | Latence touche → image, médiane | 52 à 114 ms | 39 à 53 ms |
| FreeRDP 3 (local) | Frappe, enregistré | 297 Kio/s | **4,1 Kio/s** |
| | Encodage d'une image | 12 ms | **0,2 ms** |
| TigerVNC, 800 × 600 (bac à sable Base44) | Frappe, enregistré | 155 Kio/s | **5,5 Kio/s** |
| | Pointeur, enregistré | 221 Kio/s | **15,4 Kio/s** (dont une image clé périodique) |
| | Encodage d'une image | 3,8 ms | **0,2 à 0,7 ms** |
| | Latence touche → image, médiane | 13,8 ms | 10,2 ms |

- **Gain** : le volume enregistré baisse de 20 à 300 fois en frappe et quand le pointeur bouge, et le coût d'encodage d'une image de 20 à 100 fois. La latence ne se dégrade nulle part.
- **Limites des chiffres** :
  - le défilement n'est pas comparable d'un mode à l'autre, la cible n'ayant pas envoyé autant dans les deux passages ;
  - la scène pointeur de FreeRDP ne mesure rien, xterm y cachant le pointeur ;
  - le pic du tas est celui du processus de test ;
  - la latence se mesure sur le même hôte que la cible.
- **Non éprouvé** : l'Admin UI dans un vrai navigateur (direct et rejeu). La composition y repose sur `clearRect` puis `drawImage` ; elle n'est vérifiée qu'en Go (`Composer`, et la composition indépendante du test Base44) et en tests de composant.

## Alternatives envisagées

- **B, alléger les images entières** : écartée comme levier principal. Elle réduirait le coût d'un facteur borné sans changer sa nature : le bureau entier, à chaque changement. Une compression PNG plus rapide reste possible en complément, mesurée.
- **C, un codec vidéo** : écartée, comme dans ADR-0090. Rejeu avec perte, dépendance lourde.
- **D, rien** : écartée. Les chiffres du lot A placent le coût de l'enregistrement au premier rang des limites de capacité.
- **Des images partielles sans images clés** : écartée. Le rejeu devrait repartir du début de la session, et une perte s'étendrait jusqu'à la fin.
- **Des rectangles bruts (RGBA) plutôt qu'en PNG** : écartée. Ils seraient plus simples à composer, mais plus gros que les PNG sur du texte et des fonds unis.
