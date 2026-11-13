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
- **Ce que cela annonce** : aucune capacité n'éteint RemoteFX ni RemoteFX progressif (MS-RDPEGFX 2.2.3). L'option A tient seulement si la cible choisit d'elle-même un codec sans perte, et FreeRDP ne le fait pas. Le choix de Windows est mesuré par `TestRDPWindows_GraphicsPipeline` contre les cinq cibles. Si Windows choisit aussi un codec avec perte, la question « ancien chemin ou refus » d'ADR-0101 se posera dès l'incrément 3.

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
