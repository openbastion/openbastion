# ADR-0146 — Ordres PolygonCB et EllipseCB avec brosse cachee RDP

**Statut** `Proposé` · 27 novembre 2026

## Contexte

Le codec RDP Go sait rendre les ordres `PolygonSC` et `EllipseSC` avec une couleur unie. Le cache de pinceaux de l'ADR-0143 sait déjà conserver des motifs monochromes et couleur, et PatBlt/Mem3Blt consomment les motifs couleur. Les variantes `PolygonCB` (`0x15`) et `EllipseCB` (`0x1a`) permettent d'appliquer une brosse couleur mise en cache aux formes géométriques.

Ces ordres possèdent des index de négociation indépendants : `TS_NEG_POLYGON_CB_INDEX` (21) et `TS_NEG_ELLIPSE_CB_INDEX` (26). Ils ne doivent pas être activés implicitement par les index `PolygonSC` (20) ou `EllipseSC` (25). Le décodage doit également respecter les champs compressés, la référence de cache et l'origine du motif.

## Décision proposée

1. Annoncer les index 21 et 26 uniquement dans le profil 32 bpp, après ajout du parseur, du rendu et des tests correspondants. Les garder à zéro en 15/16 bpp.
2. Activer `polygonCBEnabled` et `ellipseCBEnabled` uniquement après un échange Confirm Active réussi et uniquement pour une session 32 bpp.
3. Commencer par un profil strict `TS_CACHED_BRUSH` couleur `BMF_24BPP` (`BrushStyle=0x85`) et un index `BrushHatch` compris entre 0 et 63. Résoudre uniquement une entrée couleur déjà reçue par `TS_CACHE_BRUSH`. Refuser les références absentes, les formats différents et les styles de brosse non mis en cache.
4. Exiger tous les champs utiles dans chaque ordre. `PolygonCB` exige le point de départ, ROP2, `ALTERNATE` FillMode, couleurs génériques, origine, style/index, nombre de deltas et champ `CodedDeltaList` borné. `EllipseCB` exige les quatre coordonnées inclusives, ROP2, FillMode, couleurs, origine et style/index. Le champ `BrushExtra` inline est interdit pour ce profil cache.
5. Limiter la première version aux coordonnées absolues, sans clipping `TS_BOUNDS`, sans delta-coordinates et sans réutilisation de champs omis. Les coordonnées, le nombre de points, la taille du champ delta, les dimensions, le nombre d'opérations et le total de pixels restent bornés par les limites déjà appliquées aux formes SC.
6. Résoudre le motif dans le parseur en un tampon RGBA canonique borné, ancré à `BrushOrgX/BrushOrgY`. Appliquer le ROP2 au moment du rendu framebuffer, sur le contenu courant, dans l'ordre des opérations. Le parseur ne pré-calcule jamais un résultat dépendant du framebuffer.
7. Conserver les opérations transactionnelles : si un ordre du PDU est invalide, aucun cache ni état primaire partiel n'est commis. Toute utilisation d'un ordre CB non négocié termine la session.
8. Ne pas annoncer les variantes monochromes, les brosses inline, les styles hachurés/null, les autres profondeurs, les coordonnées delta, les variantes de clipping ou d'autres ROP tant que leur sémantique et leurs tests pixel-à-pixel ne sont pas livrés.
9. Ajouter des tests de décodage, champs incomplets, cache manquant, index invalide, ordre non négocié, rendu motif/origine et rollback. Les validations Windows Server 2019/2022 restent exécutées exclusivement en CI.

## Conséquences

- (+) Les formes RDP peuvent réutiliser les motifs couleur 8×8 déjà présents dans le cache sans retransmettre leurs pixels.
- (+) Les index PolygonCB et EllipseCB restent indépendants des variantes SC et de tous les autres ordres primaires.
- (+) Les profils et styles non couverts restent refusés ; aucun repli silencieux vers une couleur unie n'est permis.
- (−) La première version ne couvre que les brosses couleur 24 bpp en session 32 bpp et les champs explicitement présents.

## Alternatives envisagées

- **Réutiliser les index SC** : écartée, les capacités CB ont leurs propres index et ne doivent pas être activées par alias.
- **Activer tous les champs compressés dès le départ** : écartée, les caches de champs et les coordonnées delta ajouteraient un état implicite non nécessaire au profil initial.
- **Rendre les motifs dans le parseur** : écartée, le ROP doit être évalué contre le framebuffer courant au moment du rendu.

## Références

- [MS-RDPEGDI — PolygonCB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/24f4e229-1f9f-4633-b9be-66d7579ba36d)
- [MS-RDPEGDI — EllipseCB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/89720383-8394-423a-810a-ba631d66055f)
- [MS-RDPEGDI — Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272)
- [MS-RDPBCGR — Order Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9f409c29-480c-4751-9665-510b8ffff294)
