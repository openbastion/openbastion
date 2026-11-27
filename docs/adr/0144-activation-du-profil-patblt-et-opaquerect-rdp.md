# ADR-0144 — Activation du profil PatBlt et OpaqueRect RDP

**Statut** `Accepté` · 27 novembre 2026

## Contexte

OpenBastion décode déjà un sous-ensemble strict de `PatBlt` et `OpaqueRect` et sait rendre ces opérations dans le framebuffer. `PatBlt` prend en charge les ROP explicitement testés, les brosses unies et les brosses mises en cache couvertes par l'ADR-0143. `OpaqueRect` produit un rectangle opaque RGB. Les deux ordres partagent l'index de négociation `TS_NEG_PATBLT_INDEX` (index 1) dans `TS_ORDER_CAPABILITYSET`.

Malgré ces implémentations et leurs tests, cet index n'est pas annoncé et le garde de session refuse donc ces ordres reçus d'un serveur. Il serait incorrect d'annoncer les autres ordres de formes ou `MultiOpaqueRect` par simple proximité : leurs index et profils restent indépendants.

## Décision

1. Annoncer `TS_NEG_PATBLT_INDEX` (index 1) uniquement dans le profil 32 bpp, où les deux ordres ont un parseur borné, un rendu framebuffer et des tests dédiés.
2. Activer le garde de session `patBltOpaqueRectEnabled` uniquement après un échange Confirm Active réussi et uniquement si la profondeur négociée est 32 bpp.
3. Considérer l'index 1 comme la capacité commune de `PatBlt` et `OpaqueRect`; ne pas inventer de négociation indépendante pour ces deux ordres.
4. Ne pas annoncer `MultiOpaqueRect` (index 18), les formes avec brosse, les autres profondeurs, les styles non implémentés ni les ROP non testés.
5. Conserver le refus fail-closed des ordres non annoncés, des champs hors profil, des dimensions invalides et des données résiduelles.
6. Ajouter des tests qui vérifient la capacité émise et l'état d'activation de session pour 15, 16 et 32 bpp. Les tests Windows Server 2019/2022 restent exécutés exclusivement en CI.

## Conséquences

- (+) Les serveurs peuvent utiliser `PatBlt` et `OpaqueRect` sur le profil 32 bpp déjà décodé et rendu.
- (+) L'annonce de capacité correspond au profil réellement pris en charge.
- (+) Aucun élargissement implicite des ordres `Multi*` ou des formes avec brosse.
- (−) Les profils 15/16 bpp restent limités aux ordres déjà annoncés.
- (−) Les formes avec brosse et `MultiOpaqueRect` nécessitent des décisions et des preuves séparées.

## Références

- [MS-RDPEGDI — Primary Drawing Orders](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/)
- [MS-RDPBCGR — Order Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
