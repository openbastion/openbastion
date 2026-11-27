# ADR-0145 — Négociation de MultiOpaqueRect RDP

**Statut** `Proposé` · 27 novembre 2026

## Contexte

Le codec RDP Go sait déjà décoder `MultiOpaqueRect` (ordre primaire `0x12`) avec ses neuf champs explicites, une liste `DELTA_RECTS` bornée, des coordonnées cumulées validées et un rendu framebuffer opaque. Les limites de compte, de taille encodée, de surface et de bureau sont partagées avec le profil MultiDstBlt. Le profil n'est toutefois pas annoncé par le client et le garde de session le refuse.

L'ordre possède son propre index `TS_NEG_MULTIOPAQUERECT_INDEX` (18), distinct de l'index partagé 1 de PatBlt/OpaqueRect. L'activation ne doit donc pas être déduite de l'activation d'un autre ordre `Multi*`.

## Décision

1. Annoncer uniquement l'index 18 de `MultiOpaqueRect` dans le profil 32 bpp, où le parseur, le rendu et les limites sont couverts par des tests.
2. Activer `multiOpaqueRectEnabled` uniquement après un échange Confirm Active réussi et uniquement pour une session négociée en 32 bpp.
3. Garder l'index à zéro et le garde désactivé en 15 et 16 bpp.
4. Ne pas annoncer `MultiDstBlt`, `MultiPatBlt`, `MultiScrBlt`, ni aucun autre ordre primaire par proximité. Leurs index et profils restent indépendants.
5. Conserver le refus fail-closed des ordres non annoncés, des champs incomplets, des listes delta malformées, des rectangles hors bureau et des données résiduelles.
6. Tester séparément l'octet de capacité émis et le profil d'activation pour 15, 16 et 32 bpp. Les tests Windows Server restent exécutés exclusivement en CI.

## Conséquences

- (+) Les serveurs RDP peuvent utiliser le sous-ensemble MultiOpaqueRect déjà implémenté et rendu en 32 bpp.
- (+) L'index 18 reste indépendant de PatBlt/OpaqueRect (index 1) et des autres ordres multiples.
- (+) Les profils 15/16 bpp et les autres ordres multiples restent fermés.
- (−) Les profils de coordonnées delta, de couleurs et de rectangles restent volontairement stricts ; les variantes non couvertes ne sont pas annoncées.

## Références

- [MS-RDPEGDI — MultiOpaqueRect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/74e46cd9-d649-4bbe-9f8a-f4200f23302e)
- [MS-RDPEGDI — Primary Drawing Orders](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272)
