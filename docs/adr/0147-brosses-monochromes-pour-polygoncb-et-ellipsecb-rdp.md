# ADR-0147 — Brosses monochromes mises en cache pour PolygonCB et EllipseCB

**Statut** `Proposé` · 27 novembre 2026

## Contexte

L'incrément 68 a introduit `PolygonCB` et `EllipseCB` avec des brosses couleur `BMF_24BPP` déjà présentes dans le cache RDP. Le cache de brosses par session prend également en charge `BMF_1BPP`, et les ordres `PatBlt` et `Mem3Blt` savent déjà développer ces masques monochromes à partir des couleurs de premier plan et d'arrière-plan.

Les ordres `PolygonCB` et `EllipseCB` transportent eux aussi `ForeColor`, `BackColor`, `BrushOrgX` et `BrushOrgY`. Refuser `BMF_1BPP` alors que le cache et la sémantique de développement sont déjà disponibles limite inutilement la réutilisation des brosses monochromes.

## Décision proposée

1. Étendre uniquement les profils déjà négociés de `PolygonCB` (index 21) et `EllipseCB` (index 26) pour accepter les formats de cache `BMF_1BPP` et `BMF_24BPP` ; ne modifier ni les index ni les conditions de négociation 32 bpp / Confirm Active.
2. Pour `BMF_1BPP`, résoudre exclusivement une entrée monochrome existante dans le cache de la session et développer son masque 8×8 en RGBA canonique avec `ForeColor` pour les bits à 1 et `BackColor` pour les bits à 0.
3. Conserver `BrushOrgX` et `BrushOrgY` comme origine du motif au rendu ; le développement du motif ne doit pas déplacer l'origine ni pré-calculer un résultat dépendant du framebuffer.
4. Pour `BMF_24BPP`, conserver les pixels canoniques déjà en cache et ignorer les couleurs de premier plan/arrière-plan pour le contenu du motif, tout en validant les champs requis.
5. Refuser les styles, formats, références de cache, champs omis ou données supplémentaires non pris en charge. Ne jamais substituer une couleur unie lorsqu'une entrée monochrome est absente.
6. Maintenir les limites existantes : 64 entrées par cache, 8 octets pour un masque monochrome, une tuile RGBA de 256 octets pour le rendu, nombre de formes et aire totale bornés, et mise à jour transactionnelle de l'état des ordres.
7. Ajouter des tests de décodage, d'entrée absente, de format invalide, de développement ForeColor/BackColor, d'origine négative et de rendu pixel par pixel pour les deux ordres. Les validations Windows Server 2019/2022 restent exécutées exclusivement en CI.

## Conséquences

- (+) Les deux ordres CB peuvent consommer les deux formats de brosse déjà stockés par le cache RDP.
- (+) Le masque monochrome est développé une seule fois en motif RGBA borné, puis le ROP2 reste appliqué au framebuffer courant.
- (+) Aucun changement de négociation, de capacité mémoire persistante ou d'état implicite des champs n'est introduit.
- (−) Les styles de brosse autres que les formats mis en cache, les coordonnées delta et le clipping restent exclus.

## Alternatives envisagées

- **Convertir le masque monochrome en couleur lors de son insertion dans le cache** : écartée, car les couleurs ForeColor/BackColor appartiennent à chaque ordre consommateur et non à l'entrée de cache.
- **Réutiliser directement les huit octets du masque dans le framebuffer** : écartée, car le framebuffer consomme des pixels RGBA et le ROP2 doit être appliqué à une couleur résolue.
- **Élargir simultanément les styles et les coordonnées delta** : écartée, car ces variantes ajoutent des sémantiques distinctes qui exigent des contrats et des preuves séparés.

## Références

- [MS-RDPEGDI — PolygonCB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/24f4e229-1f9f-4633-b9be-66d7579ba36d)
- [MS-RDPEGDI — EllipseCB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/89720383-8394-423a-810a-ba631d66055f)
- [MS-RDPEGDI — Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272)
