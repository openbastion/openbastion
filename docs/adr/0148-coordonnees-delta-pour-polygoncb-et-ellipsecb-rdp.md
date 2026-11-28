# ADR-0148 — Coordonnées delta pour PolygonCB et EllipseCB RDP

**Statut** `Proposé` · 28 novembre 2026

## Contexte

Les profils `PolygonCB` (index de négociation 21) et `EllipseCB` (index 26) sont désormais rendus en 32 bpp avec brosses couleur et monochromes mises en cache. Ils exigent encore des coordonnées absolues et rejettent le contrôle `TS_DELTA_COORDINATES` (`0x10`).

La spécification MS-RDPEGDI définit les champs `COORD_FIELD` comme des valeurs signées 16 bits en mode absolu, ou comme des deltas signés sur un octet ajoutés à la dernière valeur du même champ lorsque `TS_DELTA_COORDINATES` est présent. Les champs `CodedDeltaList` de `PolygonCB` décrivent déjà les déplacements entre sommets et sont un encodage distinct : ce contrat ne doit pas les confondre avec le contrôle global des coordonnées primaires.

## Décision proposée

1. Étendre uniquement les profils déjà négociés de `PolygonCB` et `EllipseCB` pour accepter `TS_DELTA_COORDINATES`. Ne modifier ni les index 21/26, ni leur activation après Confirm Active, ni la restriction 32 bpp.
2. Pour `PolygonCB`, interpréter `xStart` et `yStart` comme des `COORD_FIELD` absolus ou delta selon le contrôle. Conserver deux valeurs précédentes propres à `PolygonCB`, indépendantes des autres familles d'ordres.
3. Pour `EllipseCB`, interpréter `left`, `top`, `right` et `bottom` comme des `COORD_FIELD` absolus ou delta selon le contrôle. Conserver quatre valeurs précédentes propres à `EllipseCB`, indépendantes de PolygonCB et des autres ordres.
4. Initialiser chaque valeur précédente à zéro conformément à l'état initial des champs primaires RDP. Pour chaque ordre, calculer `previous + int8(delta)` en entier signé suffisamment large, puis refuser tout résultat hors de l'intervalle `int16` avant validation des limites du bureau.
5. Garder tous les champs actuellement exigés explicitement présents. Les champs omis, la réutilisation implicite des champs d'ordre, `TS_BOUNDS`, `TS_ZERO_BOUNDS_DELTAS` et les autres contrôles non pris en charge restent refusés. Cet incrément ne change donc pas les règles de compression des field flags.
6. Ne modifier ni le décodage de `CodedDeltaList`, ni l'origine des brosses, ni le rendu ROP2. Le delta global ne s'applique qu'aux champs `COORD_FIELD` de l'ordre ; les deltas de sommets PolygonCB restent régis par leur propre structure.
7. Conserver le traitement transactionnel existant : les valeurs précédentes de coordonnées ne sont commises que si tous les ordres du PDU sont valides et négociés. Un ordre invalide ne doit pas laisser un état partiel réutilisable par le PDU suivant.
8. Ajouter des tests unitaires pour les deltas positifs et négatifs, la valeur initiale zéro, les limites `int16`, les deltas tronqués, les coordonnées hors bureau, l'isolation des caches PolygonCB/EllipseCB, le mélange absolu/delta entre ordres successifs, et le rollback après un ordre invalide. Ajouter des tests de rendu pixel par pixel pour vérifier que les coordonnées delta ne changent pas le résultat géométrique attendu.
9. Valider Windows Server 2019 et 2022 exclusivement en CI, dans les scénarios 32 bpp déjà couverts. Ne pas exécuter de tests Windows sur le poste de développement.

## Conséquences

- (+) Les deux ordres peuvent encoder efficacement les coordonnées de départ et les rectangles d'ellipse lorsque les valeurs évoluent peu.
- (+) L'état delta reste isolé par famille d'ordre et borné à l'intervalle signé 16 bits.
- (+) Les règles de cache de brosses, de négociation et de rendu restent inchangées.
- (−) Les champs omis, le clipping et les styles de brosse supplémentaires restent hors périmètre ; les coordonnées delta ne sont pas annoncées comme supportées pour les autres familles.

## Alternatives envisagées

- **Réutiliser le cache de coordonnées d'une autre famille d'ordre** : écartée, chaque ordre primaire possède son propre historique de champs ; un partage introduirait une dépendance inter-ordres incorrecte.
- **Autoriser simultanément les champs omis** : écartée, cela étendrait le contrat de field-cache et augmenterait l'état implicite à tester.
- **Appliquer `TS_DELTA_COORDINATES` aux points de `CodedDeltaList`** : écartée, cette structure possède déjà son propre codage de points delta ; le contrôle ne doit pas changer son interprétation.
- **Activer les coordonnées delta pour toutes les familles primaires** : écartée, chaque famille doit disposer de son propre état, de tests dédiés et de preuves d'interopérabilité avant annonce.

## Références

- [MS-RDPEGDI — Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272)
- [MS-RDPEGDI — Coord Field](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/870b982c-9abe-40cb-99d0-2c3f0cc5fb74)
- [MS-RDPEGDI — PolygonCB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/24f4e229-1f9f-4633-b9be-66d7579ba36d)
