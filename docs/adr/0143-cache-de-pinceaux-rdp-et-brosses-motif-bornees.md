# ADR-0143 — Cache de pinceaux RDP et brosses motif bornées

**Statut** `Accepté` · 27 novembre 2026 · accepté par le propriétaire du projet

## Contexte

L'ADR-0142 a livré un cache bitmap rév. 2/3 et les ordres MemBlt/Mem3Blt, avec un profil volontairement limité à la brosse `BS_SOLID`. Le parseur consomme actuellement les ordres secondaires `TS_CACHE_BRUSH` sans les interpréter. Le backlog RDP identifie le cache de pinceaux comme l'incrément suivant.

La spécification RDP définit deux caches mémoire indépendants : monochrome et couleur, chacun de 64 entrées. `TS_CACHE_BRUSH` transporte un index, un format, des dimensions, un style réservé, une longueur et les données de la brosse. Les ordres primaires indiquent une référence de cache par `TS_CACHED_BRUSH` dans `BrushStyle` et l'index dans `BrushHatch`.

Annoncer une capacité de pinceaux sans décoder les données, vérifier les références et appliquer réellement le motif serait incorrect. Les formats indexés, profondeurs multiples et styles de brosse constituent également des surfaces de parsing distinctes qui ne doivent pas être acceptées implicitement.

## Décision proposée

1. **Capacité négociée** : annoncer `TS_BRUSH_CAPABILITYSET` (`CAPSTYPE_BRUSH`, type 15, longueur 8) avec `BRUSH_COLOR_8x8` (`brushSupportLevel=1`) uniquement lorsque le profil complet de cet ADR est actif. Ne pas annoncer `BRUSH_COLOR_FULL`.
2. **Caches isolés** : créer un cache monochrome et un cache couleur, 64 entrées chacun, indexées de 0 à 63. Les entrées sont immuables et contiennent une représentation canonique 8×8 bornée. Aucun cache n'est partagé entre sessions.
3. **Formats initiaux** : accepter `BMF_1BPP` pour les motifs monochromes et `BMF_24BPP` pour les motifs couleur en session 32 bpp. Pour le 24 bpp, accepter le format compressé quatre couleurs (16 octets d'indices 2 bits + quatre couleurs RGB) et le format brut (64 pixels × 3 octets). Refuser explicitement les formats 8/16/32 bpp, les palettes, les dimensions autres que 8×8, les styles réservés non nuls et toute longueur incohérente. Cette liste est un profil volontairement plus étroit que la spécification.
4. **Ordre secondaire** : décoder `TS_CACHE_BRUSH` (`orderType=0x07`) dans la longueur isolée `orderLength+13`. Vérifier `cacheEntry<64`, le format, les dimensions, `iBytes` et l'absence de données résiduelles avant toute mutation. Remplacer atomiquement une entrée existante.
5. **Références primaires** : interpréter `TS_CACHED_BRUSH` (`BrushStyle & 0x80`) uniquement pour les ordres dont le rendu motif est livré. Vérifier que le nibble de format correspond au cache sélectionné et que `BrushHatch` référence une entrée existante. Toute référence absente, incohérente ou non annoncée termine la session ; aucune substitution par une couleur unie n'est autorisée.
6. **Consommateurs** : étendre d'abord PatBlt et Mem3Blt pour utiliser les brosses couleur 24 bpp et monochromes, en conservant l'origine de brosse, le clipping et l'ordre des opérations. Les styles hachurés, les brosses bitmap non mises en cache, les autres ordres géométriques et les autres ROP restent hors profil tant qu'ils ne disposent pas de tests pixel-à-pixel dédiés.
7. **ROP et framebuffer** : le parseur produit des opérations typées avec la brosse résolue ; le framebuffer applique le motif à partir de l'origine et évalue les ROP au moment du rendu, sur le framebuffer courant. Aucun ROP dépendant du motif ne doit être pré-calculé dans le parseur.
8. **Bornes** : 64 entrées monochromes × 8 octets de motif et 64 entrées couleur × 8×8×4 octets canoniques, soit un plafond de 16 896 octets de données canoniques par session, hors overhead Go borné. Pas d'allocation pilotée par une dimension distante autre que le 8×8 fixe. Le remplacement et la purge effacent les buffers possédés par le cache lorsque possible.
9. **Atomicité et cycle de vie** : cloner l'état des caches au début de chaque `TS_UPDATE_ORDERS`/`TS_FP_UPDATE_ORDERS` ; ne commettre aucune entrée si un ordre du PDU échoue. Purger les deux caches à la réactivation et à la fermeture, comme le cache bitmap de l'ADR-0142.
10. **Preuves** : tests unitaires pour les formats acceptés/refusés, l'ordre des bits et des lignes monochromes, la compression quatre couleurs, les remplacements, les références manquantes, les limites et le rollback ; tests framebuffer pixel-à-pixel pour les ROP et origines ; fuzz du parseur secondaire et des consommateurs ; matrice Windows Server 2019/2022 exclusivement en CI.

## Conséquences

- (+) Le serveur peut envoyer et réutiliser des motifs 8×8 sans envoyer les pixels à chaque opération.
- (+) Les caches restent strictement bornés, par session, et intégrés au mécanisme transactionnel déjà éprouvé.
- (+) Le profil annoncé correspond exactement aux formats et aux consommateurs réellement testés.
- (−) Les formats indexés 8 bpp, 15/16 bpp, 32 bpp, les profondeurs 4 bpp, les palettes et les brosses de dimensions arbitraires restent refusés.
- (−) Les styles hachurés, `BS_PATTERN` inline, `BS_NULL`, les caches persistants et les consommateurs autres que PatBlt/Mem3Blt ne sont pas inclus.
- (−) Les sessions 15/16 bpp ne bénéficient pas de ce profil dans cette première étape.

## Alternatives envisagées

- **Annoncer `BRUSH_COLOR_FULL`** : écartée, car elle autoriserait des dimensions arbitraires et élargirait inutilement la surface mémoire.
- **Accepter immédiatement tous les formats de la spécification** : écartée ; les palettes et conversions de profondeur exigent des contrats et des tests distincts.
- **Ne prendre en charge que les brosses monochromes** : écartée comme cible finale de l'incrément, car elle laisserait sans réponse les motifs couleur les plus courants ; elle reste un sous-ensemble possible si les preuves couleur révèlent un risque.
- **Rendre les motifs dans le parseur** : écartée ; le résultat dépend du framebuffer courant, de l'origine de brosse et de l'ordre des opérations du PDU.

## Références

- [MS-RDPEGDI — Cache Brush](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/9e7027c4-d989-4cb0-9674-e2e36c95ebdd)
- [MS-RDPEGDI — Compressed Color Brush](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/43f2b0a5-6a76-47a3-b6d2-79b08b80f2d2)
- [MS-RDPBCGR — Brush Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8b6a830f-3dde-4a84-9250-21ffa7d2e342)
- [MS-RDPEGDI — PatBlt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/bd4bf5e7-b988-45f9-8201-3b22cc9aeeb8)
