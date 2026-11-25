# ADR-0141 — Le client RDP annonce DstBlt seulement après décodage de son profil complet

**Statut** `Accepté` · 25 novembre 2026 · go du propriétaire : « Oui, tu peux passer à la prochaine étape. » (25 novembre 2026)

**Contexte** — Le parseur RDP savait déjà rendre un sous-ensemble de DstBlt, mais le slot `orderSupport[0]` restait à zéro : le serveur ne devait donc pas envoyer cet ordre. Le profil précédent ne gérait ni les champs omis, ni les coordonnées delta, ni les bornes de clipping. L'annoncer aurait déclaré une compatibilité plus large que le décodeur. ADR-0090, lot B, demande que chaque profil soit complet, borné et prouvé avant son annonce. Le serveur distant contrôle chaque octet reçu par le parseur ; un défaut de longueur, d'état ou de clipping peut donc devenir un déni de service ou une corruption de l'image auditée.

**Décision**

1. Le client implémente et annonce uniquement `DstBlt` (`orderType=0x00`, index de négociation `0`). Les 32 octets `orderSupport` restent nuls partout ailleurs.
2. Le profil décode les cinq champs DstBlt avec leur cache par ordre. Un champ absent conserve sa dernière valeur ; les valeurs initiales sont nulles. Le champ de drapeaux utilise la formule normative et accepte l'omission des octets finaux nuls via `TS_ZERO_FIELD_BYTE_BIT0/1`.
3. Les coordonnées absolues sont des entiers signés 16 bits ; avec `TS_DELTA_COORDINATES`, chaque champ coordonnée présent est un delta signé 8 bits ajouté à sa valeur précédente. Tout dépassement de l'intervalle signé 16 bits ferme la session.
4. `TS_BOUNDS` active un rectangle de clipping inclusif partagé par les ordres. Ses quatre composantes peuvent être absolues, delta signées 8 bits ou inchangées. `TS_ZERO_BOUNDS_DELTAS` réutilise les bornes précédentes et n'est accepté qu'avec `TS_BOUNDS`. Un rectangle inversé est refusé ; une géométrie valide est intersectée avec le bureau et les bornes. Une intersection vide ne modifie pas le framebuffer.
5. Les seules opérations ROP3 admises sont les quatre fonctions qui ne dépendent que de la destination : `BLACKNESS` (`0x00`), `DSTINVERT` (`0x55`), `DSTCOPY` (`0xaa`, aucun changement visible) et `WHITENESS` (`0xff`). Tout ROP dépendant de la source ou du motif est refusé.
6. L'état de champ et de bornes n'est commis qu'après décodage complet de la mise à jour. Une erreur laisse l'état précédent inchangé et termine la session. Les mises à jour sans rectangle visible commettent l'état protocolaire mais ne produisent pas de nouvelle image.
7. Confirm Active annonce `orderSupport[0]=1`. Après l'échange et chaque réactivation, le lecteur autorise uniquement DstBlt ; les autres gardes restent fermées. La réactivation remet à zéro les caches d'ordre avant de réappliquer ce profil.
8. Les plafonds existants `maxRDPPrimaryOrders`, `maxRDPBitmapRects` et `maxRDPDesktopArea` restent les bornes de compte, de rectangles et de pixels. Aucun cache bitmap, brosse, glyphes, autre ordre primaire, ordre secondaire/alternatif ou événement Fast-Path n'est annoncé par cette décision.

**Conséquences**

- (+) Le serveur peut utiliser DstBlt sans repli bitmap pour ce profil. Les tests couvrent les champs omis, les deltas, les bornes absolues/delta/réutilisées, le clipping, les quatre ROP3 destination-only, les refus malformés, la négociation Confirm Active, le lecteur TLS et la réactivation. Les tests couvrent aussi la persistance du cache entre PDU TLS, les dépassements de coordonnées/bornes delta et le refus atomique sans commit d'état. Les mesures et résultats de CI sont consignés dans `NOTES_SANDBOX.md`.
- (−) Le serveur qui envoie un autre ordre ou une variante hors profil provoque toujours une fermeture de session. La compatibilité Windows/RDS générale n'est pas revendiquée ; les scénarios Windows restent éprouvés exclusivement en CI.
- (−) Le framebuffer reste une image RGBA ; DstBlt ne crée ni cache ni surface hors écran. `DSTCOPY` et les ordres entièrement clippés n'émettent pas de frame.
- (−) PatBlt/OpaqueRect, ScrBlt, les variantes Multi, LineTo/Polyline/Polygon/Ellipse, les caches, MemBlt/Mem3Blt, PolygonCB/EllipseCB, les glyphes et Fast-Path Orders restent non annoncés.

**Alternatives envisagées**

- **Annoncer tous les ordres déjà partiellement décodés** : écartée, car leurs champs omis, coordonnées delta, bornes ou variantes de rendu ne sont pas tous pris en charge.
- **Garder tous les slots à zéro** : écartée pour DstBlt uniquement ; son profil complet est maintenant décodé, borné et testé, et peut être annoncé sans élargir les autres familles.
- **Accepter tous les octets ROP3** : écartée, car DstBlt est défini comme une opération qui ne dépend que de la destination ; les opérations source/motif sont hors contrat.
- **Refuser toute géométrie qui dépasse le bureau** : écartée au profit du clipping normatif à l'intersection bureau/bornes, sans allocation hors limites.
- **Déléguer le décodage à une bibliothèque RDP tierce** : écartée par ADR-0071 ; le moteur reste en Go pur, instrumentable et fermé par profils.

Références normatives : [MS-RDPBCGR §2.2.7.1.3 — Order Capability Set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9f409c29-480c-4751-9665-510b8ffff294), [MS-RDPEGDI §2.2.2.2.1.1.2 — Primary Drawing Order](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/23f766d4-8343-4e6b-8281-071ddccc0272), [§2.2.2.2.1.1.2.1 — DstBlt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/87ea30df-59d6-438e-a735-83f0225fbf91) et [§2.2.2.2.1.1.1.1 — Coord Field](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi/870b982c-9abe-40cb-99d0-2c3f0cc5fb74).
