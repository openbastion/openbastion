# ADR-0142 — Le cache bitmap RDP v2/v3 n'est annoncé qu'avec MemBlt et Mem3Blt bornés

**Statut** `Accepté` · 25 novembre 2026 · go du propriétaire du projet : « Go pour la prochaine étape » (25 novembre 2026)

**Contexte** — ADR-0090, lot B, place les caches bitmap v2/v3 avant MemBlt et Mem3Blt. Le profil graphique négocié annonce désormais uniquement DstBlt (ADR-0141). Le parseur ne traite pas encore les ordres secondaires, ne possède pas de cache bitmap RDP par partage et ne sait pas dessiner depuis une entrée de cache. Annoncer un cache seul serait incorrect : MS-RDPBCGR/MS-RDPEGDI conditionne la réception des ordres Cache Bitmap rév. 2 et 3 à la prise en charge de MemBlt et Mem3Blt. Les ordres reçus par TLS restent contrôlés par la cible distante ; les longueurs, références de cache, allocations et opérations raster doivent donc être strictement bornées.

**Décision**

1. Implémenter un profil cohérent et négocié pour les sessions 32 bpp : Cache Bitmap rév. 2 (ordres secondaires non compressé et compressé), Cache Bitmap rév. 3 avec `codecID=0` (données brutes), MemBlt et Mem3Blt. Les sessions 15/16 bpp conservent DstBlt (opération indépendante de la profondeur), mais n'annoncent aucun cache ni ordre MemBlt/Mem3Blt. Les indices primaires de négociation 3 et 4 sont annoncés seulement avec les deux décodeurs complets du profil ; le bit `ORDERFLAGS_EX_CACHE_BITMAP_REV3_SUPPORT` est annoncé avec la rév. 3.
2. Annoncer un seul cache rév. 2, `cacheId=0`, de 256 entrées, mémoire uniquement. `CacheFlags=0`, le bit de persistance `k=0` et l'absence de `ALLOW_CACHE_WAITING_LIST_FLAG` signifient qu'aucune persistance inter-session ni liste d'attente n'est annoncée. Le cache est détruit à la réactivation et à la fermeture de la session.
3. Décoder les bitmaps rév. 2 en 32 bpp : données brutes ou RDP 6.0 ARGB/AYCoCg, avec ou sans `bitmapComprHdr` selon les drapeaux. Décoder la rév. 3 uniquement avec `codecID=0`, données brutes 32 bpp ; consommer les deux moitiés de sa clé 64 bits, sans persister cette clé.
4. Borner le cache à 256 entrées, 16 Mio par bitmap et 32 Mio cumulés par partage ; la surface décodée reste sous `maxRDPDesktopArea`. Le remplacement d'un index libère logiquement l'ancienne entrée. Aucun évincement autonome, aucune persistance, aucun cache hors écran et aucun cache couleur ne sont introduits.
5. Les ordres secondaires utilisent leur en-tête normatif `orderLength + 13` ; chaque ordre est isolé dans cette longueur avant décodage. Accepter uniquement les types rév. 2 `0x04/0x05` et rév. 3 `0x08`, avec `controlFlags=TS_STANDARD|TS_SECONDARY`, cache 0 et champs cohérents. Refuser les clés persistantes rév. 2, `DO_NOT_CACHE`, les index d'attente, les codecs rév. 3 autres que zéro, les profondeurs inconnues, les longueurs incohérentes et les données résiduelles.
6. MemBlt et Mem3Blt décodent leurs champs omis, coordonnées absolues/delta et bornes à partir d'un état par type d'ordre. Ils n'acceptent que `cacheId=0`, une entrée existante, une table couleur nulle et un rectangle source intégralement contenu dans le bitmap. Les destinations sont intersectées avec le bureau et les bornes RDP avant émission d'une opération framebuffer.
7. MemBlt accepte les ROP3 indépendants du motif (fonction uniquement des bits source et destination) et applique leur table de vérité par pixel. Mem3Blt accepte uniquement `BS_SOLID`, sans données de brosse/hachure supplémentaires ; son ROP3 est évalué à partir du motif solide `ForeColor`, de la source et de la destination. Toute autre brosse ou référence de cache est refusée.
8. Les états de cache et de champs sont transactionnels à l'échelle d'un `TS_UPDATE_ORDERS` : aucune entrée ni valeur de champ n'est commise si un ordre du PDU est malformé. Une référence absente, un dépassement de budget ou un ordre non annoncé termine la session (`ErrMCSConnection`). La réactivation réinitialise l'état et les caches avant de réappliquer le profil négocié.
9. Les tests couvrent les encodages variables, les en-têtes secondaires, les ordres révision 2/3, les limites mémoire, les champs omis/deltas, le clipping, les ROP3, l'absence d'entrée, le rollback atomique, la persistance entre PDU, la négociation TLS et la réactivation. Les scénarios Windows restent exécutés exclusivement en CI.

**Conséquences**

- (+) Le serveur peut envoyer les bitmaps réutilisés et les ordres MemBlt/Mem3Blt sans que le client annonce une famille qu'il ne sait pas décoder. Les plafonds de mémoire sont explicites et par partage : 32 Mio d'état commis ; le clone transactionnel peut brièvement retenir l'ancien et le nouvel état, soit au plus 64 Mio par partage pendant le décodage d'un PDU.
- (+) Le rendu conserve l'ordre des opérations : les ROP3 lisent le framebuffer courant et ne sont pas pré-calculés dans le parseur.
- (−) La rév. 3 ne prend en charge que `codecID=0` ; les autres codecs ferment la session. Les bitmaps rév. 2 8/15/16/24 bpp sont refusés.
- (−) Un seul cache non persistant de 256 entrées est exposé ; pas de cache d'attente, de clés persistantes, de reprise de cache, de cache couleur, de bitmap hors écran, ni d'éviction LRU locale.
- (−) Mem3Blt ne prend en charge que la brosse solide ; les brosses hachurées, indexées, monochromes ou bitmap et leurs caches restent absents.
- (−) Les ROP3 source/destination/pattern non pris en charge par le profil MemBlt/Mem3Blt sont refusés ; aucun rendu approximatif n'est autorisé.
- (−) Le profil ne couvre pas SaveBitmap, PolygonCB/EllipseCB, glyphes, cache de pinceaux, Alternate Secondary Orders, Fast-Path orders, ni une compatibilité RDP/RDS générale. Les résultats de performance et d'identité pixel-à-pixel doivent être mesurés dans la matrice CI avant d'élargir le profil.

**Alternatives envisagées**

- **Annoncer le cache bitmap avant MemBlt/Mem3Blt** : écartée, car les spécifications conditionnent les ordres cache à la prise en charge des deux ordres primaires.
- **Activer la persistance et les listes d'attente** : écartée ; elles exigent la gestion des clés persistantes et des Persistent Key List PDUs, sans nécessité pour le cache mémoire d'une session.
- **Accepter tous les codecs de la rév. 3 et toutes les brosses Mem3Blt** : écartée ; chaque codec/brosse ajoute une surface de décodage et de mémoire qui doit avoir ses propres limites et contre-épreuves.
- **Rendre le ROP3 directement dans le parseur** : écartée, car le résultat dépend du framebuffer courant et des opérations antérieures du même PDU ; le parseur produit des opérations ordonnées que le framebuffer valide et applique.
