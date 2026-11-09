# ADR-0089 — Le texte RDP reste rendu par bitmaps : le cache de glyphes n'est pas implémenté tant qu'une mesure ne le demande pas

**Statut** `Proposé` · 9 novembre 2026 · en attente du go du propriétaire du projet : la décision réécrit un critère de sortie d'ADR-0071, qui est `Accepté`.

## Contexte

ADR-0071 (incrément 3) fixe comme critère de sortie « texte lisible (glyphes) ». Il prévoyait d'annoncer et de décoder le cache de glyphes. Sur les autres critères :
- tenus : session enregistrée et rejouable, capacités non annoncées refusées, QWERTY et AZERTY, touche relâchée sur perte de focus, `recording_lost` au-delà de 4 Mio ;
- restant : celui-ci, le dernier.

**Ce que le client annonce aujourd'hui** (`pkg/rdp/mcs_capabilities.go`) :
- aucun ordre primaire : `orderSupport` est tout à zéro ;
- aucun cache de glyphes : pas de `TS_GLYPHCACHE_CAPABILITYSET` ;
- aucun cache bitmap.

Windows et FreeRDP envoient donc le texte **déjà rendu**, dans les bitmaps.

**Ce qui est mesuré.** Contre Windows Server 2022, en 16 et 32 bpp (PR #86, #93, #97), le texte se lit à l'œil sur les captures : menus et contenu du Bloc-notes, texte tapé, horloge et filigrane de la barre des tâches. Contre FreeRDP, le texte du terminal se lit aussi. Le texte tapé arrive exact à la cible : vérifié par fichier à la PR #97, mais c'est l'entrée qui est prouvée, pas l'affichage.

**Ce que le cache de glyphes demanderait** (MS-RDPBCGR 2.2.7.1.8, MS-RDPEGDI) :
- annoncer `TS_GLYPHCACHE_CAPABILITYSET` ;
- décoder les ordres secondaires Cache Glyph (révisions 1 et 2), un cache par 10 tailles de cellule et un cache de fragments ;
- décoder les ordres primaires GlyphIndex, FastIndex et FastGlyph, avec le pinceau, les rectangles d'arrière-plan et d'avant-plan, et le décalage entre glyphes ;
- tenir le tout borné et refusé au moindre écart.

C'est un nouveau parseur exposé à la cible, plus large que tous les ordres décodés à ce jour.

**Ce que le cache de glyphes ne changerait pas.** L'opérateur et l'enregistrement reçoivent des images PNG complètes du framebuffer du proxy (ADR-0071 §6, ADR-0070). Que le texte arrive en glyphes ou en bitmaps, l'image montrée et l'image rejouée sont les mêmes pixels. Les glyphes n'économisent que du débit entre la cible et le proxy, d'ordinaire sur le même réseau. Ce débit n'a jamais été mesuré comme un problème.

## Décision proposée

1. **Le texte reste rendu par bitmaps.** Le client continue de n'annoncer ni ordre de texte ni cache de glyphes. « Aucune capacité non annoncée acceptée » reste vrai : un GlyphIndex, FastIndex, FastGlyph ou Cache Glyph reçu est refusé et ferme la session, comme aujourd'hui.
2. **Le critère de sortie devient « texte lisible »**, au lieu de « texte lisible (glyphes) ». Sa preuve :
   - les captures Windows en 16 et 32 bpp, jugées à l'œil, déposées en artefact par chaque passage du CI Windows ;
   - un test qui vérifie qu'un ordre de texte non annoncé est refusé.
3. **Ce qui rouvrirait la question**, mesuré, et alors par un nouvel ADR :
   - un débit cible → proxy qui gêne, une fois mesuré à l'incrément 5 d'ADR-0071 ;
   - une cible qui refuse de servir un client sans glyphes : aucune n'est connue, ni Windows Server 2022, ni FreeRDP 3.

## Conséquences

- (+) Avec ce go, le dernier critère de sortie d'ADR-0071 est tenu. La surface exposée à la cible n'augmente pas.
- (+) Rien ne change pour l'opérateur ni pour l'auditeur : le PNG montré et le PNG rejoué sont ceux d'aujourd'hui.
- (−) La lisibilité est jugée à l'œil, pas par une machine : aucune reconnaissance de caractères n'est faite.
- (−) Le débit cible → proxy est celui des bitmaps. Il n'est pas mesuré, et peut être plus élevé qu'avec des glyphes sur un écran chargé de texte.
- (−) ADR-0071 décrivait le cache de glyphes dans son périmètre (§ capacités et ordres). Ce périmètre se réduit : les lignes qui le citent renverront à cet ADR.

## Alternatives envisagées

- **Implémenter le cache de glyphes, comme ADR-0071 le prévoyait.** Écartée pour l'instant :
  - c'est le plus gros parseur restant, exposé à une cible qu'on ne fait pas confiance ;
  - il ne change pas l'image montrée ni l'image enregistrée ;
  - le gain de débit qu'il apporterait n'est pas mesuré.
- **Annoncer les glyphes sans les décoder, en les rendant par un autre moyen** : écartée. Une capacité annoncée doit être décodée ou refusée (ADR-0071 §5), jamais acceptée à moitié.
- **Prouver la lisibilité par reconnaissance de caractères en CI** : écartée pour l'instant. C'est une dépendance lourde (un moteur OCR) pour une preuve que l'œil donne déjà sur chaque passage ; à reconsidérer si les captures cessent d'être regardées.
