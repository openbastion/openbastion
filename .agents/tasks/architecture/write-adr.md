# Écrire un ADR

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Numéro = le suivant dans `docs/adr/README.md` ; nouveau fichier `docs/adr/NNNN-titre-kebab-case.md` copié de `docs/adr/template.md` ; sa ligne dans les **deux** index, avec le lien : dans sa catégorie (à sa place dans l'ordre de mise en œuvre ; une catégorie nouvelle seulement si aucune ne convient) et à la fin de l'index numérique, avec sa catégorie.
2. **Contexte** : le problème réel, ce qui manque aujourd'hui, ce qui pousse à décider maintenant.
3. **Décision** : numérotée, précise, testable ; défauts stricts.
4. **Conséquences** : `(+)` ce qui est prouvé (nombres mesurés), `(−)` **toutes** les limites, y compris celles que tu aurais préféré ne pas écrire.
5. **Alternatives envisagées** : chaque option écartée, avec son motif.
6. Statut : `Accepté` seulement avec le go de l'utilisateur pour l'étape ; sinon `Proposé`. Dis-le dans le rapport, avec ce qui reste renversable.
7. Pour changer une décision acceptée : nouvel ADR ; l'ancien est marqué `Remplacé par ADR-NNNN` ; son texte de décision ne se réécrit pas.
