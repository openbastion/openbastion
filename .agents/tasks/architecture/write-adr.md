# Écrire un ADR

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Numéro = suivant dans l'index du doc 03 ; ligne dans l'index ; section avant « Prochaine étape ».
2. **Contexte** : le problème réel, ce qui manque aujourd'hui, ce qui pousse à décider maintenant.
3. **Décision** : numérotée, précise, testable ; défauts stricts.
4. **Conséquences** : `(+)` ce qui est prouvé (nombres mesurés), `(−)` **toutes** les limites, y compris celles que tu aurais préféré ne pas écrire.
5. **Alternatives envisagées** : chaque option écartée, avec son motif.
6. Statut : `Accepté` seulement avec le go de l'utilisateur pour l'étape ; sinon `Proposé`. Dis-le dans le rapport, avec ce qui reste renversable.
7. Pour changer une décision acceptée : nouvel ADR ; l'ancien est marqué `Remplacé par ADR-NNNN` ; son texte de décision ne se réécrit pas.
