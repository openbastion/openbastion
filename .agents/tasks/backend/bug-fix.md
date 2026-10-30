# Correction de bug

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. **Reproduire** : un test qui échoue pour la bonne raison. Pas de test rouge ⇒ pas de correctif.
2. **Trouver la cause**, pas le symptôme : lis le code, vérifie les hypothèses par une mesure.
3. **Corriger au plus petit** ; pas de refactoring opportuniste.
4. **Contre-épreuve** : annule le correctif, le test redevient rouge ; restaure.
5. **Chercher les jumeaux** : le même défaut ailleurs (autre service, autre route, autre magasin) ? Corrige-les ou consigne-les.
6. **Documenter** : si le bug trahissait une hypothèse fausse ou une limite, écris-la dans `NOTES_SANDBOX.md` ; barre toute limite que le correctif referme.
7. Commit `fix(portée): …`, push, rapport : cause, correctif, test, jumeaux.
