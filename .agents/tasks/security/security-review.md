# Revue de sécurité d'un changement ou d'un composant

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Le modèle d'attaque : opérateur malveillant, service compromis, réseau hostile (entre services **et** vers les cibles), base compromise, navigateur hostile.
2. Pour chaque entrée et chaque canal : qui l'appelle ? L'identité vient-elle d'une preuve (certificat, jeton vérifié) ou d'une déclaration ? Que se passe-t-il en cas de panne (fail-closed) ?
3. Un test par attaque plausible ; vérifie qu'il échoue sans la défense.
4. Les canaux oubliés : journaux, messages d'erreur, réponses recopiées par la Gateway, arguments de commande, sauvegardes, enregistrements.
5. Classe les constats (bloquant / à corriger / limite acceptée) ; consigne les limites dans `docs/security/known-limitations.md`.
6. Pour une relecture indépendante, persona `personas/independent-security-auditor.md`.
