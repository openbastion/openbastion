# Ajouter un protocole de proxy

> Workflow : un ordre de travail, pas une liste de cases cosmétiques. Saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. « Terminé » : `rules/completion-gates.md`.

1. Lis `architecture/`, ADR-0006, doc 01 §4.2 et le Guide Développeur §5. Le pipeline commun est `pkg/proxycore` : n'implémente que le **codec**.
2. Conçois la capture (commandes, fichiers, presse-papiers…) et ce qui est enregistré ou masqué ; ADR si c'est structurant.
3. Le proxy n'atteint la cible qu'avec un credential obtenu par scope à usage unique, et n'envoie le secret qu'à la cible dont l'identité est épinglée au Vault (ADR-0039 pour SSH).
4. Tests : vrai protocole à trois participants (client, proxy, fausse cible qui rapporte ce qu'elle reçoit) ; enregistrer ou refuser ; expiration ; purge du secret ; imposteur.
5. Ajoute le service à `go.work`, au `Makefile`, aux tables d'appelants, au mTLS (`pki.StandardServices`), à `settings/project.yaml`.
