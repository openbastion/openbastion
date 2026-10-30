# Backlog

Ce qui reste à faire, du plus prioritaire au moins prioritaire. La source détaillée et datée des limites est `NOTES_SANDBOX.md` (« Ce que cela ne fait PAS ») et le Guide Sécurité §12 ; une ligne refermée se barre ici et là-bas, avec ce qui l'a refermée.

| # | Sujet | Pourquoi | Où c'est écrit |
|---|---|---|---|
| 1 | ~~**Exécuter les rotations `scheduled`**~~ — **fait** (ADR-0040) | ~~acceptées à l'enregistrement, lancées par rien~~ | ADR-0040 |
| 1 bis | Fenêtres horaires et alerte après plusieurs échecs d'une rotation planifiée | un compte peut tourner en pleine journée ; un échec est retenté chaque heure sans alerte | ADR-0040 |
| 2 | Réessayer une rotation après usage échouée | un échec laisse l'ancien secret en place jusqu'à la prochaine fin de session | ADR-0037 |
| 3 | Relayer le motif d'un `409` du Vault à l'opérateur | `connect` dit « authorize-scope: status 409 » sans dire pourquoi | ADR-0039 |
| 4 | Proxy SSH en plusieurs instances | la révocation n'atteint qu'une instance | ADR-0018, `architecture/known-gaps.md` |
| 5 | Pipeline de CI | aucune porte automatique aujourd'hui | `settings/ci-cd.yaml` |
| 6 | Certificats d'hôte SSH (autorité) à côté de l'épinglage | une seule clé par compte | ADR-0039 |
| 7 | Vrai KMS/HSM à la place de `LocalKMS` | la KEK est locale | NOTES (prochains incréments) |
| 8 | gRPC à la place de HTTP/JSON | écart assumé, réseau du sandbox | `architecture/transport-and-contracts.md` |
| 9 | Images de base épinglées par empreinte | reproductible pour le code, pas pour les images | NOTES (ADR-0033) |
| 10 | Feuille de route v1.0 (RDP, Workflow/Approval Engine, MFA natif…) | hors MVP | `roadmap.md` |
