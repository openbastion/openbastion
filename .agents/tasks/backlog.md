# Backlog

Ce qui reste à faire, du plus prioritaire au moins prioritaire. La source détaillée et datée des limites est `NOTES_SANDBOX.md` (« Ce que cela ne fait PAS ») et le Guide Sécurité §12 ; une ligne refermée se barre ici et là-bas, avec ce qui l'a refermée.

| # | Sujet | Pourquoi | Où c'est écrit |
|---|---|---|---|
| 1 | ~~**Exécuter les rotations `scheduled`**~~ — **fait** (ADR-0040) | ~~acceptées à l'enregistrement, lancées par rien~~ | ADR-0040 |
| 1 bis | ~~Fenêtres horaires et alerte après plusieurs échecs d'une rotation planifiée~~ — **fait** (ADR-0041) | ~~un compte peut tourner en pleine journée ; un échec est retenté chaque heure sans alerte~~ | ADR-0041 |
| 1 ter | Notification poussée des alertes (`vault.rotation_overdue`, …) | l'alerte n'est visible que dans l'audit | ADR-0041 |
| 2 | ~~Réessayer une rotation après usage échouée~~ — **fait** (ADR-0044) | ~~un échec laisse l'ancien secret en place jusqu'à la prochaine fin de session~~ | ADR-0044 |
| 3 | ~~Relayer le motif d'un `409` du Vault à l'opérateur~~ — **fait** (ADR-0042) | ~~`connect` dit « authorize-scope: status 409 » sans dire pourquoi~~ | ADR-0042 |
| 3 bis | ~~Revoir les autres routes publiques ; refuser dès `POST /sessions` un compte non épinglé~~ — **fait** (ADR-0043) | ~~les routes d'administration relaient encore le texte des refus d'écriture du Vault~~ | ADR-0043 |
| 4 | Proxy SSH en plusieurs instances | la révocation n'atteint qu'une instance | ADR-0018, `architecture/known-gaps.md` |
| 5 | Pipeline de CI | aucune porte automatique aujourd'hui | `settings/ci-cd.yaml` |
| 6 | Certificats d'hôte SSH (autorité) à côté de l'épinglage | une seule clé par compte | ADR-0039 |
| 7 | Vrai KMS/HSM à la place de `LocalKMS` | la KEK est locale | NOTES (prochains incréments) |
| 8 | gRPC à la place de HTTP/JSON | écart assumé, réseau du sandbox | `architecture/transport-and-contracts.md` |
| 9 | Images de base épinglées par empreinte | reproductible pour le code, pas pour les images | NOTES (ADR-0033) |
| 10 | Feuille de route v1.0 (RDP, Workflow/Approval Engine, MFA natif…) | hors MVP | `roadmap.md` |
