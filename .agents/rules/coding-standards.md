# Normes de code communes

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

## 1. Langues

| Quoi | Langue |
|---|---|
| Identifiants, noms de fichiers, noms de tests, commentaires de code, messages d'erreur et de log | **Anglais** |
| Documentation (`docs/`, `README`, `NOTES_SANDBOX.md`, ADR, instructions des agents), sujets et corps de commit, rapports à l'utilisateur, commentaires explicatifs dans `go.mod`/`Makefile` | **Français** |
| Libellés de l'Admin UI | **Français** |
| Termes techniques établis (fail-closed, deny-by-default, scope, replay, break-glass…) | Gardés tels quels |

## 2. Nommage

| Élément | Convention | Exemple |
|---|---|---|
| Paquets Go | un mot, minuscule | `domain`, `sshcodec`, `mtls` |
| Fichiers Go | `snake_case.go` ; tests `*_test.go` à côté du code | `session_broker_service.go` |
| Types et fonctions exportés | `PascalCase`, nom = rôle | `SessionBrokerService`, `CheckAccess` |
| Ports | nom du rôle, suffixe `er` ou `Repository` | `SessionRepository`, `VaultAuthorizer` |
| Adaptateurs | `<Technologie><Rôle>` | `PostgresStore`, `InMemoryStore`, `AuditHTTPClient` |
| Variables d'environnement | `UPPER_SNAKE_CASE`, préfixe par domaine | `BREAKGLASS_MAX_MINUTES`, `TLS_CERT_FILE` |
| Ressources RBAC | `<domaine>:<type>:<id ou *>` | `vault:account:acc_1` |
| Actions d'audit | `<objet>.<événement>` en minuscules | `session.recording_lost` |
| Tests Go | `Test<Sujet>_<Comportement>` | `TestCheckAccess_DeniesByDefaultWithNoPolicy` |
| Tests d'intégration | `Test<Fonction>_<Comportement>_<Portée>` | `…_AcrossEightRealProcesses` |
| Composants React | `PascalCase.tsx`, un dossier par fonctionnalité | `features/accounts/Accounts.tsx` |
| ADR | `ADR-NNNN`, numéro suivant, jamais réutilisé | `ADR-0039` |

## 3. Commentaires

1. En tête de chaque paquet et de chaque type ou fonction exporté : **pourquoi**, et **ce que ça ne garantit pas**. Ne paraphrase pas le code.
2. Un commentaire qui s'appuie sur une décision cite l'ADR par son numéro.
3. Écris comme le code qui t'entoure : même densité de commentaires, même idiome.

## 4. Taille et forme du changement

4. Édite l'existant avant de créer ; un fichier nouveau a un rôle propre.
5. Le plus petit changement qui tient l'invariant ; pas de refactoring opportuniste hors du sujet, pas de code mort, pas de généralisation « au cas où ».
6. Formate uniquement les fichiers que tu modifies (`gofmt` pour Go).
