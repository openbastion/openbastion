# rules — normes de code, de test, de documentation et de réponse

Applique ces règles à chaque ligne que tu écris. Quand une règle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies.md`.

---

## 1. Langues

| Quoi | Langue |
|---|---|
| Identifiants, noms de fichiers, noms de tests, commentaires de code, messages d'erreur et de log | **Anglais** |
| Documentation (`docs/`, `README`, `NOTES_SANDBOX.md`, ADR), sujets et corps de commit, rapports à l'utilisateur, commentaires explicatifs dans `go.mod`/`Makefile` | **Français** |
| Termes techniques établis (fail-closed, deny-by-default, scope, replay, break-glass…) | Gardés tels quels, sans les traduire |

## 2. Go

1. Version `go 1.22` dans chaque `go.mod`. Code formaté par `gofmt` ; `go vet` propre. **Formate uniquement les fichiers que tu modifies** (jamais `gofmt -w` sur un dossier : `policies.md` §3).
2. **Bibliothèque standard d'abord.** Pas de framework web, pas de bibliothèque d'injection, pas de mock framework : des interfaces étroites et des fakes écrits à la main.
3. Interfaces **petites**, définies côté consommateur (dans `domain/` pour les ports). Un port n'expose que ce dont le cas d'usage a besoin — l'absence d'une méthode peut être une garantie de sécurité (`VaultAuthorizer` n'a pas de méthode de lecture de credential).
4. `context.Context` en premier paramètre de toute opération qui peut bloquer ou appeler le réseau ; jamais stocké dans une struct.
5. Erreurs : renvoie-les, ne les avale pas ; encapsule avec `fmt.Errorf("verbe + objet: %w", err)` ; messages en minuscules, sans point final ; erreurs sentinelles (`ErrX`) dans `domain` pour ce que l'appelant doit distinguer (`errors.Is`). **Ne fais jamais remonter à un client une erreur interne brute** (adresse, SQL, chemin de fichier) : journalise la cause, réponds une phrase générique.
6. Concurrence : tout état partagé est protégé ou confiné ; teste avec `-race` ce que tu touches. Pas de goroutine sans condition d'arrêt claire.
7. Pas de variable globale mutable, pas d'`init()` à effet de bord, pas de `panic` hors erreur de programmation détectée au démarrage (ex. table de règles mal formée).
8. Commentaires : en tête de chaque paquet et de chaque type/fonction exportée, dis **pourquoi** et **ce que ça ne garantit pas**. Ne paraphrase pas le code. Un commentaire qui cite un ADR le fait par son numéro.

## 3. Nommage

| Élément | Convention | Exemple |
|---|---|---|
| Paquets | un mot, minuscule | `domain`, `sshcodec`, `mtls` |
| Fichiers | `snake_case.go` ; tests `*_test.go` à côté du code | `session_broker_service.go`, `callers_test.go` |
| Types/fonctions exportés | `PascalCase`, nom = rôle | `SessionBrokerService`, `CheckAccess` |
| Ports | nom du rôle, suffixe `er` ou `Repository` si pertinent | `SessionRepository`, `VaultAuthorizer` |
| Adaptateurs | `<Technologie><Rôle>` | `PostgresStore`, `InMemoryStore`, `AuditHTTPClient` |
| Variables d'environnement | `UPPER_SNAKE_CASE`, préfixe par domaine | `BREAKGLASS_MAX_MINUTES`, `TLS_CERT_FILE` |
| Ressources RBAC | `<domaine>:<type>:<id ou *>` | `vault:account:acc_1`, `breakglass:account:acc_1`, `breakglass-approve:account:acc_1` |
| Actions d'audit | `<objet>.<événement>` en minuscules | `session.breakglass`, `session.breakglass_requested`, `session.recording_lost` |
| Tests | `Test<Sujet>_<Comportement>` (underscores) | `TestCheckAccess_DeniesByDefaultWithNoPolicy` |
| Tests d'intégration | `Test<Fonction>_<Comportement>_<Portée>` | `…_AcrossEightRealProcesses` |
| ADR | `ADR-NNNN`, numéro suivant, jamais réutilisé | `ADR-0015` |
| Commits | voir §9 | |

## 4. HTTP/JSON interne et public

1. Les noms de champs JSON d'une route interne **reprennent ceux du `proto`** (`snake_case`, ex. `fetch-credential`) ; les routes d'administration relayées par le Gateway gardent la forme de l'OpenAPI du doc 05 (`camelCase`, ex. `onboard-account`). Les routes publiques suivent l'OpenAPI. **Ne renomme jamais un champ existant** (contrat additif). La traduction public → interne se fait dans le Gateway, nulle part ailleurs.
2. Codes de statut **honnêtes** : `400` entrée invalide, `401` non authentifié, `403` interdit, `404` introuvable, `409` conflit d'état, `503` dépendance indisponible. Ne fais pas mentir un code : un `403` qui masque une panne de base est un défaut. **Exception voulue** : un refus d'accès renvoie le même `403` que la ressource existe ou non (pas d'oracle d'existence).
3. Toute route interne a une entrée dans `CallerRules()` **et** un cas dans `callers_test.go` (appelants autorisés ; au moins un appelant refusé ; route inconnue refusée).
4. Borne la taille des corps (`http.MaxBytesReader`), n'accepte que les méthodes attendues, et ne divulgue aucun secret ni détail interne dans les réponses.
5. Ne relis jamais l'identité de l'appelant dans le corps : `mtls.CallerFrom(ctx)` (service) ou l'identité injectée par le Gateway après vérification du jeton (utilisateur).

## 5. Sécurité dans le code

- Comparaisons de secrets en temps constant (`subtle.ConstantTimeCompare`) ; aléa par `crypto/rand` ; AES-256-GCM pour le chiffrement au repos (nonce unique, données associées liant l'identifiant et l'horodatage) ; Argon2id pour les mots de passe.
- Un secret en mémoire est **purgé** après usage ; il n'est jamais journalisé ni mis dans une erreur.
- Audit **fail-closed** : l'action qui doit être auditée n'a lieu que si l'événement a été écrit — ou l'événement est écrit **avant** l'action quand la dérogation en dépend (cf. `session.breakglass`).
- Une garantie de sécurité vit **dans un type ou dans une règle vérifiée par le compilateur/les tests** autant que possible, pas dans une convention (preuve à champs non exportés, port sans méthode dangereuse).
- Variable de configuration de sécurité : `required` par défaut ; valeur inconnue = erreur fatale au démarrage ; le mode faible s'annonce par un avertissement.

## 6. Tests

1. **Chaque comportement a un test ; chaque garantie de sécurité a un test d'attaque et une contre-épreuve.** Teste le cas heureux, le refus, le cas limite, et l'attaque.
2. Niveaux : unitaire (à côté du code, hermétique) ; PostgreSQL (`TEST_DATABASE_URL`, **se skippe** sans base) ; intégration sur **processus réels** (`test/integration/`, binaires compilés par le test, ports `18xxx`).
3. Ports d'intégration : réserve un bloc libre — `grep -ohE '18[0-9]{3}' test/integration/*.go | sort -u` — et ne réutilise pas un port d'un autre fichier. Les flux hors mTLS tournent avec `INTERNAL_TLS=disabled` (déjà dans `buildEnv`) ; le mTLS a ses propres fichiers (`mtls_*_test.go`).
4. **Contre-épreuve (mutation)** : pour chaque garantie nouvelle, introduis la faute qu'elle prévient, lance le test, vérifie qu'il **échoue**, restaure. Sauvegarde le fichier sous un **nom unique par fichier et par mutation**, restaure depuis cette copie, vérifie avec `cmp`. (Une sauvegarde partagée entre deux `main.go` a déjà écrasé un fichier.) Consigne le nombre de mutations tuées.
5. Une assertion **négative** (« rien ne s'est produit ») attend d'abord que le système ait eu le temps d'agir : utilise l'aide `settle()` / `waitUntil`, jamais un `Sleep` nu arbitraire dans une assertion positive.
6. Pas de test fragile : pas de dépendance à l'heure murale sans horloge injectable, pas d'ordre de map, pas de port codé en dur partagé.
7. **Compter les tests** : nombre de fonctions de premier niveau = `go test -v … | grep -c '^--- PASS'` (les sous-tests ne comptent pas). Compte avec et sans `TEST_DATABASE_URL` ; n'écris dans un document que des nombres que tu viens de mesurer.
8. Les tests PostgreSQL partagent une base : purge-la (`TRUNCATE … RESTART IDENTITY CASCADE`) avant chaque suite complète ; `make test-postgres` le fait seul.

## 7. Documentation

1. **ADR** (dans `docs/architecture/OpenBastion_03_ADR.md`) : gabarit `Contexte / Décision / Conséquences / Alternatives envisagées`, ligne dans l'index (§2 du document), statut. Les conséquences distinguent `(+)` et `(−)` ; **les limites sont écrites, pas cachées**. Une décision rejetée y figure avec son motif.
2. Pour toute fonctionnalité : documente **ce qu'elle fait et ce qu'elle ne fait pas** (section « Ce que X ne fait PAS » dans `NOTES_SANDBOX.md`), les choix que l'utilisateur peut renverser, les risques résiduels.
3. Mets à jour dans le **même commit** que le code : l'ADR, `NOTES_SANDBOX.md` (section + état des tests), le Guide Sécurité (§12 limites), le guide Administrateur (configuration, dépannage), le Guide HA/PRA si la disponibilité ou la reprise change, le Guide Développeur si le geste du développeur change, l'OpenAPI (doc 05) et les interfaces (doc 07) si un contrat change, le `README`, `architecture.md`.
4. Mermaid pour les diagrammes ; tableaux pour les comparaisons ; YAML des documents validé avec `python3 -I` + `yaml.safe_load` quand tu en modifies.
5. Un fait documenté (port, nom de variable, comportement) doit être **vérifiable dans le code** ; vérifie avant d'écrire.

## 8. Modules Go et dépendances locales

- Un module par composant, déclaré dans `go.work`. Un module qui importe `pkg/proxycore` ou `pkg/mtls` déclare `require … v0.0.0` **et** un `replace` explicite vers le chemin relatif (`../../../pkg/mtls`) avec un commentaire en français : en mode workspace, un module qui a aussi des dépendances externes sous `replace` ne résout pas les locaux sans lui.
- Les patterns `./services/...` **ne traversent pas** les modules du `go.work` : le `Makefile` liste les modules un par un. Quand tu crées un module, ajoute-le à `go.work`, aux listes `build`/`vet`/`test` du `Makefile`, et aux `require`/`replace` nécessaires.

## 9. Commits

```
type(portée): sujet à l'indicatif, en français, sans point final

Corps : le pourquoi, ce qui change, ce qui est prouvé, ce qui reste (limites).
Une ligne par idée, pas de récit des essais.

Co-Authored-By: …
Claude-Session: …
```

`type` ∈ `feat`, `fix`, `docs`, `test`, `refactor`, `chore`. `portée` = composant(s) (`mtls`, `session-broker`, `vault`…). Un commit par incrément **cohérent et vérifié** ; ne mélange pas deux sujets.

## 10. Format des réponses à l'utilisateur

1. **BLUF** : première phrase = le résultat. Puis ce qui a été prouvé (chiffres mesurés), puis **les choix que l'utilisateur peut renverser**, puis les **limites restantes**, puis **une** prochaine étape.
2. Prose concise ; une liste seulement quand le lecteur compare ou parcourt. Pas de récit chronologique, pas de recopie du code, pas d'émojis.
3. Les fichiers produits sont **livrés** (`SendUserFile`) ; ne colle pas un fichier dans la conversation.
4. Quand tu travailles longtemps, signale en une phrase ce que tu fais (`SendUserMessage`) ; ne commente pas chaque appel d'outil.
