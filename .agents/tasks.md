# tasks — workflows types

Suis le workflow qui correspond à la demande. Un workflow est un **ordre de travail**, pas une liste de cases à cocher cosmétiques : saute une étape seulement si elle n'a objectivement pas lieu d'être, et dis-le. Les règles de forme sont dans `rules.md`, les limites dans `policies.md`.

---

## 0. Définition de « terminé » (commune à tous les workflows)

Un travail est terminé quand **tout** ce qui suit est vrai :

1. Le code compile (`make build`), `go vet` est propre, les fichiers modifiés sont `gofmt`-és.
2. Chaque comportement nouveau a un test ; chaque garantie de sécurité a un test d'attaque **et** une contre-épreuve réussie.
3. Les tests des modules touchés passent, `-race` propre, et les suites complètes passent avant un jalon.
4. La documentation est à jour **dans le même commit** (`rules.md` §7), les chiffres sont mesurés.
5. Les limites que ton travail laisse sont écrites (`NOTES_SANDBOX.md`, Guide Sécurité §12).
6. Le commit est fait **et poussé** ; aucun fichier sensible n'est inclus.
7. Le rapport à l'utilisateur suit `rules.md` §10.

---

## 1. Nouvelle fonctionnalité (surtout si elle touche la sécurité)

1. **Explorer** : lis le code existant concerné, les ADR liés, les docs 05/06/07 ; cherche ce qui existe déjà (ne réinvente pas). Fais la liste des invariants que la fonctionnalité touche.
2. **Concevoir avant de coder** : modèle d'attaque (qui peut abuser de quoi), contrats (OpenAPI, proto, tables), **ADR** (`Proposé`, puis `Accepté` si l'utilisateur a donné le go) avec les alternatives rejetées. Ne produis pas de code avant l'ADR.
3. **Tâches** : crée la liste (`settings.md` §2).
4. **Implémenter couche par couche** : domaine (entités, ports, erreurs) → application (cas d'usage) → infrastructure (magasin mémoire **et** PostgreSQL, clients) → interfaces (handlers, `callers.go`) → `main.go` (composition, variables d'environnement avec défaut strict).
5. **Tester** : unitaires par couche ; test de chaque verrou **isolément** (un verrou manquant ⇒ refus) ; PostgreSQL (aller-retour + mise à niveau sur place d'une table existante) ; **processus réels** pour le parcours complet et l'attaque.
6. **Contre-épreuves** : mutations sur chaque garantie (`rules.md` §6.4), consigne « N tuées ».
7. **Documenter** : ADR définitif, `NOTES_SANDBOX.md` (section + « Ce que ça ne fait PAS » + état des tests), Guide Sécurité §12, guide Administrateur, HA/PRA si pertinent, OpenAPI/doc 07, `README`, `architecture.md`, Makefile.
8. **Vérifier** : workflow §9.
9. **Livrer** : commit + push, archive, rapport.

## 2. Correction de bug

1. **Reproduire** : écris d'abord un test qui échoue pour la bonne raison. Pas de test rouge ⇒ pas de correctif.
2. **Trouver la cause**, pas le symptôme : lis le code en cause, vérifie les hypothèses par une mesure.
3. **Corriger au plus petit** : pas de refactoring opportuniste.
4. **Contre-épreuve** : annule le correctif, le test redevient rouge ; restaure.
5. **Chercher les jumeaux** : le même défaut existe-t-il ailleurs (autre service, autre route) ? Corrige-les ou consigne-les.
6. **Documenter** : si le bug trahissait une hypothèse fausse ou une limite, écris-la dans `NOTES_SANDBOX.md` (et barre toute limite que le correctif referme).
7. Commit `fix(portée): …`, push, rapport (cause, correctif, test, jumeaux).

## 3. Ajouter ou modifier une route interne

1. Définis le contrat (champs `proto`/OpenAPI, statut de chaque cas).
2. Implémente le cas d'usage et le handler ; l'identité de l'appelant vient de `mtls.CallerFrom(ctx)`.
3. Ajoute la règle dans `CallerRules()` (appelants **minimaux**) ; ajoute à `callers_test.go` : appelant autorisé passe, au moins un appelant refusé, route inconnue refusée.
4. Si la route est exposée par le Gateway : traduction public → interne dans le Gateway ; le Gateway **écrase** l'identité revendiquée.
5. Test d'intégration d'attaque : une identité valide **mais fausse** reçoit `403 forbidden` à la porte, et rien n'a eu lieu.
6. Mets à jour OpenAPI/doc 07, guide Administrateur (dépannage), `architecture.md` §5.

## 4. Modifier le schéma PostgreSQL

1. Reste **additif et idempotent** : `CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF NOT EXISTS … DEFAULT …` dans le même `InitSQL`.
2. Test PostgreSQL d'aller-retour de la nouvelle colonne/table **et** test de mise à niveau sur place d'une table créée avant ton changement.
3. Si une table est ajoutée : mets à jour les `TRUNCATE` (`Makefile`, `settings.md` §7) ; mets à jour le doc 06.
4. Lance la suite PostgreSQL avec une vraie base (`settings.md` §7), purgée avant.

## 5. Écrire un ADR

1. Numéro = suivant dans l'index du doc 03 ; ligne dans l'index ; section avant « Prochaine étape ».
2. **Contexte** : le problème réel, ce qui manque aujourd'hui, ce qui pousse à décider maintenant.
3. **Décision** : numérotée, précise, testable ; les défauts sont stricts.
4. **Conséquences** : `(+)` ce qui est prouvé (avec les nombres mesurés), `(−)` **toutes** les limites, y compris celles que tu aurais préféré ne pas écrire.
5. **Alternatives envisagées** : chaque option rejetée avec son motif.
6. Statut : `Accepté` seulement si l'utilisateur a donné le go ; sinon `Proposé`. Signale-le dans le rapport.
7. Pour remplacer une décision : nouvel ADR, ancien marqué `Remplacé par ADR-NNNN` ; ne réécris pas l'ancien.

## 6. Revue de sécurité d'un changement (ou d'un composant)

1. Dresse le modèle d'attaque : opérateur malveillant, service compromis, réseau hostile, base compromise.
2. Pour chaque entrée et chaque canal : qui l'appelle ? L'identité vient-elle d'une preuve (certificat, jeton vérifié) ou d'une déclaration ? Que se passe-t-il en cas de panne (fail-closed) ?
3. Écris un test par attaque plausible ; vérifie qu'il échoue sans la défense.
4. Cherche les canaux oubliés : logs, messages d'erreur, réponses d'erreur recopiées par le Gateway, arguments de commande, sauvegardes.
5. Classe les constats (bloquant / à corriger / limite acceptée), consigne les limites dans le Guide Sécurité §12.

## 7. Ajouter un protocole de proxy

1. Lis `architecture.md`, ADR-0006, doc 01 §4.2, et le guide Développeur §5. Le pipeline commun est dans `pkg/proxycore` : n'implémente que le **codec** du protocole.
2. Conçois la capture (commandes, fichiers, clipboard selon le protocole) et ce qui est enregistré / masqué ; ADR si c'est structurant.
3. Le proxy n'a **aucun accès direct** possible : la cible n'est atteinte qu'avec un credential obtenu par scope à usage unique auprès du Vault.
4. Tests : vrai protocole à trois participants (client, proxy, fausse cible qui rapporte ce qu'elle reçoit) ; enregistrer-ou-refuser ; expiration de session ; purge du secret.
5. Ajoute le service au `go.work`, au `Makefile`, aux tables d'appelants, au mTLS (`pki.StandardServices`).

## 8. Ajouter ou modifier une dépendance

1. **Demande** (`policies.md` §4.2) avec : besoin, licence, maintenance, alternative stdlib écartée, empreinte.
2. Vérifie qu'elle se résout dans le sandbox (`GOPROXY=direct`) avant de t'engager ; sinon propose le contournement connu (`replace` vers le miroir GitHub) ou l'alternative.
3. Un module à la fois ; `go.sum` régénéré par l'outil ; jamais dans `pkg/mtls`.

## 9. Vérification complète (avant un jalon)

```sh
cd /home/claude/openbastion && export GOWORK=$PWD/go.work GOPROXY=direct
service postgresql start && sudo -u postgres psql -c "ALTER ROLE openbastion WITH PASSWORD 'openbastion';"
export TEST_DATABASE_URL="postgres://openbastion:openbastion@127.0.0.1:5432/openbastion?sslmode=disable"

make build vet
(unset TEST_DATABASE_URL; make test; go test ./test/integration/... -count=1 -timeout=300s)   # sans base
T="TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, sessions, audit_events RESTART IDENTITY CASCADE;"
psql "$TEST_DATABASE_URL" -c "$T"
make test                                                                                      # avec base
make test-postgres                                                                             # se purge lui-même
psql "$TEST_DATABASE_URL" -c "$T"; go test ./test/integration/... -count=1 -timeout=300s       # intégration avec base
go test -race -count=1 <modules touchés>
(git diff --name-only; git ls-files --others --exclude-standard) | grep '\.go$' | xargs gofmt -l   # doit ne rien afficher
```

Puis compte les tests (`settings.md` §8) et reporte-les dans `NOTES_SANDBOX.md` et le rapport.

## 10. Jalon : commit, push, archive, rapport

1. `git status` : rien de sensible, rien d'inattendu.
2. Commit (`rules.md` §9), `git push origin main`.
3. Archive (`settings.md` §6), vérifie `unzip -l … | grep -c '\.pem'` = 0, **livre-la**.
4. Rapport (`rules.md` §10) : résultat, preuves mesurées, **choix renversables**, limites, **une** prochaine étape.

## 11. Reprise après une longue interruption

1. Relis `NOTES_SANDBOX.md` (sections récentes), `git log --oneline | head`, `git status`.
2. Remets l'environnement en route (`settings.md` §7) — PostgreSQL est probablement arrêté.
3. Relance `make build vet test` pour connaître l'état réel avant d'ajouter quoi que ce soit.
4. Ne te fie pas à un chiffre ou à une affirmation d'un résumé : revérifie ce dont ta tâche dépend.
