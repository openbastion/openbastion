# settings — préférences de travail de l'agent

Ces réglages décrivent **comment** tu travailles par défaut. Ils s'appliquent tant que l'utilisateur ne demande pas autre chose pour la tâche en cours ; une demande explicite de l'utilisateur l'emporte sur un réglage (jamais sur une policy).

---

## 1. Communication

| Réglage | Valeur |
|---|---|
| Langue des réponses et de la documentation | français |
| Langue du code, des commentaires, des tests | anglais |
| Verbosité des réponses | **concise** : résultat d'abord, détail seulement s'il aide à décider ou à reprendre |
| Verbosité des messages de progression | une phrase quand l'utilisateur n'a pas eu de nouvelles depuis un moment ; jamais un message par outil |
| Format du rapport final | BLUF → preuves chiffrées → choix renversables → limites → une prochaine étape (`rules.md` §10) |
| Ton | professionnel, direct, sans flatterie, sans émojis |
| « Continuer », « Go », « Go pour la prochaine étape » | enchaîne sur l'étape logique suivante **sans redemander** ; marque tes choix renversables |

## 2. Autonomie

| Réglage | Valeur |
|---|---|
| Niveau d'autonomie | **élevé** : explore, conçois, implémente, teste, documente, commite, pousse |
| Quand s'arrêter pour demander | uniquement les cas de `policies.md` §5 (irréversible **et** ambigu, ou affaiblissement d'une garantie) |
| Si l'utilisateur est absent | prends la lecture la plus raisonnable, dis-la en tête de ton travail, continue ; ne tranche pas l'irréversible |
| Ordre de travail pour une fonctionnalité | **conception avant code** : ADR et contrats d'abord, puis domaine → application → infrastructure → interfaces, puis tests, documentation, vérification |
| Gestion des tâches | liste de tâches pour tout travail de plus de deux étapes ; dernière étape = « vérifier le travail » ; ne marque terminé que ce qui est vérifié |

## 3. Écriture du code

| Réglage | Valeur |
|---|---|
| Mode d'écriture | **éditer l'existant** avant de créer ; crée un fichier seulement s'il a un rôle propre |
| Taille du changement | le plus petit changement qui tient l'invariant ; pas de refactoring opportuniste hors du sujet |
| Commentaires | le pourquoi et les limites, pas le quoi |
| Formatage | `gofmt` sur les fichiers modifiés seulement |
| Documentation | mise à jour dans le même commit que le code (`rules.md` §7) |
| Choix de conception ambigu et sans enjeu | tranche, note-le comme renversable |

## 4. Dépendances

| Réglage | Valeur |
|---|---|
| Politique | stdlib d'abord ; `pkg/mtls` stdlib seulement |
| Ajout d'une dépendance | demande (`policies.md` §4) après avoir vérifié qu'elle se résout dans le sandbox |
| Résolution | `GOPROXY=direct` ; `go.sum` committé ; ne retire pas les `replace` vers `github.com/golang/*` |
| Mise à jour de versions | seulement si la tâche l'exige ; jamais en masse |

## 5. Vérification

| Réglage | Valeur |
|---|---|
| Avant tout commit | `make build vet` + tests des modules touchés ; avant un jalon : `make build vet test test-integration test-postgres` |
| Race detector | `go test -race` sur les modules modifiés avant un jalon |
| Tests PostgreSQL | exécute-les avec une vraie base (voir §7) ; compte les tests avec et sans |
| Contre-épreuves | pour chaque garantie de sécurité nouvelle (`rules.md` §6.4) |
| Chiffres dans la documentation | mesurés dans la session, jamais recopiés de mémoire |

## 6. Git et livraison

| Réglage | Valeur |
|---|---|
| Branche | `main` |
| Rythme | un commit cohérent et vérifié par incrément, **poussé immédiatement** (consigne permanente de l'utilisateur) |
| Message | `rules.md` §9 |
| Livrable après un jalon | archive zip sans `.git` ni `node_modules` ni clés, livrée à l'utilisateur ; chemin gardé dans `/tmp/claude-0/last_zip.txt` |
| Commande d'archive | `cd /home/claude && zip -qr "$Z" openbastion -x "openbastion/.git/*" "*/node_modules/*"` avec `Z=/mnt/user-data/outputs/openbastion-checkpoint-<AAAAMMJJ-HHMMSS>.zip` |

## 7. Environnement (sandbox cloud connu — vérifie avant de supposer ailleurs)

```sh
cd /home/claude/openbastion                       # toujours, le répertoire courant peut changer
export GOWORK=/home/claude/openbastion/go.work GOPROXY=direct

# PostgreSQL s'arrête entre deux tours : le redémarrer et remettre le mot de passe du rôle
service postgresql start && sudo -u postgres psql -c "ALTER ROLE openbastion WITH PASSWORD 'openbastion';"
export TEST_DATABASE_URL="postgres://openbastion:openbastion@127.0.0.1:5432/openbastion?sslmode=disable"

# avant une suite PostgreSQL complète (make test-postgres le fait seul)
psql "$TEST_DATABASE_URL" -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, sessions, audit_events RESTART IDENTITY CASCADE;"
```

Si tu ajoutes une table, ajoute-la à ce `TRUNCATE` **et** à celui du `Makefile`.

**Autre environnement constaté (codespace `/workspaces/openbastion`, Go 1.27, `GOPATH=/go`)** : pas de service PostgreSQL, mais Docker et `psql` sont là. Une base de test locale équivalente :

```sh
docker start obpg 2>/dev/null || docker run -d --name obpg -e POSTGRES_USER=openbastion -e POSTGRES_PASSWORD=openbastion \
  -e POSTGRES_DB=openbastion -p 127.0.0.1:5432:5432 postgres:16
export GOWORK=$PWD/go.work TEST_DATABASE_URL="postgres://openbastion:openbastion@127.0.0.1:5432/openbastion?sslmode=disable"
```

Le cache de modules y est vide au départ : `make build` le remplit (les tests d'intégration compilent avec `GOPROXY=off`).

Réseau : accès restreint à une liste de domaines (registres de paquets, GitHub). Un refus se constate et se rapporte ; ne le contourne pas (`policies.md` §4.3).

## 8. Comptage et rapport des tests

- Compte = `go test -v … | grep -c '^--- PASS'` (tests de premier niveau), avec et sans `TEST_DATABASE_URL`.
- Rapporte : unitaires (passés / ignorés sans base), intégration (idem), PostgreSQL dédiés, `-race`, `gofmt`, nombre de mutations tuées.
