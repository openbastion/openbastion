# Vérification complète (avant un jalon)

> Workflow : un ordre de travail. Les portes : `settings/quality-gates.yaml` ; l'environnement : `settings/environments/local.yaml`.

```sh
export GOWORK=$PWD/go.work
export TEST_DATABASE_URL="postgres://openbastion:openbastion@127.0.0.1:5432/openbastion?sslmode=disable"
T="TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, oidc_login_attempts, sessions, audit_events, alert_outbox, mfa_challenges, mfa_enrollment_codes, mfa_webauthn_credentials RESTART IDENTITY CASCADE;"

make build vet
(unset TEST_DATABASE_URL; go test -v <modules> -count=1)                      # unitaires sans base
psql "$TEST_DATABASE_URL" -q -c "$T"; go test -v <modules> -count=1           # unitaires avec base
make test-postgres                                                            # se purge lui-même
(unset TEST_DATABASE_URL; go test -v ./test/integration/... -count=1 -timeout=900s)
psql "$TEST_DATABASE_URL" -q -c "$T"; go test -v ./test/integration/... -count=1 -timeout=900s
go test -race -count=1 <modules touchés>
make ui-test ui-build
(git diff --name-only; git ls-files --others --exclude-standard) | grep '\.go$' | xargs gofmt -l   # doit ne rien afficher
```

`<modules>` : la liste de modules du `Makefile` (les motifs `./...` ne traversent pas le `go.work`). Lance les suites longues en arrière-plan, sortie dans un fichier. Puis compte (`grep -c '^--- PASS'`) et reporte dans `NOTES_SANDBOX.md` et le rapport. Le test Compose : `../devsecops/compose-test.md`.
