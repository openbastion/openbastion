GO ?= go
export GOWORK := $(CURDIR)/go.work
# golang.org/x/crypto, golang.org/x/sys, github.com/lib/pq — voir
# NOTES_SANDBOX.md. GOPROXY=direct fonctionne dans tout environnement ;
# go.sum est committé.
export GOPROXY := direct
export GOFLAGS :=

.PHONY: build test test-integration test-postgres vet run-vault run-audit run-authorization run-authentication run-broker run-ssh-proxy run-gateway clean

## Compile tous les modules actuellement implémentés.
build:
	$(GO) build \
		./pkg/proxycore/... \
		./services/access/api-gateway/... \
		./services/access/authentication/... \
		./services/access/authorization/... \
		./services/access/session-broker/... \
		./services/proxy/ssh-proxy/... \
		./services/vault/password-vault/... \
		./services/recording-audit/audit-service/...

## go vet sur tous les modules.
vet:
	$(GO) vet ./pkg/proxycore/...
	$(GO) vet ./services/access/api-gateway/...
	$(GO) vet ./services/access/authentication/...
	$(GO) vet ./services/access/authorization/...
	$(GO) vet ./services/access/session-broker/...
	$(GO) vet ./services/proxy/ssh-proxy/...
	$(GO) vet ./services/vault/password-vault/...
	$(GO) vet ./services/recording-audit/audit-service/...
	$(GO) vet ./test/integration/...

## Tests unitaires de tous les services. Hermétique : les tests
## PostgreSQL-dépendants (postgres_store_test.go) se SKIP automatiquement
## sans TEST_DATABASE_URL.
test:
	$(GO) test \
		./pkg/proxycore/... \
		./services/access/api-gateway/... \
		./services/access/authentication/... \
		./services/access/authorization/... \
		./services/access/session-broker/... \
		./services/proxy/ssh-proxy/... \
		./services/vault/password-vault/... \
		./services/recording-audit/audit-service/... \
		-count=1

## Tests d'intégration : compile et lance les services comme processus
## séparés, dialogue en HTTP (et en SSH réel) entre eux.
## - ssh_flow_test.go       : SSH Proxy (simulé) + Vault + Audit
## - broker_flow_test.go    : CINQ processus (Authorization, Session
##                            Broker, Vault, Audit, ssh-proxy)
## - gateway_flow_test.go   : SEPT processus, entièrement pilotés par la
##                            Gateway — login réel, injection d'identité
##                            vérifiée, vraie connexion SSH
## - admin_routes_test.go   : QUATRE processus — routage admin via la
##                            Gateway, refus RBAC réel avant toute
##                            politique, rotation auto vérifiée
## - postgres_flow_test.go  : SKIP sans TEST_DATABASE_URL — voir
##                            `make test-postgres`
test-integration:
	$(GO) test ./test/integration/... -v -count=1 -timeout=140s

## Lance les tests PostgreSQL réels (postgres_store_test.go +
## postgres_flow_test.go). Nécessite une base PostgreSQL accessible via
## TEST_DATABASE_URL (voir NOTES_SANDBOX.md pour comment elle a été
## mise en place et vérifiée dans ce sandbox).
##
## Purge la base avant CHAQUE phase, systématiquement — pas une
## suggestion dans la doc à exécuter à la main. Raison structurelle, pas
## cosmétique, et une seule purge en tête de cible ne suffit pas : les
## tests *_store_test.go ci-dessous écrivent eux-mêmes des lignes
## directement (policies, users, sessions...), et ils tournent avant
## postgres_flow_test.go dans cette même invocation. Or
## AuthorizationService.BootstrapAdminPolicy ne bootstrape "platform-admin"
## que sur un magasin de politiques entièrement vide, par conception
## (voir son commentaire de doc) — une seule ligne de policies laissée
## par TestPostgresStore_CreateThenForRoles_RoundTrips (ou n'importe quel
## autre test *_store_test.go écrivant dans `policies`) suffit à faire
## échouer TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart sur
## un 403 qui n'a rien à voir avec un vrai bug. D'où la seconde purge
## juste avant la ligne `test/integration`, pas seulement une au début.
test-postgres:
	@if [ -z "$$TEST_DATABASE_URL" ]; then \
		echo "TEST_DATABASE_URL non défini — voir NOTES_SANDBOX.md"; exit 1; \
	fi
	@command -v psql >/dev/null 2>&1 || { echo "psql introuvable — nécessaire pour purger la base avant les tests PostgreSQL (voir NOTES_SANDBOX.md)"; exit 1; }
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, sessions, audit_events RESTART IDENTITY CASCADE;"
	$(GO) test ./services/vault/password-vault/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/authorization/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/authentication/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/session-broker/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/recording-audit/audit-service/internal/infrastructure/... -run TestPostgres -v -count=1
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, sessions, audit_events RESTART IDENTITY CASCADE;"
	$(GO) test ./test/integration/... -run TestPostgresFlow -v -count=1 -timeout=60s

## Lance chaque service en local (ports par défaut : voir chaque cmd/main.go).
run-vault:
	$(GO) run ./services/vault/password-vault/cmd/password-vault
run-audit:
	$(GO) run ./services/recording-audit/audit-service/cmd/audit-service
run-authorization:
	$(GO) run ./services/access/authorization/cmd/authorization
run-authentication:
	$(GO) run ./services/access/authentication/cmd/authentication
run-ssh-proxy:
	VAULT_URL=http://127.0.0.1:8081 AUDIT_URL=http://127.0.0.1:8082 \
		$(GO) run ./services/proxy/ssh-proxy/cmd/ssh-proxy
run-broker:
	AUTHORIZATION_URL=http://127.0.0.1:8083 VAULT_URL=http://127.0.0.1:8081 AUDIT_URL=http://127.0.0.1:8082 SSH_PROXY_URL=http://127.0.0.1:8085 \
		$(GO) run ./services/access/session-broker/cmd/session-broker
run-gateway:
	AUTHENTICATION_URL=http://127.0.0.1:8086 SESSION_BROKER_URL=http://127.0.0.1:8084 VAULT_URL=http://127.0.0.1:8081 AUTHORIZATION_URL=http://127.0.0.1:8083 \
		$(GO) run ./services/access/api-gateway/cmd/api-gateway

clean:
	$(GO) clean -cache -testcache
