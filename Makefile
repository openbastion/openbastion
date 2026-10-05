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
test-postgres:
	@if [ -z "$$TEST_DATABASE_URL" ]; then \
		echo "TEST_DATABASE_URL non défini — voir NOTES_SANDBOX.md"; exit 1; \
	fi
	$(GO) test ./services/vault/password-vault/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./test/integration/... -run TestPostgresFlow -v -count=1 -timeout=30s

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
