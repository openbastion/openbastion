GO ?= go
export GOWORK := $(CURDIR)/go.work
# golang.org/x/crypto, golang.org/x/sys, github.com/lib/pq — voir
# NOTES_SANDBOX.md. GOPROXY=direct fonctionne dans tout environnement ;
# go.sum est committé.
export GOPROXY := direct
export GOFLAGS :=

## Transport interne (ADR-0010). Par défaut : mTLS requis — chaque service lit son
## identité dans $(PKI_DIR) (voir `make pki`). `make run-X INTERNAL_TLS=disabled`
## lance sans certificats, en HTTP clair : développement uniquement, annoncé en
## avertissement par chaque service.
INTERNAL_TLS ?= required
PKI_DIR ?= .pki
ifeq ($(INTERNAL_TLS),disabled)
SCHEME := http
tls = INTERNAL_TLS=disabled
else
SCHEME := https
tls = INTERNAL_TLS=$(INTERNAL_TLS) TLS_CERT_FILE=$(PKI_DIR)/$(1)/cert.pem TLS_KEY_FILE=$(PKI_DIR)/$(1)/key.pem TLS_CA_FILE=$(PKI_DIR)/ca.pem
endif

.PHONY: build test test-integration test-postgres test-compose ui-build ui-test ui-icons vet pki run-vault run-audit run-authorization run-authentication run-broker run-ssh-proxy run-recorder run-gateway clean

## Compile tous les modules actuellement implémentés.
build:
	$(GO) build \
		./pkg/proxycore/... \
		./pkg/mtls/... \
		./cli/openbastion-cli/... \
		./pkg/migrate/... \
		./pkg/refusalbudget/... \
		./pkg/webhook/... \
		./pkg/hostkey/... \
		./services/access/api-gateway/... \
		./services/access/authentication/... \
		./services/access/authorization/... \
		./services/access/session-broker/... \
		./services/proxy/ssh-proxy/... \
		./services/vault/password-vault/... \
		./services/recording-audit/audit-service/... \
		./services/recording-audit/command-recorder/...

## go vet sur tous les modules.
vet:
	$(GO) vet ./pkg/proxycore/...
	$(GO) vet ./pkg/mtls/...
	$(GO) vet ./cli/openbastion-cli/...
	$(GO) vet ./pkg/migrate/...
	$(GO) vet ./pkg/refusalbudget/...
	$(GO) vet ./pkg/webhook/...
	$(GO) vet ./pkg/hostkey/...
	$(GO) vet ./services/access/api-gateway/...
	$(GO) vet ./services/access/authentication/...
	$(GO) vet ./services/access/authorization/...
	$(GO) vet ./services/access/session-broker/...
	$(GO) vet ./services/proxy/ssh-proxy/...
	$(GO) vet ./services/vault/password-vault/...
	$(GO) vet ./services/recording-audit/audit-service/...
	$(GO) vet ./services/recording-audit/command-recorder/...
	$(GO) vet ./test/integration/...

## Tests unitaires de tous les services. Hermétique : les tests
## PostgreSQL-dépendants (postgres_store_test.go) se SKIP automatiquement
## sans TEST_DATABASE_URL.
test:
	$(GO) test \
		./pkg/proxycore/... \
		./pkg/mtls/... \
		./cli/openbastion-cli/... \
		./pkg/migrate/... \
		./pkg/refusalbudget/... \
		./pkg/webhook/... \
		./pkg/hostkey/... \
		./services/access/api-gateway/... \
		./services/access/authentication/... \
		./services/access/authorization/... \
		./services/access/session-broker/... \
		./services/proxy/ssh-proxy/... \
		./services/vault/password-vault/... \
		./services/recording-audit/audit-service/... \
		./services/recording-audit/command-recorder/... \
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
## - recording_flow_test.go : HUIT processus — session SSH interactive
##                            réelle (Entrée = '\r', mot de passe sudo
##                            saisi), replay relu par un auditeur via la
##                            Gateway, RBAC et pagination vérifiés
## - record_or_refuse_test.go : HUIT processus — ADR-0008 : une panne du
##                            Command Recorder refuse la session (503), une
##                            commande non enregistrée n'atteint jamais la
##                            cible, la reprise fonctionne ; un proxy sans
##                            RECORDER_URL refuse de démarrer
## - breakglass_flow_test.go : ADR-0009 sur des processus réels — une
##                            session dérogée vit recorder arrêté, la
##                            dérogation est auditée avant le credential,
##                            une session ordinaire reste refusée, la
##                            coupure à l'échéance est faite par le proxy
## - breakglass_approval_test.go : ADR-0011 — HUIT processus : une demande
##                            break-glass attend, l'auto-approbation est
##                            refusée, une autre personne approuve, seul le
##                            demandeur se connecte ; refus de démarrer sur
##                            une valeur illisible
## - breakglass_discovery_test.go : ADR-0012 — CINQ processus : l'approbateur
##                            trouve la demande par GET /sessions?status=
##                            pending_approval, le webhook est prévenu ; puis
##                            il refuse, bloque, disparaît sans rien changer
##                            à la demande ni à la décision ; refus de
##                            démarrer sur une URL inutilisable
## - mtls_flow_test.go     : ADR-0010 — HUIT processus sous mTLS requis : le
##                            parcours complet, 27 appels forgés par une
##                            identité valide mais fausse arrêtés à la porte,
##                            jeton de scope volé inutilisable, imposteur du
##                            Vault qui ne reçoit rien
## - mtls_lifecycle_test.go : ADR-0010 — rotation d'un certificat et
##                            remplacement de l'autorité sur un processus
##                            vivant ; refus de démarrer sans identité propre
## - postgres_flow_test.go  : SKIP sans TEST_DATABASE_URL — voir
##                            `make test-postgres`
test-integration:
	$(GO) test ./test/integration/... -v -count=1 -timeout=300s

## L'Admin UI (web/admin-ui, ADR-0036) : dépendances depuis le lockfile, tests, construction.
ui-icons:
	cd web/openbastion-icons && npm ci --no-audit --no-fund && npm run build
ui-test: ui-icons
	cd web/admin-ui && npm ci --no-audit --no-fund && npm test
ui-build: ui-icons
	cd web/admin-ui && npm ci --no-audit --no-fund && npm run build

## Construit et démarre la pile docker-compose réelle (deploy/docker-compose, ADR-0033) et
## y joue le parcours du MVP sur les seuls ports publiés. Docker requis ; quelques minutes.
test-compose:
	COMPOSE_TEST=1 $(GO) test ./test/integration/ -run TestCompose -v -count=1 -timeout=900s

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
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, oidc_login_attempts, sessions, audit_events RESTART IDENTITY CASCADE;"
	$(GO) test ./services/vault/password-vault/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/authorization/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/authentication/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/session-broker/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/recording-audit/audit-service/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/recording-audit/command-recorder/internal/infrastructure/... -run TestPostgres -v -count=1
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, oidc_login_attempts, sessions, audit_events RESTART IDENTITY CASCADE;"
	$(GO) test ./test/integration/... -run TestPostgresFlow -v -count=1 -timeout=300s

## Crée, dans $(PKI_DIR), une autorité et l'identité de chaque service (ADR-0010).
## Pour le développement et les petits déploiements ; en production, l'émission est
## celle de l'organisation, avec la même forme d'identité (docs/administration/ §PKI).
## Relancer renouvelle les certificats (7 jours) et conserve l'autorité : les services
## en cours les reprennent sans redémarrage. $(PKI_DIR) est ignoré par git.
pki:
	$(GO) run ./pkg/mtls/cmd/openbastion-pki all -dir $(PKI_DIR)

## Lance chaque service en local (ports par défaut : voir chaque cmd/main.go).
## Sous mTLS (défaut), lancer d'abord `make pki`.
run-vault:
	$(call tls,password-vault) $(GO) run ./services/vault/password-vault/cmd/password-vault
run-audit:
	$(call tls,audit-service) $(GO) run ./services/recording-audit/audit-service/cmd/audit-service
run-authorization:
	$(call tls,authorization) $(GO) run ./services/access/authorization/cmd/authorization
run-authentication:
	$(call tls,authentication) $(GO) run ./services/access/authentication/cmd/authentication
# RECORDING_POLICY vaut « required » par défaut (ADR-0008) : sans RECORDER_URL, le proxy refuse de démarrer.
# « best-effort » (développement uniquement) doit être demandé explicitement.
# BREAKGLASS_ENABLED=true autorise ce proxy à honorer un break-glass (ADR-0009), voir run-broker.
# Sous mTLS, l'identité du proxy est celle de son certificat : ne pas fixer PROXY_SERVICE_ID.
run-ssh-proxy:
	$(call tls,ssh-proxy) RECORDER_URL=$(SCHEME)://127.0.0.1:8087 \
		$(GO) run ./services/proxy/ssh-proxy/cmd/ssh-proxy
run-recorder:
	$(call tls,command-recorder) AUTHORIZATION_URL=$(SCHEME)://127.0.0.1:8083 AUDIT_URL=$(SCHEME)://127.0.0.1:8082 \
		$(GO) run ./services/recording-audit/command-recorder/cmd/command-recorder
# BREAKGLASS_MAX_MINUTES=30 active le break-glass (ADR-0009) ; absent ou 0 : désactivé.
# Une demande break-glass attend l'accord d'une autre personne (ADR-0011) :
# BREAKGLASS_APPROVAL=required (défaut) | disabled (mode faible, annoncé),
# BREAKGLASS_APPROVAL_WINDOW_MINUTES=15 (défaut, 1 à 1440).
# BREAKGLASS_NOTIFY_URL=https://… prévient un canal (webhook) des demandes break-glass
# (ADR-0012) ; absent : aucune notification. L'URL est un SECRET : jamais journalisée.
# https exigé, sauf vers une adresse de boucle locale (développement).
# BREAKGLASS_MAX_PENDING_PER_REQUESTER=3 (défaut, 1 à 100) : demandes break-glass en attente
# par demandeur ; au-delà, 429 (ADR-0013). Pas de valeur « illimité ».
# BREAKGLASS_NOTIFY_SECRET=$$(openssl rand -hex 32) signe le webhook (X-OpenBastion-Signature) ;
# 32 octets au moins, et seulement avec BREAKGLASS_NOTIFY_URL. Jamais journalisé.
# SESSION_READ_AUDIT_BURST (défaut 10, de 1 à 1000) et SESSION_READ_AUDIT_RATE_PER_MINUTE
# (défaut 6, de 1 à 600) bornent ce que les refus de lecture d'une session écrivent à l'audit,
# PAR UTILISATEUR et par processus (ADR-0020) ; le refus, lui, est le même. Pas de valeur
# « illimité » ni « désactivé » : une valeur invalide arrête le Broker.
run-broker:
	$(call tls,session-broker) \
		$(GO) run ./services/access/session-broker/cmd/session-broker
# Le listener public de la Gateway reste en HTTP (le TLS se termine à l'arête) ;
# elle a une identité pour ses appels sortants.
# SESSION_REQUEST_BURST (défaut 10, de 1 à 1000) et SESSION_REQUEST_RATE_PER_MINUTE (défaut 6,
# de 1 à 600) règlent le budget de POST /sessions PAR UTILISATEUR, par processus (ADR-0014) ;
# une valeur invalide arrête la Gateway. Pas de valeur « illimité ».
# SESSION_ACTION_BURST (défaut 10, de 1 à 1000) et SESSION_ACTION_RATE_PER_MINUTE (défaut 6,
# de 1 à 600) règlent le budget, par utilisateur et par processus, de approve, reject,
# connect et terminate (DELETE /sessions/{id}) — un seul seau pour les quatre, distinct du
# précédent (ADR-0016, ADR-0017).
# Les limites PAR ADRESSE (login : CLIENT_LOGIN_BURST 5 / CLIENT_LOGIN_RATE_PER_MINUTE 1 ;
# requêtes authentifiées : CLIENT_REQUEST_BURST 60 / CLIENT_REQUEST_RATE_PER_MINUTE 60) ont
# ces défauts-là, réglables, jamais « illimités ». Derrière un reverse proxy, TRUSTED_PROXY_CIDRS
# (adresses ou réseaux CIDR, séparés par des virgules) déclare qui peut dire quel est le client
# par X-Forwarded-For ; absente : personne, l'adresse du pair fait foi (ADR-0015). 0.0.0.0/0 et
# les valeurs douteuses arrêtent la Gateway.
run-gateway:
	$(call tls,api-gateway) COMMAND_RECORDER_URL=$(SCHEME)://127.0.0.1:8087 \
		$(GO) run ./services/access/api-gateway/cmd/api-gateway

clean:
	$(GO) clean -cache -testcache
