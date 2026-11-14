GO ?= go
export GOWORK := $(CURDIR)/go.work
# golang.org/x/crypto, golang.org/x/sys, github.com/lib/pq — voir
# NOTES_SANDBOX.md. GOPROXY=direct fonctionne dans tout environnement ;
# go.sum est committé.
export GOPROXY := direct
export GOFLAGS :=

## La version (ADR-0063) : VERSION est la source, en Semantic Versioning. Une construction est
## estampillée VERSION+<commit> ; une construction de release (la CI, sur un tag) passe
## BUILD_VERSION=$(VERSION). Lue par `openbastion-cli version --short` et la première ligne du journal
## de chaque service.
VERSION := $(shell cat VERSION)
GIT_SHA := $(shell git rev-parse --short=12 HEAD 2>/dev/null)
GIT_SHA_FULL := $(shell git rev-parse HEAD 2>/dev/null)
SOURCE_REPOSITORY ?= https://github.com/openbastion/openbastion
BUILD_VERSION ?= $(VERSION)$(if $(GIT_SHA),+$(GIT_SHA))
LDFLAGS := -X github.com/openbastion/openbastion/pkg/buildinfo.Version=$(BUILD_VERSION)

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

.PHONY: build version version-check test fuzz test-rdp-interop test-rdp-recording test-rdp-windows test-integration test-postgres test-compose vuln scan-images scan-postgres-image ui-build ui-test ui-icons ui-tokens-test vet pki proto-tools proto-gen proto-lint run-vault run-audit run-authorization run-authentication run-broker run-ssh-proxy run-rdp-vnc-proxy run-recorder run-video-recorder run-gateway clean license-check

## La version qu'une construction estampille ; et sa vérification : VERSION est une version
## sémantique, et sur un tag (TAG=vX.Y.Z, la CI le passe) le tag est v$(VERSION), sans pré-version.
version:
	@echo $(BUILD_VERSION)
version-check:
	$(GO) test ./pkg/buildinfo/... -count=1
	@if [ -n "$(TAG)" ]; then \
		[ "$(TAG)" = "v$(VERSION)" ] || { echo "le tag $(TAG) n'est pas v$(VERSION) (le fichier VERSION)"; exit 1; }; \
		case "$(VERSION)" in *-*|*+*) echo "le tag $(TAG) nomme une pré-version ou porte une métadonnée ($(VERSION)) : une release est X.Y.Z"; exit 1;; esac; \
		echo "le tag $(TAG) est la release $(VERSION)"; \
	fi

## Les contrats Protobuf ne sont pas générés dans git ; buf et les deux plugins doivent être installés.
BUF ?= buf
PROTOBUF_GO_VERSION := v1.36.4
PROTOBUF_GRPC_VERSION := v1.5.1
BUF_VERSION := v1.75.0
proto-tools:
	GOWORK=off $(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	GOWORK=off $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOBUF_GO_VERSION)
	GOWORK=off $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOBUF_GRPC_VERSION)
proto-gen:
	@command -v $(BUF) >/dev/null 2>&1 || { echo "buf introuvable — voir docs/development/prerequisites.md"; exit 1; }
	@command -v protoc-gen-go >/dev/null 2>&1 || { echo "protoc-gen-go introuvable — voir docs/development/prerequisites.md"; exit 1; }
	@command -v protoc-gen-go-grpc >/dev/null 2>&1 || { echo "protoc-gen-go-grpc introuvable — voir docs/development/prerequisites.md"; exit 1; }
	$(BUF) generate
proto-lint:
	$(BUF) lint

## Compile tous les modules actuellement implémentés, estampillés de leur version.
build: proto-gen
	$(GO) build -ldflags "$(LDFLAGS)" \
		./pkg/buildinfo/... \
		./pkg/command/... \
		./pkg/proxycore/... \
		./pkg/rdp/... \
		./pkg/vnc/... \
		./pkg/tlspin/... \
		./pkg/screenstream/... \
		./pkg/mtls/... \
		./pkg/mtls/cmd/openbastion-pki/... \
		./cli/openbastion-cli/... \
		./pkg/migrate/... \
		./pkg/refusalbudget/... \
		./pkg/webhook/... \
		./pkg/hostkey/... \
		./pkg/transit/... \
		./proto/... \
		./services/access/api-gateway/... \
		./services/access/authentication/... \
		./services/access/authorization/... \
		./services/access/session-broker/... \
		./services/proxy/ssh-proxy/... \
		./services/proxy/rdp-vnc-proxy/... \
		./services/vault/password-vault/... \
		./services/recording-audit/audit-service/... \
		./services/recording-audit/command-recorder/... \
		./services/recording-audit/video-recorder/...

## go vet sur tous les modules.
vet: proto-gen
	$(GO) vet ./pkg/proxycore/...
	$(GO) vet ./pkg/rdp/...
	$(GO) vet ./pkg/vnc/...
	$(GO) vet ./pkg/tlspin/...
	$(GO) vet ./pkg/screenstream/...
	$(GO) vet ./pkg/mtls/...
	$(GO) vet ./pkg/mtls/cmd/openbastion-pki/...
	$(GO) vet ./cli/openbastion-cli/...
	$(GO) vet ./pkg/migrate/...
	$(GO) vet ./pkg/refusalbudget/...
	$(GO) vet ./pkg/webhook/...
	$(GO) vet ./pkg/hostkey/...
	$(GO) vet ./pkg/transit/...
	$(GO) vet ./proto/...
	$(GO) vet ./pkg/buildinfo/...
	$(GO) vet ./pkg/command/...
	$(GO) vet ./services/access/api-gateway/...
	$(GO) vet ./services/access/authentication/...
	$(GO) vet ./services/access/authorization/...
	$(GO) vet ./services/access/session-broker/...
	$(GO) vet ./services/proxy/ssh-proxy/...
	$(GO) vet ./services/proxy/rdp-vnc-proxy/...
	$(GO) vet ./services/vault/password-vault/...
	$(GO) vet ./services/recording-audit/audit-service/...
	$(GO) vet ./services/recording-audit/command-recorder/...
	$(GO) vet ./services/recording-audit/video-recorder/...
	$(GO) vet ./test/integration/...

## Tests unitaires de tous les services. Hermétique : les tests
## PostgreSQL-dépendants (postgres_store_test.go) se SKIP automatiquement
## sans TEST_DATABASE_URL.
test: proto-gen
	$(GO) test \
		./pkg/proxycore/... \
		./pkg/rdp/... \
		./pkg/vnc/... \
		./pkg/tlspin/... \
		./pkg/screenstream/... \
		./pkg/mtls/... \
		./pkg/mtls/cmd/openbastion-pki/... \
		./cli/openbastion-cli/... \
		./pkg/migrate/... \
		./pkg/refusalbudget/... \
		./pkg/webhook/... \
		./pkg/hostkey/... \
		./pkg/transit/... \
		./proto/... \
		./pkg/buildinfo/... \
		./pkg/command/... \
		./services/access/api-gateway/... \
		./services/access/authentication/... \
		./services/access/authorization/... \
		./services/access/session-broker/... \
		./services/proxy/ssh-proxy/... \
		./services/proxy/rdp-vnc-proxy/... \
		./services/vault/password-vault/... \
		./services/recording-audit/audit-service/... \
		./services/recording-audit/command-recorder/... \
		./services/recording-audit/video-recorder/... \
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
## Fuzz every parser a target or a browser feeds (ADR-0071, increment 4): each Fuzz target of the
## protocol packages, FUZZTIME each. A failure leaves its input in the package's testdata/fuzz.
FUZZTIME ?= 30s
FUZZ_PACKAGES ?= ./pkg/rdp ./pkg/vnc ./pkg/screenstream
fuzz:
	@set -e; for p in $(FUZZ_PACKAGES); do \
		for t in $$($(GO) test -list '^Fuzz' $$p | grep '^Fuzz'); do \
			echo "fuzz $$p $$t ($(FUZZTIME))"; \
			$(GO) test $$p -run '^$$' -fuzz "^$$t\$$" -fuzztime $(FUZZTIME); \
		done; \
	done

# A real RDP server in Docker, FreeRDP 3 (ADR-0071). Not Windows.
test-rdp-interop:
	RDP_INTEROP=1 $(GO) test ./services/proxy/rdp-vnc-proxy/internal/engine/ -run TestRDPInterop -v -count=1 -timeout=300s

## The recording of an RDP session, end to end (ADR-0071): the proxy's real server with the RDP codec,
## the real Video Recorder on PostgreSQL (TEST_DATABASE_URL), FreeRDP 3 in Docker whose display
## shrinks mid-session. RDP stays unexposed: the test registers the ticket the Broker would.
## Then the operator's route (ADR-0088): from the public API, eight services on real processes, RDP on.
test-rdp-recording:
	RDP_INTEROP=1 $(GO) test ./services/proxy/rdp-vnc-proxy/internal/interfaces/ -run TestRDPRecording -v -count=1 -timeout=600s
	RDP_INTEROP=1 $(GO) test ./test/integration/ -run TestScreenFlow_RDPFrom -v -count=1 -timeout=900s

## A real Windows target (ADR-0071), in CI: .github/workflows/windows-rdp.yml starts it
## (test/integration/testdata/rdp/windows) and exports the RDP_WINDOWS_* variables of its test.env.
## Needs /dev/kvm and about 40 GB of disk; waits up to RDP_WINDOWS_WAIT (90m) for the installation.
test-rdp-windows:
	$(GO) test ./services/proxy/rdp-vnc-proxy/internal/engine/ -run TestRDPWindows -v -count=1 -timeout=120m

test-integration: build
	$(GO) test ./test/integration/... -v -count=1 -timeout=300s

## L'Admin UI (web/admin-ui, ADR-0036) : tokens, dépendances depuis les lockfiles, tests et construction.
ui-tokens-test:
	node web/packages/design-tokens/scripts/check-contrast.mjs
	node web/packages/design-tokens/scripts/check-app-colors.mjs
ui-icons:
	cd web/packages/icons && npm ci --no-audit --no-fund && npm run build
ui-test: ui-icons ui-tokens-test
	cd web/admin-ui && npm ci --no-audit --no-fund && npm test
ui-build: ui-icons ui-tokens-test
	cd web/admin-ui && OPENBASTION_SOURCE_REVISION=${OPENBASTION_SOURCE_REVISION:-$(GIT_SHA_FULL)} npm ci --no-audit --no-fund && OPENBASTION_SOURCE_REVISION=${OPENBASTION_SOURCE_REVISION:-$(GIT_SHA_FULL)} npm run build

## Les vulnérabilités connues (ADR-0052) : govulncheck, épinglé, sur chaque module du go.work
## (une vulnérabilité dont le code est appelé fait échouer), puis npm audit sur les deux lockfiles.
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@v1.9.0
vuln: proto-gen
	@set -e; for m in $$(awk '/^use \(/{f=1;next} f&&/\)/{exit} f{print $$1}' go.work); do \
		echo "govulncheck $$m"; $(GO) run $(GOVULNCHECK) -C $$m ./...; \
	done
	cd web/admin-ui && npm audit
	cd web/packages/icons && npm audit

## Vérifie les déclarations de licence et la conservation des notices tierces.
license-check:
	bash scripts/check-license-metadata.sh

## Construit et démarre la pile docker-compose réelle (deploy/docker-compose, ADR-0033) et
## y joue le parcours du MVP sur les seuls ports publiés. Docker requis ; quelques minutes.
test-compose: proto-gen
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
test-postgres: proto-gen
	@if [ -z "$$TEST_DATABASE_URL" ]; then \
		echo "TEST_DATABASE_URL non défini — voir NOTES_SANDBOX.md"; exit 1; \
	fi
	@command -v psql >/dev/null 2>&1 || { echo "psql introuvable — nécessaire pour purger la base avant les tests PostgreSQL (voir NOTES_SANDBOX.md)"; exit 1; }
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, oidc_login_attempts, sessions, audit_events, alert_outbox, mfa_challenges, mfa_action_challenges, mfa_action_grants, mfa_enrollment_codes, mfa_webauthn_credentials, identity_provider_bindings RESTART IDENTITY CASCADE;"
	$(GO) test ./services/vault/password-vault/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/authorization/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/authentication/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/access/session-broker/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/recording-audit/audit-service/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/recording-audit/command-recorder/internal/infrastructure/... -run TestPostgres -v -count=1
	$(GO) test ./services/recording-audit/video-recorder/internal/infrastructure/... -run TestPostgres -v -count=1
	psql "$$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "TRUNCATE policies, privileged_accounts, vault_secrets, vault_scope_grants, users, oidc_login_attempts, sessions, audit_events, alert_outbox, mfa_challenges, mfa_action_challenges, mfa_action_grants, mfa_enrollment_codes, mfa_webauthn_credentials, identity_provider_bindings, video_recording_segments, video_recordings RESTART IDENTITY CASCADE;"
	$(GO) test ./test/integration/... -run TestPostgresFlow -v -count=1 -timeout=300s
	$(GO) test ./test/integration/... -run TestScreenFlow -v -count=1 -timeout=300s

## Les images : celle d'OpenBastion (cible runtime) et l'image PostgreSQL 16 durcie, analysées par
## Trivy (ADR-0060) ; échoue sur toute vulnérabilité HIGH ou CRITICAL corrigée ailleurs, sauf celles
## acceptées par écrit dans .trivyignore.yaml (par chemin, avec une date d'expiration).
## TRIVY : le binaire, vérifié contre son empreinte (la CI le fait) ; Docker requis.
TRIVY ?= trivy
scan-images: scan-postgres-image
	docker build --progress=plain -f deploy/docker-compose/Dockerfile --target runtime --build-arg VERSION=$(BUILD_VERSION) --build-arg SOURCE_REVISION=$(GIT_SHA_FULL) --build-arg SOURCE_REPOSITORY=$(SOURCE_REPOSITORY) -t openbastion:scan .
	@for bin in openbastion-cli openbastion-pki api-gateway audit-service ssh-proxy password-vault; do \
		got=$$(docker run --rm --entrypoint /usr/local/bin/$$bin openbastion:scan version --short); \
		[ "$$got" = "$(BUILD_VERSION)" ] || { echo "$$bin : version $$got ≠ $(BUILD_VERSION)"; exit 1; }; \
		echo "$$bin : $$got"; \
	done
	$(TRIVY) image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --ignorefile .trivyignore.yaml openbastion:scan

scan-postgres-image:
	docker build --progress=plain -f deploy/docker-compose/postgres/Dockerfile -t openbastion-postgres:scan .
	$(TRIVY) image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --ignorefile .trivyignore.yaml openbastion-postgres:scan

## Crée, dans $(PKI_DIR), une autorité et l'identité de chaque service (ADR-0010).
## Pour le développement et les petits déploiements ; en production, l'émission est
## celle de l'organisation, avec la même forme d'identité (docs/administration/ §PKI).
## Relancer renouvelle les certificats (7 jours) et conserve l'autorité : les services
## en cours les reprennent sans redémarrage. $(PKI_DIR) est ignoré par git.
pki:
	$(GO) run ./pkg/mtls/cmd/openbastion-pki all --dir $(PKI_DIR)

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
# TARGET_TLS_ROOTS_FILE is an explicit trust bundle for graphical targets; no system roots are implicit.
run-rdp-vnc-proxy:
	$(call tls,rdp-vnc-proxy) VAULT_URL=$(SCHEME)://127.0.0.1:8081 AUDIT_URL=$(SCHEME)://127.0.0.1:8082 \
		VIDEO_RECORDER_GRPC_URL=$(SCHEME)://127.0.0.1:8089 TARGET_TLS_ROOTS_FILE=$(TARGET_TLS_ROOTS_FILE) \
		$(GO) run ./services/proxy/rdp-vnc-proxy/cmd/rdp-vnc-proxy
run-recorder:
	$(call tls,command-recorder) AUTHORIZATION_URL=$(SCHEME)://127.0.0.1:8083 AUDIT_URL=$(SCHEME)://127.0.0.1:8082 \
		$(GO) run ./services/recording-audit/command-recorder/cmd/command-recorder
run-video-recorder:
	$(call tls,video-recorder) AUTHORIZATION_URL=$(SCHEME)://127.0.0.1:8083 AUDIT_URL=$(SCHEME)://127.0.0.1:8082 \
		$(GO) run ./services/recording-audit/video-recorder/cmd/video-recorder
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
