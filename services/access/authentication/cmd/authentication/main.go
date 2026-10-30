// Command authentication runs the Authentication Service (doc 00 §4.1).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authentication/internal/interfaces"
)

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.Authentication)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8086"
	}
	dsn := os.Getenv("DATABASE_URL")
	signingKeyHex := os.Getenv("TOKEN_SIGNING_KEY_HEX")

	// Fail closed, not open: a random per-process signing key
	// (SigningKeyFromHex's empty-key fallback) silently invalidates
	// every token issued by this process the moment it restarts — the
	// Authentication equivalent of the LocalKMS bug documented in
	// NOTES_SANDBOX.md. A real deployment generates this once
	// (`openssl rand -hex 32`) and keeps it outside the database.
	if dsn != "" && signingKeyHex == "" {
		log.Fatalf("authentication: DATABASE_URL is set but TOKEN_SIGNING_KEY_HEX is not — refusing to start with a random, per-process signing key that would invalidate every active session after a restart. Generate one with `openssl rand -hex 32` and set TOKEN_SIGNING_KEY_HEX.")
	}
	key, err := infrastructure.SigningKeyFromHex(signingKeyHex)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}

	var store interface {
		domain.UserRepository
		domain.LoginAttemptRepository
	}
	if dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		log.Printf("authentication: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("authentication: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	hasher := infrastructure.Argon2Hasher{}
	tokens := infrastructure.NewTokenIssuer(key)
	svc := application.NewAuthenticationService(store, hasher, tokens, time.Hour)

	// Federated login (ADR-0035): off unless every variable is set — all or none.
	oidcVars := map[string]string{}
	for _, name := range []string{"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "OIDC_ROLE_MAP_FILE"} {
		oidcVars[name] = os.Getenv(name)
	}
	set := 0
	for _, v := range oidcVars {
		if v != "" {
			set++
		}
	}
	switch set {
	case 0:
		log.Printf("authentication: federated login (OIDC) off — local accounts only")
	case len(oidcVars):
		roles, err := application.LoadRoleMap(oidcVars["OIDC_ROLE_MAP_FILE"])
		if err != nil {
			log.Fatalf("authentication: OIDC_ROLE_MAP_FILE: %v — refusing to start", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		provider, err := infrastructure.NewOIDCProvider(ctx, infrastructure.OIDCConfig{
			Issuer: oidcVars["OIDC_ISSUER"], ClientID: oidcVars["OIDC_CLIENT_ID"], ClientSecret: oidcVars["OIDC_CLIENT_SECRET"],
			RedirectURL: oidcVars["OIDC_REDIRECT_URL"], GroupsClaim: os.Getenv("OIDC_GROUPS_CLAIM"),
		}, nil)
		cancel()
		if err != nil {
			// Never the secret: the errors name variables and URLs, not values of the secret.
			log.Fatalf("authentication: OIDC: %v — refusing to start", err)
		}
		svc.WithOIDC(provider, roles, store)
		log.Printf("authentication: federated login (OIDC) with %s, %d group(s) in the role map; a user with no mapped role is refused", oidcVars["OIDC_ISSUER"], len(roles))
	default:
		var missing []string
		for name, v := range oidcVars {
			if v == "" {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		log.Fatalf("authentication: OIDC is half configured, %s missing — set all of OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URL, OIDC_ROLE_MAP_FILE, or none — refusing to start", strings.Join(missing, ", "))
	}

	// Demo seed — real onboarding goes through POST /auth/v1/users.
	if os.Getenv("SKIP_DEMO_SEED") == "" {
		ctx := context.Background()
		if _, err := svc.CreateUser(ctx, "demo-dba", "Demo DBA", "demo-password", []string{"dba"}); err != nil {
			log.Fatalf("seed: %v", err)
		}
	}

	srv := interfaces.NewHTTPServer(svc)
	log.Printf("authentication listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Fatal(rt.ListenAndServe(":"+port, srv.Routes(), interfaces.CallerRules()))
}

func redactDSN(dsn string) string {
	at := -1
	for i, c := range dsn {
		if c == '@' {
			at = i
		}
	}
	if at == -1 {
		return dsn
	}
	return "***@" + dsn[at+1:]
}
