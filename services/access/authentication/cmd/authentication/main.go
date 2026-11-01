// Command authentication runs the Authentication Service (docs/architecture/system-overview.md).
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

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/refusalbudget"
	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authentication/internal/interfaces"
)

func main() {
	// The version it was built as (ADR-0063): the first line of its log.
	log.Printf("authentication %s", buildinfo.String())
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
		domain.MFARepository
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

	// Every token issued, and the second factor's administrative gestures, are written to the
	// audit first (ADR-0064): the audit down, nobody logs in. Refusals at best, in a budget per
	// login name (pkg/refusalbudget's strict defaults).
	auditURL := os.Getenv("AUDIT_URL")
	if auditURL == "" {
		auditURL = rt.DefaultURL("127.0.0.1:8082")
	}
	auditClient, err := rt.Client(mtls.Peer{URL: auditURL, Service: mtls.AuditService})
	if err != nil {
		log.Fatalf("authentication: %v", err)
	}
	svc.WithAudit(&infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: auditClient},
		refusalbudget.New(refusalbudget.DefaultBurst, refusalbudget.DefaultRatePerMinute))
	log.Printf("authentication: logins are written to the audit at %s before a token is issued — the audit down, no login (ADR-0064)", auditURL)

	configureDirectory(svc)
	configureMFA(svc, store)

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

// configureDirectory turns directory login on (ADR-0061): off unless every variable is set — all or
// none, LDAP_CA_FILE optional. A directory that does not answer at start does not stop the service
// (local login, the administrator's way in, stays): it is said, and the directory login answers 503.
func configureDirectory(svc *application.AuthenticationService) {
	required := []string{"LDAP_URL", "LDAP_SCHEMA", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD_FILE", "LDAP_USER_BASE_DN", "LDAP_GROUP_BASE_DN", "LDAP_ROLE_MAP_FILE"}
	var missing []string
	set := 0
	for _, name := range required {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		} else {
			set++
		}
	}
	switch {
	case set == 0 && os.Getenv("LDAP_CA_FILE") == "":
		log.Printf("authentication: directory login (LDAP) off")
		return
	case len(missing) > 0:
		log.Fatalf("authentication: LDAP is half configured, %s missing — set all of %s (and LDAP_CA_FILE if needed), or none — refusing to start",
			strings.Join(missing, ", "), strings.Join(required, ", "))
	}
	raw, err := application.LoadRoleMap(os.Getenv("LDAP_ROLE_MAP_FILE"))
	if err != nil {
		log.Fatalf("authentication: LDAP_ROLE_MAP_FILE: %v — refusing to start", err)
	}
	roles, err := infrastructure.NormalizeRoleMap(raw)
	if err != nil {
		log.Fatalf("authentication: LDAP_ROLE_MAP_FILE: %v — refusing to start", err)
	}
	dir, err := infrastructure.NewLDAPDirectory(infrastructure.LDAPConfig{
		URL: os.Getenv("LDAP_URL"), CAFile: os.Getenv("LDAP_CA_FILE"), Schema: os.Getenv("LDAP_SCHEMA"),
		BindDN: os.Getenv("LDAP_BIND_DN"), BindPasswordFile: os.Getenv("LDAP_BIND_PASSWORD_FILE"),
		UserBaseDN: os.Getenv("LDAP_USER_BASE_DN"), GroupBaseDN: os.Getenv("LDAP_GROUP_BASE_DN"),
	})
	if err != nil {
		log.Fatalf("authentication: LDAP: %v — refusing to start", err)
	}
	svc.WithDirectory(dir, roles)
	ctx, cancel := context.WithTimeout(context.Background(), 2*infrastructure.LDAPTimeout)
	defer cancel()
	if err := dir.Probe(ctx); err != nil {
		log.Printf("authentication: directory login (LDAP) configured, but the directory does not answer now (%v): POST /auth/ldap/login answers 503 until it does; local login is not affected", err)
	} else {
		log.Printf("authentication: directory login (LDAP, schema %s) with %s over TLS, the service account accepted", os.Getenv("LDAP_SCHEMA"), dir.Where())
	}
	log.Printf("authentication: %d group(s) in the LDAP role map; a user with no mapped group is refused", len(roles))
}

// configureMFA turns the second factor on (ADR-0062) for the accounts that hold one of
// MFA_REQUIRED_ROLES; MFA_SECRET_KEY_HEX, which seals the TOTP secrets, goes with it — one without
// the other stops the service, and neither the key nor a secret is ever written.
func configureMFA(svc *application.AuthenticationService, repo domain.MFARepository) {
	rolesVar, strictVar, keyHex := os.Getenv("MFA_REQUIRED_ROLES"), os.Getenv("MFA_PHISHING_RESISTANT_ROLES"), os.Getenv("MFA_SECRET_KEY_HEX")
	rpID, originsVar := os.Getenv("WEBAUTHN_RP_ID"), os.Getenv("WEBAUTHN_ORIGINS")
	switch {
	case rolesVar == "" && strictVar == "" && keyHex == "" && rpID == "" && originsVar == "":
		log.Printf("authentication: second factor off — no role requires it (MFA_REQUIRED_ROLES, MFA_PHISHING_RESISTANT_ROLES not set)")
		return
	case rolesVar == "" && strictVar == "":
		log.Fatalf("authentication: MFA_SECRET_KEY_HEX or WEBAUTHN_* is set but neither MFA_REQUIRED_ROLES nor MFA_PHISHING_RESISTANT_ROLES is: no role would require the second factor — refusing to start")
	case keyHex == "":
		log.Fatalf("authentication: a second factor is required without MFA_SECRET_KEY_HEX, which seals the TOTP secrets (64 hex digits, kept outside the database; `openssl rand -hex 32`) — refusing to start")
	case (rpID == "") != (originsVar == ""):
		log.Fatalf("authentication: WEBAUTHN_RP_ID and WEBAUTHN_ORIGINS go together (ADR-0065) — refusing to start")
	case strictVar != "" && rpID == "":
		log.Fatalf("authentication: MFA_PHISHING_RESISTANT_ROLES requires WebAuthn (WEBAUTHN_RP_ID, WEBAUTHN_ORIGINS): only a security key counts for them — refusing to start")
	}
	var roles, strict []string
	var err error
	if rolesVar != "" {
		if roles, err = application.ParseRoleList(rolesVar); err != nil {
			log.Fatalf("authentication: MFA_REQUIRED_ROLES: %v — refusing to start", err)
		}
	}
	if strictVar != "" {
		if strict, err = application.ParseRoleList(strictVar); err != nil {
			log.Fatalf("authentication: MFA_PHISHING_RESISTANT_ROLES: %v — refusing to start", err)
		}
	}
	sealer, err := infrastructure.NewMFASealer(keyHex)
	if err != nil {
		log.Fatalf("authentication: %v — refusing to start", err)
	}
	svc.WithMFA(roles, repo, sealer)
	if rpID != "" {
		var origins []string
		for _, o := range strings.Split(originsVar, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
		verifier, err := infrastructure.NewWebAuthnVerifier(rpID, origins)
		if err != nil {
			log.Fatalf("authentication: %v — refusing to start", err)
		}
		svc.WithWebAuthn(verifier, strict)
		log.Printf("authentication: WebAuthn second factor for %s (origins %s)", rpID, strings.Join(origins, ", "))
	}
	if len(roles) > 0 {
		log.Printf("authentication: second factor required for the roles %s, for local and directory accounts; enrollment needs an administrator's code (openbastion-cli mfa enrollment-code)", strings.Join(roles, ", "))
	}
	if len(strict) > 0 {
		log.Printf("authentication: only a security key (WebAuthn) counts for the roles %s: TOTP gives them no token (ADR-0065)", strings.Join(strict, ", "))
	}
}
