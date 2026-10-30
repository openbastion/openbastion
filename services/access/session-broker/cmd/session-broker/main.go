// Command session-broker runs the Session Broker (doc 00 §4.1) — the
// orchestrator that never sees a secret (ADR-0003).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// boundedIntEnv reads a number that has a default and bounds. Anything else — not a number,
// zero, a negative, above the maximum — stops the Broker: there is no value that means
// "unlimited" or "off", and a typo must not select one.
func boundedIntEnv(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		log.Fatalf("session-broker: %s must be a number between %d and %d, got %q", name, min, max, v)
	}
	return n
}

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.SessionBroker)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8084")
	authzURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	vaultURL := mustEnv("VAULT_URL", rt.DefaultURL("127.0.0.1:8081"))
	auditURL := mustEnv("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))
	sshProxyURL := mustEnv("SSH_PROXY_URL", rt.DefaultURL("127.0.0.1:8085"))

	var store domain.SessionRepository
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		log.Printf("session-broker: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("session-broker: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	// Each client is pinned to the identity of the one service it calls: the
	// Broker never hands a scope to anything but the Vault, nor a break-glass
	// flag to anything but the SSH Proxy (ADR-0009, ADR-0010).
	peer := func(url, service string) *http.Client {
		c, err := rt.Client(mtls.Peer{URL: url, Service: service})
		if err != nil {
			log.Fatalf("session-broker: %v", err)
		}
		return c
	}
	vaultClient := peer(vaultURL, mtls.PasswordVault)
	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL, Client: peer(authzURL, mtls.Authorization)}
	vault := &infrastructure.VaultAuthorizationHTTPClient{BaseURL: vaultURL, Client: vaultClient}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: peer(auditURL, mtls.AuditService)}
	accounts := &infrastructure.AccountLookupHTTPClient{BaseURL: vaultURL, Client: vaultClient}
	proxy := &infrastructure.ProxyClientHTTPClient{BaseURL: sshProxyURL, Client: peer(sshProxyURL, mtls.SSHProxy)}

	svc := application.NewSessionBrokerService(store, authz, vault, audit, accounts, proxy).
		// A granted session ended: the Vault rotates the account if it is post_use (ADR-0037).
		WithAfterUseRotation(vault)

	// Sessions and requests past their end are expired, once, and each expiry is written to
	// the audit (ADR-0034). Always on: an end is a fact, not an option.
	sweep := boundedIntEnv("SESSION_EXPIRY_SWEEP_SECONDS", 30, 1, 3600)
	go expireEvery(svc, time.Duration(sweep)*time.Second)
	log.Printf("session-broker: sessions and requests past their end are expired every %ds, each expiry written to the audit", sweep)

	// What the refused reads of one user may write to the audit (ADR-0020): a burst, then a
	// steady rate. Read whether or not anyone is ever refused, so that a bad value is found
	// on the day it is written.
	svc.WithReadRefusalAudit(
		boundedIntEnv("SESSION_READ_AUDIT_BURST", application.DefaultReadAuditBurst, 1, application.MaxReadAuditBurst),
		boundedIntEnv("SESSION_READ_AUDIT_RATE_PER_MINUTE", application.DefaultReadAuditRatePerMinute, 1, application.MaxReadAuditRatePerMinute))
	readBurst, readRate := svc.ReadRefusalAudit()
	log.Printf("session-broker: the refusals of reads of a session are written to the audit per user: a burst of %d, then %d a minute (per process; a refusal is the same whatever the budget says)", readBurst, readRate)

	// Break-glass (ADR-0009) is off unless a limit is given: the maximum number of
	// minutes a break-glass session may last. A value that is not a number is an
	// error, not a quiet "off" — or worse, a quiet "on".
	breakGlassMax := 0
	if v := os.Getenv("BREAKGLASS_MAX_MINUTES"); v != "" {
		max, err := strconv.Atoi(v)
		if err != nil || max < 0 {
			log.Fatalf("session-broker: BREAKGLASS_MAX_MINUTES must be a number of minutes (0 disables break-glass), got %q", v)
		}
		breakGlassMax = max
		svc.WithBreakGlass(max)
	}

	// The double validation (ADR-0011) is required unless it is turned off by name:
	// anything else than the two known words is an error, so that a typo does not pick
	// a side — and it is read whether or not break-glass is on, so that a bad value
	// is found on the day it is written, not on the day break-glass is enabled.
	approvalWindow := application.DefaultBreakGlassApprovalWindow
	if v := os.Getenv("BREAKGLASS_APPROVAL_WINDOW_MINUTES"); v != "" {
		minutes, err := strconv.Atoi(v)
		if err != nil || minutes < 1 || minutes > 1440 {
			log.Fatalf("session-broker: BREAKGLASS_APPROVAL_WINDOW_MINUTES must be a number of minutes between 1 and 1440, got %q", v)
		}
		approvalWindow = time.Duration(minutes) * time.Minute
	}
	svc.WithBreakGlassApprovalWindow(approvalWindow)
	// How many requests one requester may have waiting (ADR-0013). There is no value
	// for "unlimited": a number out of range is a mistake to be found at start-up,
	// not a way to switch the protection off.
	maxPending := application.DefaultMaxPendingPerRequester
	if v := os.Getenv("BREAKGLASS_MAX_PENDING_PER_REQUESTER"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			log.Fatalf("session-broker: BREAKGLASS_MAX_PENDING_PER_REQUESTER must be a number between 1 and 100, got %q", v)
		}
		maxPending = n
	}
	svc.WithMaxPendingPerRequester(maxPending)
	approvalRequired := true
	switch v := os.Getenv("BREAKGLASS_APPROVAL"); v {
	case "", "required":
	case "disabled":
		approvalRequired = false
		svc.WithoutBreakGlassApproval()
	default:
		log.Fatalf("session-broker: BREAKGLASS_APPROVAL must be %q (the default) or %q, got %q", "required", "disabled", v)
	}

	switch {
	case breakGlassMax > 0 && approvalRequired:
		log.Printf("session-broker: BREAK-GLASS ENABLED (at most %d minutes) — a request needs the approval of a second user, within %s, and a requester may have at most %d waiting; an approved session runs while the Command Recorder is down", breakGlassMax, approvalWindow, maxPending)
	case breakGlassMax > 0:
		log.Printf("session-broker: BREAK-GLASS ENABLED (at most %d minutes) WITHOUT APPROVAL (BREAKGLASS_APPROVAL=disabled) — a single actor with a policy on breakglass:account:* can obtain a session that runs while the Command Recorder is down", breakGlassMax)
	}

	// Who is told of a break-glass request (ADR-0012): nobody, unless a webhook is
	// given. The URL is a secret — it is checked here, and never written: a URL that
	// cannot be used stops the Broker, whose message does not repeat it, rather than
	// leaving approvers to believe they would be told.
	notifyChannel := ""
	notifySigned := false
	notifySecret := os.Getenv("BREAKGLASS_NOTIFY_SECRET")
	if os.Getenv("BREAKGLASS_NOTIFY_URL") == "" && notifySecret != "" {
		// A secret with nobody to sign for: the operator would believe a channel is
		// protected that does not exist. Never repeated, like the URL (ADR-0013).
		log.Fatalf("session-broker: BREAKGLASS_NOTIFY_SECRET is set but BREAKGLASS_NOTIFY_URL is not: there is nothing to sign")
	}
	if v := os.Getenv("BREAKGLASS_NOTIFY_URL"); v != "" {
		n, err := infrastructure.NewWebhookNotifier(v)
		if err != nil {
			log.Fatalf("session-broker: BREAKGLASS_NOTIFY_URL cannot be used: %v", err)
		}
		if notifySecret != "" {
			if _, err := n.WithSecret(notifySecret); err != nil {
				log.Fatalf("session-broker: BREAKGLASS_NOTIFY_SECRET cannot be used: %v", err)
			}
			notifySigned = true
		}
		svc.WithApprovalNotifier(n)
		notifyChannel = n.Where()
	}
	switch {
	case notifyChannel != "":
		signing := "not signed"
		if notifySigned {
			signing = "signed: " + infrastructure.WebhookSignatureHeader + " is a v1 HMAC-SHA256"
		}
		log.Printf("session-broker: break-glass notifications are sent to %s (%s; best effort; the rest of the URL is a secret and is not logged)", notifyChannel, signing)
	case breakGlassMax > 0 && approvalRequired:
		log.Printf("session-broker: no notification channel (BREAKGLASS_NOTIFY_URL is not set): approvers have to look at GET /sessions?status=pending_approval")
	}
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("session-broker listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> vault:         %s", vaultURL)
	log.Printf("  -> audit:         %s", auditURL)
	log.Printf("  -> ssh-proxy:     %s", sshProxyURL)
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

// expireEvery runs the expiry sweep at every tick (ADR-0034). A failure is written once per
// episode: what is expired stays expired, the expiries not written wait for the next sweep.
func expireEvery(svc *application.SessionBrokerService, every time.Duration) {
	failing := false
	for range time.Tick(every) {
		expired, written, err := svc.ExpireDue(context.Background())
		if expired > 0 || written > 0 {
			log.Printf("session-broker: %d session(s) expired, %d expiry event(s) written to the audit", expired, written)
		}
		switch {
		case err != nil && !failing:
			log.Printf("session-broker: writing expiries to the audit failed, they wait for the next sweep (written once until it works again): %v", err)
			failing = true
		case err == nil && failing:
			log.Printf("session-broker: writing expiries to the audit works again")
			failing = false
		}
	}
}
