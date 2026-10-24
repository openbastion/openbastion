// Command api-gateway runs the API Gateway (doc 00 §4.1) — the single
// public entry point in front of Authentication and Session Broker.
//
// SANDBOX NOTE: serves HTTP/JSON, same as every other service in this
// project — see /NOTES_SANDBOX.md. This is arguably the one service
// where that's simply correct rather than a stand-in: the Gateway is
// documented as an HTTP/gRPC edge in the first place (doc 00 §4.1).
package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// boundedIntEnv reads a whole number between min and max. Anything else — a word,
// zero, a negative, a number above the maximum — stops the Gateway: there is no
// value that means "no limit", and a typo must not select one.
func boundedIntEnv(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		log.Fatalf("api-gateway: %s must be a number between %d and %d, got %q", name, min, max, v)
	}
	return n
}

func main() {
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010). The Gateway
	// has an identity for what it calls; what calls it — users — does not.
	rt, err := mtls.Setup(mtls.APIGateway)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8080")
	authenticationURL := mustEnv("AUTHENTICATION_URL", rt.DefaultURL("127.0.0.1:8086"))
	sessionBrokerURL := mustEnv("SESSION_BROKER_URL", rt.DefaultURL("127.0.0.1:8084"))
	vaultURL := mustEnv("VAULT_URL", rt.DefaultURL("127.0.0.1:8081"))
	authorizationURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	commandRecorderURL := mustEnv("COMMAND_RECORDER_URL", rt.DefaultURL("127.0.0.1:8087"))

	// One client for the five upstreams, each known by the identity it must
	// answer with: the Gateway forwards a user's request, and a user's identity
	// header, only to the service it is meant for.
	upstreams, err := rt.Client(
		mtls.Peer{URL: authenticationURL, Service: mtls.Authentication},
		mtls.Peer{URL: sessionBrokerURL, Service: mtls.SessionBroker},
		mtls.Peer{URL: vaultURL, Service: mtls.PasswordVault},
		mtls.Peer{URL: authorizationURL, Service: mtls.Authorization},
		mtls.Peer{URL: commandRecorderURL, Service: mtls.CommandRecorder},
	)
	if err != nil {
		log.Fatalf("api-gateway: %v", err)
	}

	authClient := &infrastructure.AuthenticationHTTPClient{BaseURL: authenticationURL, Client: upstreams}
	// Per client address, before the token is looked at (ADR-0014 says what that
	// address is behind a reverse proxy: the proxy's, for everybody).
	//   - authenticated traffic: a burst of 60, then one more every second — 60 per
	//     minute once the burst is spent. (It used to be NewRateLimiter(60,
	//     time.Minute): a burst of 60 and then ONE per minute.)
	//   - login: a burst of 5, then ONE per minute. Deliberately much stricter, since
	//     login is the one endpoint reachable without already holding a token; this
	//     is what it has always done, whatever its comment said, and it is kept.
	requestLimiter := application.NewRateLimiter(60, time.Second)
	loginLimiter := application.NewRateLimiter(5, time.Minute)

	// Per verified user, on POST /sessions only (ADR-0014): what bounds the rows and
	// the audit events a user can make the Broker write by being refused.
	sessionBurst := boundedIntEnv("SESSION_REQUEST_BURST", application.DefaultSessionBurst, 1, application.MaxSessionBurst)
	sessionRate := boundedIntEnv("SESSION_REQUEST_RATE_PER_MINUTE", application.DefaultSessionRatePerMinute, 1, application.MaxSessionRatePerMinute)

	srv := interfaces.NewGatewayServer(authClient, requestLimiter, loginLimiter, authenticationURL, sessionBrokerURL, vaultURL, authorizationURL, commandRecorderURL).
		WithHTTPClient(upstreams).
		WithSessionRequestLimiter(application.NewSessionRequestLimiter(sessionBurst, sessionRate))

	log.Printf("api-gateway listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authentication:  %s", authenticationURL)
	log.Printf("  -> session-broker:  %s", sessionBrokerURL)
	log.Printf("  -> vault:           %s", vaultURL)
	log.Printf("  -> authorization:   %s", authorizationURL)
	log.Printf("  -> command-recorder: %s", commandRecorderURL)
	log.Printf("  POST /sessions: at most %d at once per user, then %d per minute (this process only; a request refused for it never reaches the Broker)", sessionBurst, sessionRate)
	// Plain HTTP: this is the public listener, whose clients are users with bearer
	// tokens. TLS for them ends at the reverse proxy in front of it.
	log.Fatal(rt.ServePublic(":"+port, srv.Routes()))
}
