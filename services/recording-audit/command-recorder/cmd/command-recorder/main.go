// Command command-recorder runs the Command Recorder (docs/architecture/system-overview.md): the
// service that stores, command by command, what operators ran in a session,
// so a session can be replayed as text.
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/command"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/transit"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// boundedIntEnv reads a number that must lie within bounds: a value that is not one stops
// the Recorder, naming the variable — there is no quiet fallback.
func boundedIntEnv(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		log.Fatalf("command-recorder: %s must be a number between %d and %d, got %q", name, min, max, v)
	}
	return n
}

func runService() {
	// The version it was built as (ADR-0063): the first line of its log.
	log.Printf("command-recorder %s", buildinfo.String())
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.CommandRecorder)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := mustEnv("PORT", "8087")
	authzURL := mustEnv("AUTHORIZATION_URL", rt.DefaultURL("127.0.0.1:8083"))
	// Every read of a recording is written here before it is served, and is not served
	// without it (ADR-0022): there is no setting that turns this off.
	auditURL := mustEnv("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))

	var repo domain.CommandRepository
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		// Fail closed, not open: with PostgreSQL every command is encrypted
		// under a per-session key wrapped by this key, so a missing or random
		// key would make every recording unreadable after a restart — or, if
		// we skipped encryption instead, store commands in the clear. Generate
		// one once (`openssl rand -hex 32`), keep it outside the database, and
		// give this service its OWN key, not the Password Vault's.
		kek, previous := recordingKeys()
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store, err := infrastructure.NewPostgresStore(ctx, db, kek, previous...)
		if err != nil {
			log.Fatalf("postgres store: %v", err)
		}
		repo = store
		// What an earlier key still wraps is re-wrapped under the current one (ADR-0055).
		if len(previous) > 0 {
			every := boundedIntEnv("KEY_REWRAP_SWEEP_SECONDS", 60, 1, 3600)
			var ids []string
			for _, p := range previous {
				ids = append(ids, p.KeyID())
			}
			go rewrapEvery(store, time.Duration(every)*time.Second, ids)
			log.Printf("command-recorder: session keys under %s are re-wrapped under %s, %d a batch, every %ds", strings.Join(ids, ", "), kek.KeyID(), infrastructure.RewrapBatch, every)
		}
		log.Printf("command-recorder: using PostgreSQL at %s — commands encrypted at rest (AES-256-GCM, key per session wrapped by %s)", redactDSN(dsn), kek.KeyID())
	} else {
		repo = infrastructure.NewInMemoryStore()
		log.Printf("command-recorder: DATABASE_URL not set, using in-memory storage (dev/test only — recordings are lost on restart)")
	}

	authzClient, err := rt.Client(mtls.Peer{URL: authzURL, Service: mtls.Authorization})
	if err != nil {
		log.Fatalf("command-recorder: %v", err)
	}
	authz := &infrastructure.AuthorizationHTTPClient{BaseURL: authzURL, Client: authzClient}
	auditClient, err := rt.Client(mtls.Peer{URL: auditURL, Service: mtls.AuditService})
	if err != nil {
		log.Fatalf("command-recorder: %v", err)
	}
	audit := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: auditClient}
	svc := application.NewRecorderService(repo, authz, audit)
	// What the refused reads of one user may write to the audit (ADR-0024): a burst, then a
	// steady rate. Read whether or not anyone is ever refused, so that a bad value is found
	// on the day it is written.
	svc.WithReadRefusalAudit(
		boundedIntEnv("RECORDING_READ_AUDIT_BURST", application.DefaultReadAuditBurst, 1, application.MaxReadAuditBurst),
		boundedIntEnv("RECORDING_READ_AUDIT_RATE_PER_MINUTE", application.DefaultReadAuditRatePerMinute, 1, application.MaxReadAuditRatePerMinute))
	readBurst, readRate := svc.ReadRefusalAudit()
	srv := interfaces.NewHTTPServer(svc)

	log.Printf("command-recorder listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
	log.Printf("  -> authorization: %s", authzURL)
	log.Printf("  -> audit: %s (every read of a recording is written there before it is served)", auditURL)
	log.Printf("command-recorder: the refusals of reads of a recording are written to the audit per user: a burst of %d, then %d a minute (per process; a refusal is the same whatever the budget says)", readBurst, readRate)
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

// recordingKeys returns the key that wraps each session's data key, and the earlier keys held to
// read what they wrapped (ADR-0049). With Transit configured (TRANSIT_ADDR, TRANSIT_KEY,
// and TRANSIT_TOKEN_FILE or AppRole, ADR-0058), the key lives there, after a real round trip proves the key and the token
// work; KMS_KEY_HEX, if still given, reads the recordings wrapped before and wraps nothing.
// Without Transit, KMS_KEY_HEX is the key, as before.
func recordingKeys() (infrastructure.KeyWrapper, []infrastructure.KeyWrapper) {
	client, configured, err := transit.FromEnv(os.Getenv)
	if err != nil {
		log.Fatalf("command-recorder: %v — refusing to start", err)
	}
	hexKey := os.Getenv("KMS_KEY_HEX")
	if !configured {
		kek, err := infrastructure.NewLocalKEKFromHexKey(hexKey)
		if err != nil {
			log.Fatalf("command-recorder: DATABASE_URL is set, so recordings are encrypted at rest and a key is required (Transit, or KMS_KEY_HEX) — refusing to start: %v", err)
		}
		return kek, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*transit.Timeout)
	defer cancel()
	if err := client.Probe(ctx); err != nil {
		log.Fatalf("command-recorder: Transit cannot wrap and unwrap with %s: %v — refusing to start", client.KeyID(), err)
	}
	// The token renews itself at half its life (ADR-0053); with AppRole, a new one is logged in
	// once it reaches its maximum (ADR-0058).
	go client.KeepAlive(context.Background(), func(f string, a ...any) { log.Printf("command-recorder: "+f, a...) })
	// A token replaced on disk is taken once Transit accepts it (ADR-0056); with AppRole there is no
	// token file, and that is said.
	reload := boundedIntEnv("TRANSIT_TOKEN_RELOAD_SECONDS", int(transit.DefaultTokenReload/time.Second), 1, 3600)
	go client.WatchTokenFile(context.Background(), time.Duration(reload)*time.Second, func(f string, a ...any) { log.Printf("command-recorder: "+f, a...) })
	var previous []infrastructure.KeyWrapper
	if hexKey != "" {
		local, err := infrastructure.NewLocalKEKFromHexKey(hexKey)
		if err != nil {
			log.Fatalf("command-recorder: %v", err)
		}
		previous = append(previous, local)
		log.Printf("command-recorder: recordings wrapped under %s are still read (KMS_KEY_HEX); nothing new is wrapped under it", local.KeyID())
	}
	log.Printf("command-recorder: session keys are wrapped by %s at %s (Transit; the token is not logged)", client.KeyID(), client.Where())
	return infrastructure.NewTransitKEK(client), previous
}

// rewrapEvery re-wraps under the current key the session keys an earlier key still wraps
// (ADR-0055): page after page, a pass every period; a pass that finds nothing says, once, that
// the earlier key wraps nothing any more.
func rewrapEvery(store *infrastructure.PostgresStore, every time.Duration, previous []string) {
	time.Sleep(every)
	said := false
	for {
		found, skipped, cursor := 0, 0, ""
		for {
			r, err := store.RewrapDue(context.Background(), cursor)
			if err != nil {
				log.Printf("command-recorder: re-wrapping paused until the next pass: %v", err)
				found = -1
				break
			}
			found, skipped = found+r.Found, skipped+r.Skipped
			if r.Rewrapped > 0 {
				log.Printf("command-recorder: %d session key(s) re-wrapped under the current key", r.Rewrapped)
			}
			if cursor = r.Next; cursor == "" {
				break
			}
		}
		switch {
		case found == 0 && !said:
			said = true
			log.Printf("command-recorder: nothing is wrapped under %s any more: KMS_KEY_HEX can be removed", strings.Join(previous, ", "))
		case found > 0:
			said = false
			if skipped > 0 {
				log.Printf("command-recorder: %d session key(s) under %s do not unwrap with the key held: they stay, and KMS_KEY_HEX cannot be removed yet", skipped, strings.Join(previous, ", "))
			}
		}
		time.Sleep(every)
	}
}

// main dispatches version before entering the recorder lifecycle.
func main() {
	if err := command.NewServiceCommand("command-recorder", runService).Execute(); err != nil {
		log.Fatalf("command-recorder: %v", err)
	}
}
