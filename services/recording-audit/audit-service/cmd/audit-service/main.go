// Command audit-service runs the Audit Service (docs/architecture/system-overview.md).
//
// SANDBOX NOTE: serves HTTP/JSON rather than gRPC — see
// internal/interfaces/http.go and /NOTES_SANDBOX.md.
package main

import (
	"context"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/command"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/webhook"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/interfaces"
)

func runService() {
	// The version it was built as (ADR-0063): the first line of its log.
	log.Printf("audit-service %s", buildinfo.String())
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.AuditService)
	if err != nil {
		log.Fatalf("%v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	var store application.Store
	var alertQueue infrastructure.AlertQueue = infrastructure.NewMemoryAlertQueue()
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		db, err := infrastructure.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		store = infrastructure.NewPostgresStore(db)
		alertQueue = infrastructure.NewPostgresAlertQueue(db) // ADR-0057: what waits survives a restart
		log.Printf("audit-service: using PostgreSQL at %s", redactDSN(dsn))
	} else {
		store = infrastructure.NewInMemoryStore()
		log.Printf("audit-service: DATABASE_URL not set, using in-memory storage (dev/test only)")
	}

	// The chain is keyed (ADR-0027). With a database the key is required: a chain that
	// outlives the process must be verifiable by the next one, and a key made up at start
	// would make yesterday's chain unverifiable. In memory the chain dies with the process,
	// and so may its key.
	svc := application.NewAuditService(store)
	keyHex, previousHex := os.Getenv("AUDIT_CHAIN_KEY_HEX"), os.Getenv("AUDIT_CHAIN_PREVIOUS_KEYS_HEX")
	switch {
	case keyHex != "":
		keys, err := application.ParseChainKeys(keyHex, previousHex)
		if err != nil {
			// The error never repeats the value.
			log.Fatalf("audit-service: AUDIT_CHAIN_KEY_HEX / AUDIT_CHAIN_PREVIOUS_KEYS_HEX: %v — refusing to start", err)
		}
		svc.WithChainKeys(keys)
		log.Printf("audit-service: the chain is signed with key %s (%d key(s) held for verification)", keys.CurrentID(), keys.Count())
	case os.Getenv("DATABASE_URL") != "":
		log.Fatalf("audit-service: DATABASE_URL is set, so the chain outlives this process and AUDIT_CHAIN_KEY_HEX is required (64 hex digits, kept outside the database; `openssl rand -hex 32`) — refusing to start")
	case previousHex != "":
		log.Fatalf("audit-service: AUDIT_CHAIN_PREVIOUS_KEYS_HEX is set without AUDIT_CHAIN_KEY_HEX — refusing to start")
	default:
		log.Printf("audit-service: in-memory chain signed with a random key that lives as long as this process (dev/test only)")
	}
	// The head of the chain is anchored outside the database (ADR-0028). With a database the
	// anchors are required: they are what a chain rewritten entirely, or cut at its end, cannot
	// survive. In memory there is nothing to rewrite behind the process's back.
	if path := os.Getenv("AUDIT_ANCHOR_FILE"); path != "" || os.Getenv("DATABASE_URL") != "" {
		if path == "" {
			log.Fatalf("audit-service: DATABASE_URL is set, so AUDIT_ANCHOR_FILE is required (an absolute path the database does not control: another volume, an append-only mount) — refusing to start")
		}
		interval := 60
		if v := os.Getenv("AUDIT_ANCHOR_INTERVAL_SECONDS"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 3600 {
				log.Fatalf("audit-service: AUDIT_ANCHOR_INTERVAL_SECONDS must be a number between 1 and 3600, got %q", v)
			}
			interval = n
		}
		sink, err := infrastructure.NewFileAnchorSink(path)
		if err != nil {
			log.Fatalf("audit-service: AUDIT_ANCHOR_FILE: %v — refusing to start", err)
		}
		svc.WithAnchors(sink)
		go anchorEvery(svc, time.Duration(interval)*time.Second)
		log.Printf("audit-service: the head of the chain is anchored to %s every %ds (anchors verified by verify-chain)", path, interval)
	} else {
		log.Printf("audit-service: in-memory chain, not anchored (dev/test only)")
	}

	// Months older than the retention leave the database, verified, archived and checkpointed
	// (ADR-0032). Off unless both variables are set: nothing is ever taken out by default.
	archiveDir, retention := os.Getenv("AUDIT_ARCHIVE_DIR"), os.Getenv("AUDIT_RETENTION_MONTHS")
	switch {
	case archiveDir == "" && retention == "":
		log.Printf("audit-service: no retention — nothing ever leaves the audit database (AUDIT_ARCHIVE_DIR and AUDIT_RETENTION_MONTHS unset)")
	case archiveDir == "" || retention == "":
		log.Fatalf("audit-service: AUDIT_ARCHIVE_DIR and AUDIT_RETENTION_MONTHS go together (one is set without the other) — refusing to start")
	case os.Getenv("AUDIT_ANCHOR_FILE") == "":
		log.Fatalf("audit-service: AUDIT_ARCHIVE_DIR needs AUDIT_ANCHOR_FILE: the checkpoints of the archives are kept with the anchors — refusing to start")
	default:
		months, err := strconv.Atoi(retention)
		if err != nil || months < 1 || months > 120 {
			log.Fatalf("audit-service: AUDIT_RETENTION_MONTHS must be a number of months between 1 and 120, got %q", retention)
		}
		archiver, err := infrastructure.NewFileArchiver(archiveDir)
		if err != nil {
			log.Fatalf("audit-service: AUDIT_ARCHIVE_DIR: %v — refusing to start", err)
		}
		svc.WithArchive(archiver, months)
		go archiveEvery(svc, time.Hour)
		log.Printf("audit-service: months older than %d are archived to %s, hourly (verified first; a checkpoint is kept with the anchors)", months, archiveDir)
	}

	configureAlerts(svc, rt.Enabled(), alertQueue)

	srv := interfaces.NewHTTPServer(svc)

	log.Printf("audit-service listening on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", port)
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

// anchorEvery anchors the head of the chain at every tick. A failure is written once per
// episode, not once per tick: anchoring is out of band, events are still written and signed.
func anchorEvery(svc *application.AuditService, every time.Duration) {
	failing := false
	for range time.Tick(every) {
		if _, err := svc.Anchor(context.Background()); err != nil {
			if !failing {
				log.Printf("audit-service: anchoring the head of the chain failed (written once until it works again): %v", err)
			}
			failing = true
			continue
		}
		if failing {
			log.Printf("audit-service: anchoring the head of the chain works again")
		}
		failing = false
	}
}

// archiveEvery archives what is due at start and at every tick. A refusal is written once per
// episode: the events stay in the database, verified again next time.
func archiveEvery(svc *application.AuditService, every time.Duration) {
	failing := false
	for {
		names, err := svc.ArchiveDue(context.Background())
		for _, name := range names {
			log.Printf("audit-service: archived %s (verified, written, read back, checkpointed, then deleted from the database)", name)
		}
		switch {
		case err != nil && !failing:
			log.Printf("audit-service: archiving stopped, nothing more leaves the database (written once until it works again): %v", err)
			failing = true
		case err == nil && failing:
			log.Printf("audit-service: archiving works again")
			failing = false
		}
		time.Sleep(every)
	}
}

// configureAlerts pushes the alerts written to the chain to ALERT_NOTIFY_URL, signed with
// ALERT_NOTIFY_SECRET (ADR-0045). The two go together, and neither is ever written: a URL that
// cannot be used, a secret too short, or one without the other stops the service, with a
// message that repeats neither. The alerts wait in queue: alert_outbox with a database, so that
// a restart does not lose them (ADR-0057), memory without one.
func configureAlerts(svc *application.AuditService, internalTLS bool, queue infrastructure.AlertQueue) {
	rawURL, secret, retry := os.Getenv("ALERT_NOTIFY_URL"), os.Getenv("ALERT_NOTIFY_SECRET"), os.Getenv("ALERT_NOTIFY_RETRY_SECONDS")
	switch {
	case rawURL == "" && secret == "" && retry == "":
		log.Printf("audit-service: no alert channel (ALERT_NOTIFY_URL is not set): alerts are in the chain only, for whoever reads it")
		return
	case rawURL == "":
		log.Fatalf("audit-service: ALERT_NOTIFY_SECRET or ALERT_NOTIFY_RETRY_SECONDS is set but ALERT_NOTIFY_URL is not: there is no alert channel to configure — refusing to start")
	case secret == "":
		log.Fatalf("audit-service: ALERT_NOTIFY_URL is set without ALERT_NOTIFY_SECRET: an alert channel is signed (at least %d bytes; `openssl rand -hex 32`) — refusing to start", webhook.MinSecretBytes)
	}
	wait := infrastructure.DefaultAlertRetry
	if retry != "" {
		n, err := strconv.Atoi(retry)
		if err != nil || n < 1 || time.Duration(n)*time.Second > infrastructure.MaxAlertRetry {
			log.Fatalf("audit-service: ALERT_NOTIFY_RETRY_SECONDS must be a number between 1 and %d, got %q — refusing to start", int(infrastructure.MaxAlertRetry/time.Second), retry)
		}
		wait = time.Duration(n) * time.Second
	}
	endpoint, err := webhook.New(rawURL)
	if err != nil {
		log.Fatalf("audit-service: ALERT_NOTIFY_URL cannot be used: %v — refusing to start", err)
	}
	if _, err := endpoint.WithSecret(secret); err != nil {
		log.Fatalf("audit-service: ALERT_NOTIFY_SECRET cannot be used: %v — refusing to start", err)
	}
	notifier, err := infrastructure.NewAlertWebhookWithQueue(endpoint, wait, queue)
	if err != nil {
		log.Fatalf("audit-service: the alert channel cannot be used: %v — refusing to start", err)
	}
	svc.WithAlertNotifier(notifier, !internalTLS)

	var alerts []string
	for action, emitter := range application.AlertActions() {
		alerts = append(alerts, action+" from "+emitter)
	}
	sort.Strings(alerts)
	log.Printf("audit-service: alerts (%s) are pushed to %s once written, signed (%s, v1 HMAC-SHA256), up to %d attempts from %s; best effort, the rest of the URL is a secret and is not logged",
		strings.Join(alerts, ", "), notifier.Where(), webhook.SignatureHeader, infrastructure.AlertMaxAttempts, wait)
	if _, durable := queue.(*infrastructure.PostgresAlertQueue); durable {
		log.Printf("audit-service: the alerts waiting for a retry are kept in alert_outbox: a restart delivers them")
	} else {
		log.Printf("audit-service: the alerts waiting for a retry are kept in memory: a restart loses them (no DATABASE_URL)")
	}
	if !internalTLS {
		log.Printf("audit-service: internal TLS is disabled, so no emitter is named: an alert is pushed whoever writes it (dev only)")
	}
}

// main dispatches version before entering the recorder lifecycle.
func main() {
	if err := command.NewServiceCommand("audit-service", runService).Execute(); err != nil {
		log.Fatalf("audit-service: %v", err)
	}
}
