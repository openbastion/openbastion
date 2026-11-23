package integration_test

// ADR-0116 §3 across two real processes: a Session Broker on PostgreSQL that changes a session's row
// moves its head in the Audit Service, and the head's digest is the SHA-256 of the row's canonical
// form as this package computes it on its own (session_metadata_sign_test.go).

import (
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestPostgresFlow_AChangeOfASessionMovesItsHeadInTheAuditService(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	root := repoRoot(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-0116")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-0116")
	unreachable := "http://127.0.0.1:1"
	audit := startService(t, root, auditBin, "19951")
	// Started once to migrate the table, then the row is written signed, past its end.
	broker := startService(t, root, brokerBin, "19952", "DATABASE_URL="+dsn, "AUTHORIZATION_URL="+unreachable,
		"AUDIT_URL="+audit.baseURL, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=1")
	stopService(t, broker)
	end := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	row := signedSessionRow{ID: fmt.Sprintf("session_head_%d", time.Now().UnixNano()), Status: "active", Protocol: "ssh",
		RequestedBy: "user_a", Account: "acc_1", Justification: "ADR-0116 head", CreatedAt: end.Add(-time.Hour), ExpiresAt: end}
	insertSignedSession(t, db, row)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM sessions WHERE id = $1`, row.ID) })
	startService(t, root, brokerBin, "19952", "DATABASE_URL="+dsn, "AUTHORIZATION_URL="+unreachable,
		"AUDIT_URL="+audit.baseURL, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=1")

	// The sweep expires it: revision 2, an active session that ended owing the Vault its end.
	expired := row
	expired.Status, expired.AfterUseOwed = "expired", true
	want := sha256.Sum256(sessionMetadataCanonical(expired))
	var head struct {
		Revision       uint64 `json:"revision"`
		MetadataSHA256 string `json:"metadata_sha256"`
		KeyID          string `json:"key_id"`
	}
	waitUntil(t, 15*time.Second, "the head at the expiry's revision", func() bool {
		resp, err := http.Get(audit.baseURL + "/audit/v1/session-metadata/head?session_id=" + row.ID)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&head) == nil && head.Revision == 2
	})
	if head.MetadataSHA256 != hex.EncodeToString(want[:]) || head.KeyID != "k1" {
		t.Fatalf("the head %+v, want digest %x under k1", head, want)
	}
	var revision int64
	_ = db.QueryRow(`SELECT metadata_revision FROM sessions WHERE id = $1`, row.ID).Scan(&revision)
	if revision != 2 {
		t.Fatalf("the row at revision %d, want 2", revision)
	}
}

// ADR-0116 §6 across two real processes: a backup of a session's row restored over a later revision
// carries a valid MAC, and the Broker still refuses it, because the Audit Service's head is further.
func TestPostgresFlow_ARolledBackSessionIsRefusedByTheBroker(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	root := repoRoot(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-0116")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-0116")
	unreachable := "http://127.0.0.1:1"
	audit := startService(t, root, auditBin, "19953")
	env := []string{"DATABASE_URL=" + dsn, "AUTHORIZATION_URL=" + unreachable, "AUDIT_URL=" + audit.baseURL,
		"VAULT_URL=" + unreachable, "SSH_PROXY_URL=" + unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=3600"}
	broker := startService(t, root, brokerBin, "19954", env...)
	stopService(t, broker)

	// Revision 1: an active session, signed; the backup is taken.
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := signedSessionRow{ID: fmt.Sprintf("session_rollback_%d", time.Now().UnixNano()), Status: "active", Protocol: "ssh",
		RequestedBy: "user_a", Account: "acc_1", Justification: "ADR-0116 rollback", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	insertSignedSession(t, db, row)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM sessions WHERE id = $1`, row.ID) })
	var backupMAC []byte
	_ = db.QueryRow(`SELECT metadata_mac FROM sessions WHERE id = $1`, row.ID).Scan(&backupMAC)

	broker = startService(t, root, brokerBin, "19954", env...)
	read := func() int {
		resp, err := http.Get(broker.baseURL + "/sessions/" + row.ID + "?callerId=user_a")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// The first read finds no head and attests revision 1.
	if code := read(); code != http.StatusOK {
		t.Fatalf("the first read: %d", code)
	}
	// Revision 2 — the session terminated — written in SQL and signed as the Broker signs (the proxy
	// is unreachable here, so the Broker's own termination cannot run). The next read finds it one
	// revision ahead of its head and attests it (§5).
	ended := row
	ended.Status = "terminated"
	terminated := now.Add(time.Minute)
	if _, err := db.Exec(`UPDATE sessions SET status = 'terminated', terminated_at = $2, metadata_revision = 2, metadata_mac = $3 WHERE id = $1`,
		row.ID, terminated, sessionMetadataMACTerminated(t, ended, terminated, 2)); err != nil {
		t.Fatal(err)
	}
	if code := read(); code != http.StatusOK {
		t.Fatalf("the read of revision 2: %d", code)
	}
	// The backup restored: revision 1 again, its MAC valid. The head says 2: refused.
	if _, err := db.Exec(`UPDATE sessions SET status = 'active', terminated_at = NULL, metadata_revision = 1, metadata_mac = $2 WHERE id = $1`,
		row.ID, backupMAC); err != nil {
		t.Fatal(err)
	}
	if code := read(); code != http.StatusInternalServerError {
		t.Fatalf("a rolled-back session read: %d, want 500", code)
	}
	// os/exec drains the child process's stdout/stderr into syncBuffer asynchronously;
	// the HTTP response can arrive before that copy goroutine has delivered the log line.
	waitUntil(t, 2*time.Second, "the Broker's rollback log", func() bool {
		return strings.Contains(broker.out.String(), "rolled back")
	})
}

// ADR-0116, consequences: "la latence et le débit doivent être mesurés". Run on demand
// (OPENBASTION_MEASURE=1): two real Broker replicas, one real Audit Service and PostgreSQL 16,
// all internal calls over mTLS. Persistent clients model pooled production connections; each
// concurrency level is measured after per-worker warm-up. This is a measurement, not a CI gate.
func TestPostgresFlow_MeasureTheReadOfASession(t *testing.T) {
	if os.Getenv("OPENBASTION_MEASURE") == "" {
		t.Skip("OPENBASTION_MEASURE not set: a measurement, not a check")
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	root := repoRoot(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	p := newTestPKI(t)
	// This measurement can run after a long build; give its service identities enough lifetime
	// that certificate expiry cannot contaminate the latency sample.
	for _, service := range []string{mtls.AdminCLI, mtls.APIGateway, mtls.AuditService, mtls.SessionBroker} {
		if _, err := pki.IssueToDir(p.ca, p.dir, service, pki.IssueOptions{TTL: 6 * time.Hour}); err != nil {
			t.Fatalf("issue measurement identity for %s: %v", service, err)
		}
	}
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-0116-measure")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-0116-measure")
	const (
		auditPort   = "19955"
		brokerPortA = "19956"
		brokerPortB = "19957"
	)
	auditURL := "https://127.0.0.1:" + auditPort
	audit := startMTLSService(t, root, auditBin, auditPort, p, mtls.AuditService,
		"DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+testKMSKeyHex(t),
		"AUDIT_ANCHOR_FILE="+t.TempDir()+"/anchors.jsonl")
	unreachable := "https://127.0.0.1:1"
	brokerEnv := []string{"DATABASE_URL=" + dsn, "AUTHORIZATION_URL=" + unreachable,
		"AUDIT_URL=" + auditURL, "VAULT_URL=" + unreachable, "SSH_PROXY_URL=" + unreachable,
		"SESSION_EXPIRY_SWEEP_SECONDS=3600"}
	// Start once to apply the Broker migrations before inserting a row with the independent signer.
	stopService(t, startMTLSService(t, root, brokerBin, brokerPortA, p, mtls.SessionBroker, brokerEnv...).runningService)

	now := time.Now().UTC().Truncate(time.Microsecond)
	row := signedSessionRow{ID: fmt.Sprintf("session_measure_%d", time.Now().UnixNano()), Status: "active", Protocol: "ssh",
		RequestedBy: "user_a", Account: "acc_1", Justification: "ADR-0116 concurrent mTLS measure", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	insertSignedSession(t, db, row)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM sessions WHERE id = $1`, row.ID) })

	brokerA := startMTLSService(t, root, brokerBin, brokerPortA, p, mtls.SessionBroker, brokerEnv...)
	brokerB := startMTLSService(t, root, brokerBin, brokerPortB, p, mtls.SessionBroker, brokerEnv...)
	brokerURLs := []string{brokerA.baseURL, brokerB.baseURL}

	persistentClient := func(identity string, maxConns int) *http.Client {
		t.Helper()
		cert, err := tls.LoadX509KeyPair(pki.CertFile(p.dir, identity), pki.KeyFile(p.dir, identity))
		if err != nil {
			t.Fatalf("load %s identity: %v", identity, err)
		}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: p.roots(), Certificates: []tls.Certificate{cert}},
			MaxIdleConns:    maxConns * 2, MaxIdleConnsPerHost: maxConns, MaxConnsPerHost: maxConns,
		}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		t.Cleanup(client.CloseIdleConnections)
		return client
	}
	// The Broker only admits the Gateway certificate on session routes. This benchmark calls the
	// Broker directly with that service identity to isolate its read path; it does not bypass mTLS.
	// The Audit head route is restricted to the Broker identity, used for the direct comparison.
	brokerClient := persistentClient(mtls.APIGateway, 64)
	headClient := persistentClient(mtls.SessionBroker, 64)
	brokerPath := "/sessions/" + row.ID + "?callerId=user_a"
	headPath := "/audit/v1/session-metadata/head?session_id=" + row.ID

	// Prime the session's first independent head before measuring either endpoint.
	for i := 0; i < 4; i++ {
		resp, err := brokerClient.Get(brokerURLs[i%len(brokerURLs)] + brokerPath)
		if err != nil {
			t.Fatalf("prime Broker read: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("prime Broker read: status %d", resp.StatusCode)
		}
	}

	type measurement struct {
		p50, p95, p99     time.Duration
		requestsPerSecond float64
		elapsed           time.Duration
	}
	measure := func(client *http.Client, urls []string, path string, concurrency, requests int) measurement {
		t.Helper()
		const warmupPerWorker = 20
		var ready, workers sync.WaitGroup
		begin := make(chan struct{})
		results := make(chan []time.Duration, concurrency)
		errors := make(chan error, concurrency)
		for worker := 0; worker < concurrency; worker++ {
			count := requests / concurrency
			if worker < requests%concurrency {
				count++
			}
			ready.Add(1)
			workers.Add(1)
			go func(worker, count int) {
				defer workers.Done()
				urlFor := func(i int) string { return urls[(worker+i)%len(urls)] + path }
				request := func(url string) (time.Duration, error) {
					started := time.Now()
					resp, err := client.Get(url)
					if err != nil {
						return 0, err
					}
					_, copyErr := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if copyErr != nil {
						return 0, copyErr
					}
					if resp.StatusCode != http.StatusOK {
						return 0, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
					}
					return time.Since(started), nil
				}
				for i := 0; i < warmupPerWorker; i++ {
					if _, err := request(urlFor(i)); err != nil {
						errors <- err
						ready.Done()
						return
					}
				}
				ready.Done()
				<-begin
				latencies := make([]time.Duration, 0, count)
				for i := 0; i < count; i++ {
					latency, err := request(urlFor(warmupPerWorker + i))
					if err != nil {
						errors <- err
						return
					}
					latencies = append(latencies, latency)
				}
				results <- latencies
			}(worker, count)
		}
		ready.Wait()
		started := time.Now()
		close(begin)
		workers.Wait()
		elapsed := time.Since(started)
		close(results)
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatalf("measurement at concurrency %d: %v", concurrency, err)
			}
		}
		latencies := make([]time.Duration, 0, requests)
		for samples := range results {
			latencies = append(latencies, samples...)
		}
		if len(latencies) != requests {
			t.Fatalf("measured %d successful requests, want %d", len(latencies), requests)
		}
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		percentile := func(p int) time.Duration {
			index := (len(latencies)*p+99)/100 - 1
			if index < 0 {
				index = 0
			}
			return latencies[index]
		}
		return measurement{p50: percentile(50), p95: percentile(95), p99: percentile(99),
			requestsPerSecond: float64(requests) / elapsed.Seconds(), elapsed: elapsed}
	}

	const requestsPerLevel = 2000
	t.Logf("ADR-0116 benchmark: PostgreSQL 16, 2 Broker replicas, 1 Audit Service, mTLS TLS 1.3, pooled HTTP/1.1; %d requests per endpoint and concurrency level", requestsPerLevel)
	t.Log("endpoint,concurrency,requests,elapsed,p50,p95,p99,requests_per_second")
	for _, concurrency := range []int{1, 8, 32, 64} {
		for _, target := range []struct {
			name   string
			client *http.Client
			urls   []string
			path   string
		}{
			{"broker_read_hmac_plus_head", brokerClient, brokerURLs, brokerPath},
			{"audit_head_only", headClient, []string{audit.baseURL}, headPath},
		} {
			m := measure(target.client, target.urls, target.path, concurrency, requestsPerLevel)
			t.Logf("%s,%d,%d,%s,%s,%s,%s,%.1f", target.name, concurrency, requestsPerLevel,
				m.elapsed, m.p50, m.p95, m.p99, m.requestsPerSecond)
		}
	}
}
