// Command ssh-proxy runs the SSH Proxy (docs/architecture/system-overview.md) — the first proxy
// with a real protocol implementation, using golang.org/x/crypto/ssh (see
// /NOTES_SANDBOX.md for how it's fetched in this build sandbox).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/openbastion/openbastion/pkg/command"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

func mustEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runService() {
	// The version it was built as (ADR-0063): the first line of its log.
	log.Printf("ssh-proxy %s", buildinfo.String())
	// Mutual TLS is required unless INTERNAL_TLS=disabled (ADR-0010).
	rt, err := mtls.Setup(mtls.SSHProxy)
	if err != nil {
		log.Fatalf("%v", err)
	}

	sshPort := mustEnv("SSH_PORT", "2222")
	// The address operators reach THIS instance at (ADR-0046): a ticket is good here and nowhere
	// else, so with several instances each says its own. Read first: a wrong one stops the proxy
	// before anything else is done.
	endpoint := publicEndpoint(sshPort)
	httpPort := mustEnv("PORT", "8085")
	vaultURL := mustEnv("VAULT_URL", rt.DefaultURL("127.0.0.1:8081"))
	auditURL := mustEnv("AUDIT_URL", rt.DefaultURL("127.0.0.1:8082"))
	proxyID := mustEnv("PROXY_SERVICE_ID", mtls.SSHProxy)
	if rt.Enabled() && proxyID != mtls.SSHProxy {
		// Under mutual TLS the Vault takes this proxy's identity from its
		// certificate; a different name here could only ever be refused.
		log.Fatalf("ssh-proxy: PROXY_SERVICE_ID=%q, but the identity of this proxy is its certificate's, %q — remove PROXY_SERVICE_ID", proxyID, mtls.SSHProxy)
	}
	// Where captured commands go.
	recorderURL := os.Getenv("RECORDER_URL")

	// What happens to a session that cannot be recorded (ADR-0008). Required
	// is the default and refuses such sessions; it needs RECORDER_URL, and the
	// proxy will not start without it — a proxy that cannot record must not be
	// one that quietly accepts sessions. best-effort must be asked for by name.
	policy, err := proxycore.ParseRecordingPolicy(os.Getenv("RECORDING_POLICY"))
	if err != nil {
		log.Fatalf("ssh-proxy: RECORDING_POLICY: %v", err)
	}
	if policy == proxycore.RecordingRequired && recorderURL == "" {
		log.Fatalf("ssh-proxy: RECORDING_POLICY is %q (the default), which refuses sessions it cannot record, but RECORDER_URL is not set — "+
			"refusing to start. Set RECORDER_URL, or set RECORDING_POLICY=best-effort to run without recording (development only)", policy)
	}

	// Break-glass (ADR-0009): a recording waiver for a session the Session Broker
	// authorised, usable only while the recorder is not ready. Off unless asked
	// for by name, and meaningless without the required policy — best-effort
	// already runs unrecorded sessions, for everyone.
	breakGlass := os.Getenv("BREAKGLASS_ENABLED") == "true"
	if breakGlass && policy != proxycore.RecordingRequired {
		log.Printf("ssh-proxy: BREAKGLASS_ENABLED is ignored under RECORDING_POLICY=%s", policy)
		breakGlass = false
	}

	// MVP: an ephemeral host key generated at process start. Production
	// needs a persisted, rotated identity (docs/security/network-security.md) — this is a
	// deliberate simplification, not an oversight.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generating host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("host signer: %v", err)
	}

	// Each client is pinned to the identity of the one service it calls: the
	// proxy only ever sends a scope token to the Vault, and commands to the recorder.
	peer := func(url, service string) *http.Client {
		c, err := rt.Client(mtls.Peer{URL: url, Service: service})
		if err != nil {
			log.Fatalf("ssh-proxy: %v", err)
		}
		return c
	}
	vaultClient := &infrastructure.VaultCredentialHTTPClient{BaseURL: vaultURL, Client: peer(vaultURL, mtls.PasswordVault)}
	auditClient := &infrastructure.AuditHTTPClient{BaseURL: auditURL, Client: peer(auditURL, mtls.AuditService)}
	var recorderHTTP *http.Client
	if recorderURL != "" {
		recorderHTTP = peer(recorderURL, mtls.CommandRecorder)
	}
	fetcher := proxycore.NewCredentialFetcher(vaultClient, proxyID)
	terminator := proxycore.NewTerminator(auditClient)
	listener := proxycore.NewListener(fetcher, terminator)

	pending := infrastructure.NewPendingSessions()

	ln, err := net.Listen("tcp", ":"+sshPort)
	if err != nil {
		log.Fatalf("ssh listen: %v", err)
	}

	secretInputs := infrastructure.NewSecretInputRegistry()
	server := &interfaces.SSHServer{
		HostSigner:       hostSigner,
		Pending:          pending,
		Listener:         listener,
		DialTimeout:      10 * time.Second,
		SecretTyperReady: secretInputs.Register,
	}

	var asyncRecorder *infrastructure.AsyncRecorder
	switch policy {
	case proxycore.RecordingRequired:
		// Each command line is acknowledged by the Command Recorder BEFORE it
		// is passed on to the target; a session is refused when the recorder
		// is not ready. See proxycore.RecordingConfig and ADR-0008.
		recorder := &infrastructure.CommandRecorderHTTPClient{BaseURL: recorderURL, Client: recorderHTTP}
		listener.Recording = proxycore.RecordingConfig{
			Policy: proxycore.RecordingRequired,
			Strict: &infrastructure.SyncRecorder{Sender: recorder},
			Gate:   recorder,
		}
		log.Printf("ssh-proxy: recording policy REQUIRED — sessions are refused when the Command Recorder cannot take them, " +
			"and a command is sent to the target only after it has been recorded")
		if breakGlass {
			// What a waived session's commands go to: sent without being waited
			// for, so an emergency session is never stalled by the recorder
			// that is, by definition, in trouble.
			asyncRecorder = infrastructure.NewAsyncRecorder(&infrastructure.CommandRecorderHTTPClient{BaseURL: recorderURL, Client: recorderHTTP}, 1024, 100)
			listener.Recording.Sink = asyncRecorder
			listener.Recording.BreakGlass = true
			log.Printf("ssh-proxy: BREAK-GLASS ENABLED — a session the Session Broker authorised for break-glass runs even when the " +
				"Command Recorder is NOT ready, with commands recorded best-effort. Every such session is audited (session.breakglass)")
		}
	default:
		// Commands are sent to the Command Recorder asynchronously, in
		// batches, so a slow or unreachable recorder can never stall a live
		// session — see infrastructure.AsyncRecorder, including what that costs.
		log.Printf("ssh-proxy: recording policy BEST-EFFORT — a session whose commands cannot be recorded CONTINUES, and those commands are lost. Not for production")
		listener.Recording = proxycore.RecordingConfig{Policy: proxycore.RecordingBestEffort, Sink: infrastructure.StdoutRecorder{}}
		if recorderURL != "" {
			asyncRecorder = infrastructure.NewAsyncRecorder(&infrastructure.CommandRecorderHTTPClient{BaseURL: recorderURL, Client: recorderHTTP}, 1024, 100)
			listener.Recording.Sink = asyncRecorder
		} else {
			log.Printf("ssh-proxy: RECORDER_URL not set — captured commands are only logged, NOT recorded for replay")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		log.Printf("ssh-proxy: SSH listener on :%s", sshPort)
		if err := server.Serve(ctx, ln); err != nil {
			log.Printf("ssh-proxy: SSH server stopped: %v", err)
		}
	}()

	log.Printf("ssh-proxy: tickets issued here send the operator to %s (SSH_PUBLIC_ENDPOINT)", endpoint)
	httpServer := interfaces.NewHTTPServer(pending, endpoint)
	httpServer.SecretInputs = secretInputs
	httpServer.Fetcher = fetcher
	httpServer.SecretAuditor = auditClient
	httpServer.Admit = listener.Probe // refuse before issuing a ticket, not after
	// The same registry as the listener's: the route that revokes a session and the
	// pipeline that serves it must talk about the same connections (ADR-0018).
	httpServer.Live = listener.Live
	log.Printf("ssh-proxy: internal API on :%s (HTTP/JSON — see /NOTES_SANDBOX.md)", httpPort)
	log.Printf("  -> vault: %s", vaultURL)
	log.Printf("  -> audit: %s", auditURL)
	if recorderURL != "" {
		log.Printf("  -> command-recorder: %s", recorderURL)
	}

	go func() {
		log.Fatal(rt.ListenAndServe(":"+httpPort, httpServer.Routes(), interfaces.CallerRules()))
	}()

	// On SIGTERM/SIGINT (a rolling update, say) flush what is still queued,
	// so the last commands of live sessions are not lost with the process.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("ssh-proxy: shutting down")
	cancel()
	if asyncRecorder != nil {
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if err := asyncRecorder.Close(flushCtx); err != nil {
			log.Printf("ssh-proxy: could not flush recorded commands before exit: %v (%d lost in total)", err, asyncRecorder.Dropped())
		}
	}
}

// publicEndpoint reads SSH_PUBLIC_ENDPOINT, host:port with a port from 1 to 65535; absent, the
// loopback address of the SSH listener, as before ADR-0046. Anything else stops the proxy: an
// operator sent to an address that is not this instance holds a ticket that opens nothing.
func publicEndpoint(sshPort string) string {
	v := os.Getenv("SSH_PUBLIC_ENDPOINT")
	if v == "" {
		return "127.0.0.1:" + sshPort
	}
	host, port, err := net.SplitHostPort(v)
	n, perr := strconv.Atoi(port)
	if err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
		log.Fatalf("ssh-proxy: SSH_PUBLIC_ENDPOINT must be host:port (the address operators reach this instance at), got %q — refusing to start", v)
	}
	return v
}

// main dispatches version before entering the proxy lifecycle.
func main() {
	if err := command.NewServiceCommand("ssh-proxy", runService).Execute(); err != nil {
		log.Fatalf("ssh-proxy: %v", err)
	}
}
