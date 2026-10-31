package integration_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// targetHostSigner is the host key every test target presents, and targetHostKey the key
// every test account is pinned to (ADR-0039): a target with another key is an impostor.
var targetHostSigner = func() ssh.Signer {
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		panic(err)
	}
	return s
}()

var targetHostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(targetHostSigner.PublicKey())))

// withHostKey pins targetHostKey on an onboarding body that names no key of its own; a body
// with "hostKey": nil goes without one (to prove the Vault refuses it).
func withHostKey(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		out[k] = v
	}
	if v, ok := fields["hostKey"]; !ok {
		out["hostKey"] = targetHostKey
	} else if v == nil {
		delete(out, "hostKey")
	}
	return out
}

// playVaultAccounts plays the Vault on 127.0.0.1:port for the one call a Broker makes when a
// session is asked (ADR-0043): it reads the account, and every account here exists and is
// pinned. For the scenarios about the Broker alone, which never connect to a target: nothing
// else is answered, so a test that does reach further fails loudly.
func playVaultAccounts(t *testing.T, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("play the Vault on %s: %v", port, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := strings.CutPrefix(r.URL.Path, "/vault/v1/accounts/")
		if r.Method != http.MethodGet || !ok || id == "" {
			http.Error(w, "this Vault only plays the account read", http.StatusNotImplemented)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "targetHost": "10.0.0.9:22", "username": "root", "hostKeyFingerprint": "SHA256:played"})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}
