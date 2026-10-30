package integration_test

import (
	"crypto/ed25519"
	"strings"

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
