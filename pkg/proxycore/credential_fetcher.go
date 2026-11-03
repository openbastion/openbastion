package proxycore

import (
	"context"
	"errors"
)

// Credential holds secret material in memory for the lifetime of a single
// session. It is the ONLY structure in the entire system allowed to hold
// a target credential — see ADR-0003 (docs/adr/).
//
// Callers MUST call Purge as soon as the credential is no longer needed
// (session end, error, or termination). Purge overwrites the backing byte
// slice before the Credential becomes unusable, so the secret does not
// linger in memory or in a later heap dump.
type Credential struct {
	Type     string // e.g. "ssh_private_key", "password"
	material []byte
	purged   bool

	// TargetHost and HostKey are the target the Vault gave the secret for (ADR-0039): its
	// address and pinned SSH host key. TargetUser, TLSCertificateSHA256 and TargetDomain carry
	// the target account and trust metadata for graphical protocols (ADR-0071).
	TargetHost           string
	HostKey              string
	TargetUser           string
	TLSCertificateSHA256 string
	TargetDomain         string
}

// Fetched is what the Vault delivers for one session (ADR-0039, ADR-0071).
type Fetched struct {
	Type                 string
	Material             []byte
	TargetHost           string
	HostKey              string
	TargetUser           string
	TLSCertificateSHA256 string
	TargetDomain         string
}

func newCredential(credType string, material []byte) *Credential {
	return &Credential{Type: credType, material: material}
}

// Material returns the raw secret bytes. It panics if called after Purge:
// a use-after-purge is exactly the class of bug this type exists to make
// loud and immediate rather than a silent, hard-to-trace leak.
func (c *Credential) Material() []byte {
	if c.purged {
		panic("proxycore: credential accessed after purge")
	}
	return c.material
}

// Purge overwrites the credential material with zero bytes and marks the
// credential unusable. It is idempotent and safe to call from multiple
// cleanup paths (normal completion and deferred/error handling both).
func (c *Credential) Purge() {
	if c.purged {
		return
	}
	for i := range c.material {
		c.material[i] = 0
	}
	c.TargetUser = ""
	c.TLSCertificateSHA256 = ""
	c.TargetDomain = ""
	c.purged = true
}

// Purged reports whether Purge has run. It never panics, unlike Material,
// so callers (including cross-process integration tests that cannot see
// the zeroed bytes directly) can confirm cleanup happened.
func (c *Credential) Purged() bool {
	return c.purged
}

// VaultClient is the minimal interface the Credential Fetcher needs
// against the Vault. In production this is backed by the
// VaultCredentialIssuance gRPC client (proto/vault/v1/vault.proto); it is
// abstracted here so pkg/proxycore has zero dependency on transport, or
// on the Vault service itself — only on this contract.
type VaultClient interface {
	FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (Fetched, error)
}

// CredentialFetcher retrieves an ephemeral credential directly from the
// Vault, over the calling proxy's own mTLS identity — never via the
// Session Broker or any other control-plane component (ADR-0003).
type CredentialFetcher struct {
	vault          VaultClient
	callingProxyID string
}

func NewCredentialFetcher(vault VaultClient, callingProxyID string) *CredentialFetcher {
	return &CredentialFetcher{vault: vault, callingProxyID: callingProxyID}
}

// Fetch exchanges a scope token — issued by the Broker via
// VaultAuthorization.AuthorizeScope, never by this component — for the
// actual credential material. The scope token is single-use; a replayed
// call is expected to be rejected by the Vault.
func (f *CredentialFetcher) Fetch(ctx context.Context, scopeToken string) (*Credential, error) {
	got, err := f.vault.FetchCredential(ctx, scopeToken, f.callingProxyID)
	if err != nil {
		return nil, err
	}
	c := newCredential(got.Type, got.Material)
	c.TargetHost, c.HostKey = got.TargetHost, got.HostKey
	c.TargetUser, c.TLSCertificateSHA256, c.TargetDomain = got.TargetUser, got.TLSCertificateSHA256, got.TargetDomain
	return c, nil
}

// ErrHostKeyMismatch: the target is not the one the Vault pinned for the secret (ADR-0039) —
// another host key, no pinned key, or another address. A codec returns it (wrapped) before
// it sends anything of the secret; the Listener audits it as session.host_key_mismatch.
var ErrHostKeyMismatch = errors.New("the target did not present its pinned host key")
