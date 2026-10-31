// Package proxycore implements the pipeline shared by all nine protocol
// proxies (SSH, RDP/VNC, Database, Kubernetes, ...): credential fetch,
// protocol relay, recording, and termination.
//
// See docs/architecture/components.md, « Couche Proxy », and ADR-0006. Factoring this
// pipeline once means the most security-sensitive logic — fetching a
// credential and purging it — is implemented and tested a single time,
// not duplicated nine times with room to drift (ADR-0003, ADR-0006).
package proxycore

import (
	"context"
	"io"
)

// Codec relays a single protocol-specific session between a client
// connection and a target system, using an already-fetched credential.
// Each protocol proxy implements exactly one Codec; everything else in
// the pipeline is protocol-agnostic and lives in this package.
type Codec interface {
	// Relay copies protocol traffic between client and target, injecting
	// the credential as required by the protocol. It must not retain the
	// credential beyond the call, and must return promptly once ctx is
	// cancelled (session termination or timeout).
	Relay(ctx context.Context, client, target io.ReadWriter, credential *Credential) error
}
