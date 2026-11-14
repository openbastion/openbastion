package infrastructure

import (
	"context"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// ProtocolProxyRouter sends a session only to the pool selected from the stored
// session protocol. A failure never falls back to a different protocol family.
type ProtocolProxyRouter struct{ pools map[string]*ProxyPool }

func NewProtocolProxyRouter(pools map[string]*ProxyPool) (*ProtocolProxyRouter, error) {
	if pools["ssh"] == nil || pools["vnc"] == nil {
		return nil, fmt.Errorf("protocol proxy router requires SSH and VNC pools")
	}
	copyPools := make(map[string]*ProxyPool, len(pools)+1)
	for protocol, pool := range pools {
		if pool == nil {
			return nil, fmt.Errorf("proxy pool for %q is nil", protocol)
		}
		copyPools[protocol] = pool
	}
	copyPools["rdp"] = copyPools["vnc"]
	return &ProtocolProxyRouter{pools: copyPools}, nil
}
func (r *ProtocolProxyRouter) EstablishSession(ctx context.Context, sessionID, protocol, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool, clipboard domain.ClipboardRights) (string, string, error) {
	// RDP is served by the screen proxies, VNC's pool (ADR-0088); whether it is open is the
	// Broker's decision (RDP_ENABLED), taken before any scope, and the proxy's own again.
	pool := r.pools[protocol]
	if pool == nil {
		return "", "", fmt.Errorf("no proxy pool for protocol %q", protocol)
	}
	return pool.EstablishSession(ctx, sessionID, protocol, targetHost, targetUser, scopeToken, ttl, breakGlass, clipboard)
}
func (r *ProtocolProxyRouter) RevokeSession(ctx context.Context, protocol, sessionID string, remaining time.Duration) error {
	if protocol == "rdp" {
		protocol = "vnc"
	}
	pool := r.pools[protocol]
	if pool == nil {
		return fmt.Errorf("no proxy pool for protocol %q", protocol)
	}
	return pool.RevokeSession(ctx, sessionID, remaining)
}

// InjectVaultSecret routes the one-use scope to the proxy pool selected from
// the persisted protocol and the instance affinity established at connect time.
func (r *ProtocolProxyRouter) InjectVaultSecret(ctx context.Context, protocol, sessionID, accountID, scopeToken string) error {
	if protocol == "rdp" {
		protocol = "vnc"
	}
	pool := r.pools[protocol]
	if pool == nil {
		return fmt.Errorf("no proxy pool for protocol %q", protocol)
	}
	return pool.InjectVaultSecret(ctx, sessionID, accountID, scopeToken)
}
