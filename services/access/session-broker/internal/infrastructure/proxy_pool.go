package infrastructure

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// MaxProxyInstances bounds SSH_PROXY_URLS (ADR-0046): every termination calls each one.
const MaxProxyInstances = 16

// InstanceClient is what the pool needs of one instance: the shape of application.ProxyClient,
// which ProxyClientHTTPClient implements.
type InstanceClient interface {
	EstablishSession(ctx context.Context, sessionID, protocol, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool, clipboard domain.ClipboardRights) (string, string, error)
	RevokeSession(ctx context.Context, sessionID string, remaining time.Duration) error
	InjectVaultSecret(ctx context.Context, sessionID, accountID, scopeToken string) error
}

// ProxyInstance is one proxy, addressed directly. Name is its stable identity within the pool
// (normally https://host:port), Client is the pinned-mTLS client.
type ProxyInstance struct {
	Name   string
	Client InstanceClient
}

// ProxyPool uses rendezvous hashing on (session ID, instance name). Every Broker replica with
// the same configured pool therefore selects the same proxy for a session, without a mutable
// affinity table. The selected instance is the only one used for establish/inject; no fallback
// is safe because it would make subsequent control operations target a different proxy.
type ProxyPool struct {
	instances []ProxyInstance
}

// NewProxyPool returns a pool of 1 to MaxProxyInstances instances with unique stable names.
func NewProxyPool(instances []ProxyInstance) (*ProxyPool, error) {
	if len(instances) == 0 || len(instances) > MaxProxyInstances {
		return nil, fmt.Errorf("a pool holds 1 to %d proxy instances, got %d", MaxProxyInstances, len(instances))
	}
	seen := make(map[string]struct{}, len(instances))
	for _, in := range instances {
		if in.Name == "" || in.Client == nil {
			return nil, fmt.Errorf("proxy instances require a stable name and client")
		}
		if _, ok := seen[in.Name]; ok {
			return nil, fmt.Errorf("duplicate proxy instance name %q", in.Name)
		}
		seen[in.Name] = struct{}{}
	}
	copyInstances := append([]ProxyInstance(nil), instances...)
	return &ProxyPool{instances: copyInstances}, nil
}

// Size is the number of instances.
func (p *ProxyPool) Size() int { return len(p.instances) }

func (p *ProxyPool) selected(sessionID string) ProxyInstance {
	var chosen ProxyInstance
	var highest uint64
	for i, in := range p.instances {
		sum := sha256.Sum256([]byte(sessionID + "\x00" + in.Name))
		score := binary.BigEndian.Uint64(sum[:8])
		if i == 0 || score > highest {
			chosen, highest = in, score
		}
	}
	return chosen
}

// EstablishSession asks only the deterministic owner of this session. If it is
// unavailable the operation fails closed; another instance cannot own the ticket
// and later receive the session's privileged control commands.
func (p *ProxyPool) EstablishSession(ctx context.Context, sessionID, protocol, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool, clipboard domain.ClipboardRights) (string, string, error) {
	in := p.selected(sessionID)
	endpoint, ticket, err := in.Client.EstablishSession(ctx, sessionID, protocol, targetHost, targetUser, scopeToken, ttl, breakGlass, clipboard)
	if err != nil {
		if errors.Is(err, domain.ErrRecordingUnavailable) {
			return "", "", err
		}
		return "", "", fmt.Errorf("%s: %w", in.Name, err)
	}
	return endpoint, ticket, nil
}

// InjectVaultSecret sends the scope to the same deterministic instance that owns
// the session's ticket, including when another Broker replica handles the request.
func (p *ProxyPool) InjectVaultSecret(ctx context.Context, sessionID, accountID, scopeToken string) error {
	in := p.selected(sessionID)
	if err := in.Client.InjectVaultSecret(ctx, sessionID, accountID, scopeToken); err != nil {
		return fmt.Errorf("%s: inject vault secret: %w", in.Name, err)
	}
	return nil
}

// RevokeSession asks every instance at once and succeeds only if every one confirms: one that
// cannot be reached may still relay the session, and the Broker must not call it ended.
func (p *ProxyPool) RevokeSession(ctx context.Context, sessionID string, remaining time.Duration) error {
	errs := make([]error, len(p.instances))
	var wg sync.WaitGroup
	for i, in := range p.instances {
		wg.Add(1)
		go func(i int, in ProxyInstance) {
			defer wg.Done()
			if err := in.Client.RevokeSession(ctx, sessionID, remaining); err != nil {
				errs[i] = fmt.Errorf("%s: %w", in.Name, err)
			}
		}(i, in)
	}
	wg.Wait()
	var failed []string
	for _, err := range errs {
		if err != nil {
			failed = append(failed, err.Error())
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d proxy instance(s) did not confirm the revocation: %s", len(failed), len(p.instances), strings.Join(failed, "; "))
	}
	return nil
}
