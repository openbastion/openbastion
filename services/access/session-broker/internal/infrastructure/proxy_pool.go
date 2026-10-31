package infrastructure

import (
	"context"
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
	EstablishSession(ctx context.Context, sessionID, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool) (string, string, error)
	RevokeSession(ctx context.Context, sessionID string, remaining time.Duration) error
}

// ProxyInstance is one proxy, addressed directly: Name is what the log may say of it (scheme and
// host), Client what the Broker calls it with.
type ProxyInstance struct {
	Name   string
	Client InstanceClient
}

// ProxyPool implements application.ProxyClient over several instances of one proxy family
// (ADR-0046). A ticket is issued by one instance, in turn; a revocation is asked of every
// instance, and is one only if every instance confirms it. The pool does not remember which
// instance holds what: a connect in flight during a termination meets the revocation memory of
// the instance it lands on (ADR-0018, rule 5), whichever that is.
type ProxyPool struct {
	instances []ProxyInstance
	mu        sync.Mutex
	next      int
}

// NewProxyPool returns a pool of 1 to MaxProxyInstances instances.
func NewProxyPool(instances []ProxyInstance) (*ProxyPool, error) {
	if len(instances) == 0 || len(instances) > MaxProxyInstances {
		return nil, fmt.Errorf("a pool holds 1 to %d proxy instances, got %d", MaxProxyInstances, len(instances))
	}
	return &ProxyPool{instances: instances}, nil
}

// Size is the number of instances.
func (p *ProxyPool) Size() int { return len(p.instances) }

// EstablishSession asks the instances in turn, each at most once, until one issues a ticket. The
// endpoint returned is that instance's own: the ticket is good there and nowhere else. If none
// does, a refusal to record (ADR-0008) is what the caller is told, if any instance said so.
func (p *ProxyPool) EstablishSession(ctx context.Context, sessionID, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool) (string, string, error) {
	p.mu.Lock()
	start := p.next
	p.next = (p.next + 1) % len(p.instances)
	p.mu.Unlock()

	var last, recording error
	for i := range p.instances {
		in := p.instances[(start+i)%len(p.instances)]
		endpoint, ticket, err := in.Client.EstablishSession(ctx, sessionID, targetHost, targetUser, scopeToken, ttl, breakGlass)
		if err == nil {
			return endpoint, ticket, nil
		}
		if errors.Is(err, domain.ErrRecordingUnavailable) {
			recording = err
		}
		last = fmt.Errorf("%s: %w", in.Name, err)
		if ctx.Err() != nil {
			break
		}
	}
	if recording != nil {
		return "", "", recording
	}
	return "", "", last
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
