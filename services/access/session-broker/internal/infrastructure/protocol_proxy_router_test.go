package infrastructure_test

import (
	"context"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func TestProtocolProxyRouterRoutesVNCWithoutSSHFallback(t *testing.T) {
	ssh := &fakeInstance{name: "ssh"}
	vnc := &fakeInstance{name: "vnc"}
	sshPool, err := infrastructure.NewProxyPool([]infrastructure.ProxyInstance{{Name: "ssh", Client: ssh}})
	if err != nil {
		t.Fatal(err)
	}
	vncPool, err := infrastructure.NewProxyPool([]infrastructure.ProxyInstance{{Name: "vnc", Client: vnc}})
	if err != nil {
		t.Fatal(err)
	}
	router, err := infrastructure.NewProtocolProxyRouter(map[string]*infrastructure.ProxyPool{"ssh": sshPool, "vnc": vncPool})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := router.EstablishSession(context.Background(), "v1", "vnc", "target:5900", "operator", "scope", time.Minute, false); err != nil {
		t.Fatal(err)
	}
	if vnc.establishes != 1 || ssh.establishes != 0 {
		t.Fatalf("VNC calls=%d SSH calls=%d", vnc.establishes, ssh.establishes)
	}
	// RDP goes to the screen proxies, never to SSH's (ADR-0088): whether it is open is decided
	// before, by the Broker, and again by the proxy.
	if _, _, err := router.EstablishSession(context.Background(), "r1", "rdp", "target:3389", "operator", "scope", time.Minute, false); err != nil {
		t.Fatal(err)
	}
	if vnc.establishes != 2 || ssh.establishes != 0 {
		t.Fatalf("RDP: VNC calls=%d SSH calls=%d", vnc.establishes, ssh.establishes)
	}
}
