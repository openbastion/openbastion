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
	if _, _, err := router.EstablishSession(context.Background(), "r1", "rdp", "target:3389", "operator", "scope", time.Minute, false); err == nil {
		t.Fatal("RDP must remain unavailable")
	}
	if vnc.establishes != 1 || ssh.establishes != 0 {
		t.Fatal("unsupported RDP fell back to a proxy")
	}
}
