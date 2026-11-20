package interfaces

import (
	"context"
	"errors"

	"crypto/x509"
	"encoding/json"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/engine"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

// The screen the Broker resolved (ADR-0132) rides the one-use ticket, and the session's codec is
// opened with it: bitmap leaves the pipeline out, 16 is asked, and the proxy's own codec is left
// as it was for every other session.
func TestEstablishSessionCarriesTheScreenChoiceToTheSessionCodec(t *testing.T) {
	shared := &engine.RDPCodec{TLSRoots: x509.NewCertPool(), GraphicsPipeline: true}
	s := testHTTPServer(readyGate{}).WithRDP(shared)
	w := httptest.NewRecorder()
	body := `{"session_id":"r1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60,"screen_channel":"bitmap","color_depth":16}`
	s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out establishResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	pending, err := s.pending.Consume(out.ConnectionTicket, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if pending.ScreenChannel != "bitmap" || pending.ColorDepth != 16 {
		t.Fatalf("the ticket carries %q, %d", pending.ScreenChannel, pending.ColorDepth)
	}
	codec, err := sessionScreen(shared, pending)
	if err != nil {
		t.Fatal(err)
	}
	session, ok := codec.(*engine.RDPCodec)
	if !ok || session == shared || session.GraphicsPipeline || session.ColorDepth != 16 {
		t.Fatalf("the session's codec is %+v", codec)
	}
	if !shared.GraphicsPipeline || shared.ColorDepth != 0 {
		t.Fatal("the proxy's codec was changed for every session")
	}
	// No choice: the proxy's codec itself, as before.
	if codec, err := sessionScreen(shared, infrastructure.PendingScreenSession{SessionID: "r2"}); err != nil || codec != shared {
		t.Fatalf("no choice: %v, %v", codec, err)
	}
}

// SCREEN_RDPGFX=false is a ceiling (ADR-0132 §4): graphics chosen opens the session on bitmap.
func TestSessionScreen_TheDeploymentCeiling(t *testing.T) {
	shared := &engine.RDPCodec{TLSRoots: x509.NewCertPool()}
	codec, err := sessionScreen(shared, infrastructure.PendingScreenSession{SessionID: "r1", ScreenChannel: "graphics", ColorDepth: 32})
	if err != nil {
		t.Fatal(err)
	}
	if session := codec.(*engine.RDPCodec); session.GraphicsPipeline || session.ColorDepth != 32 {
		t.Fatalf("graphics chosen with the pipeline off: %+v", session)
	}
}

// A screen choice is RDP's alone, and only of the values the Broker resolves to: anything else is
// refused before a ticket, like a Broker that got something wrong.
func TestEstablishSessionRefusesAScreenChoiceItCannotApply(t *testing.T) {
	for name, body := range map[string]string{
		"VNC with a channel": `{"session_id":"v1","vault_scope_token":"scope","protocol":"vnc","ttl_seconds":60,"screen_channel":"bitmap"}`,
		"VNC with a depth":   `{"session_id":"v1","vault_scope_token":"scope","protocol":"vnc","ttl_seconds":60,"color_depth":16}`,
		"an unknown channel": `{"session_id":"r1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60,"screen_channel":"h264"}`,
		"an unknown depth":   `{"session_id":"r1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60,"color_depth":24}`,
		"a negative depth":   `{"session_id":"r1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60,"color_depth":-16}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := testHTTPServer(readyGate{}).WithRDP(&engine.RDPCodec{TLSRoots: x509.NewCertPool()})
			w := httptest.NewRecorder()
			s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
			if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "connection_ticket") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	// A codec that cannot apply a choice does not open the session on another screen.
	if _, err := sessionScreen(fixedCodec{}, infrastructure.PendingScreenSession{ScreenChannel: "bitmap"}); err == nil {
		t.Fatal("a choice the codec cannot apply was ignored")
	}
}

// fixedCodec is a codec without a screen choice of its own.
type fixedCodec struct{}

func (fixedCodec) Open(context.Context, *proxycore.Credential) (proxycore.ScreenSession, error) {
	return nil, errors.New("not opened in this test")
}
