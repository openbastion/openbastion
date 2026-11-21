package interfaces

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// What the proxy's screen socket hands the relay (ADR-0133): an operator's encrypted password goes
// on, as a key and a clipboard text do; anything else ends the input. At first a paste was refused
// here, before the relay could read it, and the session ended as target_unreachable.
func TestScreenSinkReceivesAnEncryptedPaste(t *testing.T) {
	key, _ := screenstream.EncodeInput(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61})
	clip, _ := screenstream.EncodeClipboardInput("x")
	in := screenstream.PasteInput{Ciphertext: make([]byte, 40)}
	in.ClientKey[0] = 0x04
	paste, err := screenstream.EncodePasteInput(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		data []byte
		ok   bool
	}{
		"a key": {key, true}, "a clipboard text": {clip, true}, "an encrypted paste": {paste, true},
		"20 unknown bytes": {make([]byte, 20), false},
	} {
		t.Run(name, func(t *testing.T) {
			got := make(chan error, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					got <- err
					return
				}
				defer conn.CloseNow()
				conn.SetReadLimit(4096)
				_, err = (&websocketScreenSink{conn: conn, inputCtx: r.Context()}).ReceiveInput(r.Context())
				got <- err
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseNow()
			if err := client.Write(ctx, websocket.MessageBinary, c.data); err != nil {
				t.Fatal(err)
			}
			if err := <-got; (err == nil) != c.ok {
				t.Fatalf("ReceiveInput: %v", err)
			}
		})
	}
}
