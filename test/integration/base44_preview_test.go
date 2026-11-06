// The Base44 preview, running (deploy/base44/docker-compose.yml): an operator opens the seeded
// accounts. The SSH one through the published port; the VNC one through the Vite server, on one
// origin, as the browser does (ADR-0071), whose target is a real TigerVNC showing `cat` in a
// terminal, so a key that reaches it changes what the screen shows.
//
// Skipped without BASE44_PREVIEW_URL: this test does not start the stack, which is long to build.
//
//	docker compose -f deploy/base44/docker-compose.yml up -d --build --wait
//	BASE44_PREVIEW_URL=http://localhost:3000 go test ./test/integration/ -run TestBase44Preview -v
package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

// The seeded SSH account: a session, a one-use ticket, and a shell on the real demonstration target
// through the published port, with what is typed recorded.
func TestBase44Preview_AnOperatorOpensTheSeededSSHSession(t *testing.T) {
	preview := os.Getenv("BASE44_PREVIEW_URL")
	if preview == "" {
		t.Skip("BASE44_PREVIEW_URL not set: this test needs the preview stack running")
	}
	token, status := gatewayLogin(t, preview, "operator", "openbastion-demo")
	if status != http.StatusOK {
		t.Fatalf("login through the preview: %d", status)
	}
	api := screenAPI{t: t, url: preview}
	status, raw := api.call(token, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "acc_demo", "protocol": "ssh", "justification": "preview", "durationMinutes": 5})
	if status != http.StatusCreated {
		t.Fatalf("session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")
	defer api.call(token, http.MethodDelete, "/sessions/"+id, nil)

	endpoint, ticket, status := gatewayConnect(t, preview, token, id)
	if status != http.StatusOK {
		t.Fatalf("connect: %d", status)
	}
	if endpoint != "localhost:2222" {
		t.Fatalf("connect sends the operator to %q, not to the published port", endpoint)
	}
	sh := openShell(t, endpoint, ticket)
	fmt.Fprint(sh.stdin, "whoami\r")
	sh.waitFor("out:whoami")

	// The ticket opened the shell above: it opens nothing else.
	if client, err := ssh.Dial("tcp", endpoint, &ssh.ClientConfig{
		User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	}); err == nil {
		client.Close()
		t.Fatal("the same ticket opened a second connection")
	}
}

func TestBase44Preview_AnOperatorOpensTheSeededScreenThroughTheOneOrigin(t *testing.T) {
	preview := os.Getenv("BASE44_PREVIEW_URL")
	if preview == "" {
		t.Skip("BASE44_PREVIEW_URL not set: this test needs the preview stack running")
	}
	token, status := gatewayLogin(t, preview, "operator", "openbastion-demo")
	if status != http.StatusOK {
		t.Fatalf("login through the preview: %d", status)
	}
	api := screenAPI{t: t, url: preview}
	newAttach := func(t *testing.T) (string, screenAttachment) {
		t.Helper()
		api := api.in(t)
		status, raw := api.call(token, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "acc_demo_vnc", "protocol": "vnc", "justification": "preview", "durationMinutes": 5})
		if status != http.StatusCreated {
			t.Fatalf("session: %d %s", status, raw)
		}
		id := jsonField(t, raw, "id")
		return id, api.connect(token, id)
	}

	t.Run("the screen opens, the keyboard changes it, and ending the session says so", func(t *testing.T) {
		api := api.in(t)
		id, attach := newAttach(t)
		conn := dialScreen(t, preview, attach.path, attach.cookie)
		defer conn.Close(websocket.StatusNormalClosure, "")
		if hello := readScreen(t, conn); hello.kind != 2 || hello.helloProtocol != 2 || hello.helloSession != id {
			t.Fatalf("first message: %+v", hello)
		}
		before := readFrame(t, conn)

		// `cat` echoes: what TigerVNC shows changes only if the key reached the desktop.
		for _, key := range []uint32{0x6f, 0x62, 0xff0d} {
			writeScreen(t, conn, inputKey(key, true))
			writeScreen(t, conn, inputKey(key, false))
		}
		changed := false
		deadline := time.Now().Add(15 * time.Second)
		for !changed && time.Now().Before(deadline) {
			frame := readFrame(t, conn)
			changed = !bytes.Equal(frame.png, before.png)
		}
		if !changed {
			t.Fatal("the screen did not change after the keys: they did not reach the target")
		}

		if status, raw := api.call(token, http.MethodDelete, "/sessions/"+id, nil); status/100 != 2 {
			t.Fatalf("terminate: %d %s", status, raw)
		}
		if end := readUntilEnd(t, conn); end.endText != "session_revoked" {
			t.Fatalf("END = %q, want session_revoked", end.endText)
		}
	})

	dialFrom := func(attach screenAttachment, origin string) (*websocket.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(preview, "http")+attach.path, &websocket.DialOptions{
			HTTPHeader:   http.Header{"Cookie": {"ob_screen_attach=" + attach.cookie}, "Origin": {origin}},
			Subprotocols: []string{"openbastion.screen.v1"},
		})
		return conn, err
	}

	t.Run("a page of another site does not open the screen, and does not spend the cookie", func(t *testing.T) {
		id, attach := newAttach(t)
		defer api.in(t).call(token, http.MethodDelete, "/sessions/"+id, nil)
		if conn, err := dialFrom(attach, "https://attacker.example"); err == nil {
			conn.Close(websocket.StatusNormalClosure, "")
			t.Fatal("another origin opened the screen")
		}
		conn := dialScreen(t, preview, attach.path, attach.cookie)
		defer conn.Close(websocket.StatusNormalClosure, "")
		readFrame(t, conn)
	})

	if suffix := os.Getenv("BASE44_PUBLIC_HOST_SUFFIX"); suffix != "" {
		t.Run("the preview's public host opens it, and a host that merely ends like it does not", func(t *testing.T) {
			id, attach := newAttach(t)
			defer api.in(t).call(token, http.MethodDelete, "/sessions/"+id, nil)
			if conn, err := dialFrom(attach, "https://evil"+suffix); err == nil {
				conn.Close(websocket.StatusNormalClosure, "")
				t.Fatalf("https://evil%s opened the screen", suffix)
			}
			conn, err := dialFrom(attach, "https://3000-sandbox."+suffix)
			if err != nil {
				t.Fatalf("the preview's public host: %v", err)
			}
			defer conn.Close(websocket.StatusNormalClosure, "")
			readFrame(t, conn)
		})
	}
}
