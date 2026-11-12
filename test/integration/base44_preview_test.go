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
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
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
		// The pointer is drawn by default (SCREEN_DRAW_POINTER, ADR-0091): the HELLO says so.
		if hello := readScreen(t, conn); hello.kind != 2 || hello.helloProtocol != 2 || hello.helloSession != id || hello.helloFlags != 1 {
			t.Fatalf("first message: %+v", hello)
		}
		var view screenView
		before := view.read(t, conn)
		// No window manager: the keyboard goes to the window under the pointer, which the X server
		// keeps from one session to the next. xterm is at the top left. After the first frame: the
		// pointer's place is checked against its size.
		writeScreen(t, conn, inputPointer(100, 100, 0))
		time.Sleep(300 * time.Millisecond)
		// `cat` echoes: what TigerVNC shows changes only if the key reached the desktop.
		for _, key := range []uint32{0x6f, 0x62, 0xff0d} {
			writeScreen(t, conn, inputKey(key, true))
			writeScreen(t, conn, inputKey(key, false))
		}
		changed, last := false, before
		deadline := time.Now().Add(15 * time.Second)
		for !changed && time.Now().Before(deadline) {
			last = view.read(t, conn)
			// Anywhere in the terminal (80x24 at the top left), where `cat` writes, but around the
			// pointer at (100,100): its drawing is no proof the keys arrived.
			changed = differsIn(t, before.png, last.png, image.Rect(0, 0, 480, 316), image.Rect(80, 80, 120, 120))
		}
		if !changed {
			t.Fatal("the screen did not change after the keys: they did not reach the target")
		}

		// The pointer (ADR-0091): TigerVNC sends its shape (Cursor pseudo-encoding) and leaves it out
		// of its framebuffer; the proxy draws it where the operator put it, in the recorded frame.
		const px, py = 300, 200
		// Far from the text `cat` echoes at the top of the terminal: only the pointer changes there.
		// A few steps, as a hand moves: xterm hides the pointer while one types, and TigerVNC sends its
		// shape again only once the pointer has moved on (seen on the sandbox, 12 November 2026).
		for _, step := range []uint16{40, 20, 0} {
			writeScreen(t, conn, inputPointer(px-step, py-step, 0))
			time.Sleep(150 * time.Millisecond)
		}
		drawn := false
		for deadline := time.Now().Add(10 * time.Second); !drawn && time.Now().Before(deadline); {
			frame := view.read(t, conn)
			drawn = differsAround(t, last.png, frame.png, px, py)
			if dir := os.Getenv("BASE44_PREVIEW_DUMP"); dir != "" && drawn {
				_ = os.WriteFile(filepath.Join(dir, "vnc-pointer.png"), frame.png, 0o600)
			}
		}
		if !drawn {
			t.Fatal("no frame shows the pointer where the operator put it")
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

// differsAround says whether two frames differ in the 32×32 square at (x, y).
func differsAround(t *testing.T, before, after []byte, x, y int) bool {
	t.Helper()
	a, err := png.Decode(bytes.NewReader(before))
	if err != nil {
		t.Fatal(err)
	}
	b, err := png.Decode(bytes.NewReader(after))
	if err != nil {
		t.Fatal(err)
	}
	for dy := -16; dy < 16; dy++ {
		for dx := -16; dx < 16; dx++ {
			if a.At(x+dx, y+dy) != b.At(x+dx, y+dy) {
				return true
			}
		}
	}
	return false
}

// screenView composes what the operator's page shows, key frames and partial frames alike
// (ADR-0092), written here from the wire format, apart from pkg/screenstream: it checks it too.
type screenView struct {
	screen   *image.RGBA
	sequence uint64
}

// read returns the next screen shown, as a PNG, whichever kind of frame made it.
func (v *screenView) read(t *testing.T, conn *websocket.Conn) screenMessage {
	t.Helper()
	for {
		m := readScreen(t, conn)
		switch m.kind {
		case 3:
			t.Fatalf("the session ended before a frame: %q", m.endText)
		case 1:
			decoded, err := png.Decode(bytes.NewReader(m.png))
			if err != nil {
				t.Fatalf("key frame %d: %v", m.sequence, err)
			}
			v.screen = image.NewRGBA(decoded.Bounds())
			draw.Draw(v.screen, v.screen.Bounds(), decoded, image.Point{}, draw.Src)
		case 4:
			width, height := binary.BigEndian.Uint32(m.raw[20:24]), binary.BigEndian.Uint32(m.raw[24:28])
			if v.screen == nil || m.sequence != v.sequence+1 || int(width) != v.screen.Bounds().Dx() || int(height) != v.screen.Bounds().Dy() {
				t.Fatalf("partial frame %d does not follow frame %d of its screen", m.sequence, v.sequence)
			}
			p := m.raw[32:]
			count, at := int(binary.BigEndian.Uint16(p)), 2
			for i := 0; i < count; i++ {
				x, y := int(binary.BigEndian.Uint32(p[at:])), int(binary.BigEndian.Uint32(p[at+4:]))
				n := int(binary.BigEndian.Uint32(p[at+16:]))
				rect, err := png.Decode(bytes.NewReader(p[at+20 : at+20+n]))
				if err != nil {
					t.Fatalf("partial frame %d, rectangle %d: %v", m.sequence, i, err)
				}
				bounds := rect.Bounds()
				draw.Draw(v.screen, image.Rect(x, y, x+bounds.Dx(), y+bounds.Dy()), rect, bounds.Min, draw.Src)
				at += 20 + n
			}
		default:
			continue
		}
		v.sequence = m.sequence
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, v.screen); err != nil {
			t.Fatal(err)
		}
		return screenMessage{kind: 1, sequence: m.sequence, png: encoded.Bytes()}
	}
}

// differsIn says whether two frames differ inside a rectangle, outside another.
func differsIn(t *testing.T, before, after []byte, area, except image.Rectangle) bool {
	t.Helper()
	a, err := png.Decode(bytes.NewReader(before))
	if err != nil {
		t.Fatal(err)
	}
	b, err := png.Decode(bytes.NewReader(after))
	if err != nil {
		t.Fatal(err)
	}
	for y := area.Min.Y; y < area.Max.Y; y++ {
		for x := area.Min.X; x < area.Max.X; x++ {
			if !image.Pt(x, y).In(except) && a.At(x, y) != b.At(x, y) {
				return true
			}
		}
	}
	return false
}
