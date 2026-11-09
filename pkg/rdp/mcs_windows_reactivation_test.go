package rdp

// ADR-0071, the Windows validation, the reactivation (MS-RDPBCGR 1.3.1.3), through the codec.
// Windows never sent the isolations a Deactivate All they could see. They read the stream
// themselves and passed over every slow-path PDU they did not know, the codec does not: CI run of
// PR #93 had the codec's second connection, which took back a disconnected session, end on a
// packet it refused. A target that always prompts for the password (fPromptForPassword) did not
// prompt under NLA: measured, the session opened with the delegated credentials.
//
// Two connections, each read by the codec's own ReadBitmapUpdate, which follows reactivations: the
// first opens the session, waits for its screen, and leaves it disconnected; the second takes it
// back. Each writes what it saw (reactivations, logon notification, size, how the stream ended) and
// its last screen, as a PNG to judge by eye. Nothing is typed: no secret reaches a screen.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation_Reactivation -v

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type reactivationRun struct {
	session     *CredSSPClientSession
	done        func()
	updates     chan RDPBitmapUpdate
	readErr     chan error
	framebuffer *RDPFramebuffer
	last        []byte
}

func openReactivationRun(address, pin, name string, roots *x509.CertPool, user, password string) (*reactivationRun, error) {
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		return nil, err
	}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	for _, step := range sequenceSteps(settings, user, password, "") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := step.run(ctx, session)
		cancel()
		if err != nil {
			done()
			return nil, fmt.Errorf("%s: %w", step.name, err)
		}
	}
	caps := session.serverCapabilities
	framebuffer, err := NewRDPFramebuffer(caps.DesktopWidth, caps.DesktopHeight)
	if err != nil {
		done()
		return nil, err
	}
	r := &reactivationRun{session: session, done: done, updates: make(chan RDPBitmapUpdate, 16), readErr: make(chan error, 1), framebuffer: framebuffer}
	// The codec's reader, as the proxy runs it: a reactivation is followed inside ReadBitmapUpdate.
	go func() {
		for {
			update, err := session.ReadBitmapUpdate(context.Background(), 10*time.Minute)
			if err != nil {
				r.readErr <- err
				close(r.updates)
				return
			}
			r.updates <- update
		}
	}()
	return r, nil
}

// watch applies updates until none comes for quiet, or until limit; an error ends the stream.
func (r *reactivationRun) watch(quiet, limit time.Duration) error {
	end := time.After(limit)
	for {
		select {
		case update, ok := <-r.updates:
			if !ok {
				return <-r.readErr
			}
			if w, h := r.framebuffer.Dimensions(); update.DesktopWidth != 0 && (uint32(update.DesktopWidth) != w || uint32(update.DesktopHeight) != h) {
				if err := r.framebuffer.Resize(update.DesktopWidth, update.DesktopHeight); err != nil {
					return err
				}
			}
			if message, err := r.framebuffer.Apply(update, time.Now()); err == nil {
				r.last = message.PNG
			}
		case <-time.After(quiet):
			return nil
		case <-end:
			return nil
		}
	}
}

func (r *reactivationRun) state() string {
	r.session.mu.Lock()
	defer r.session.mu.Unlock()
	return fmt.Sprintf("%d reactivation(s), logon notified %v, desktop %dx%d at %d bpp", r.session.reactivations, r.session.logonNotified,
		r.session.serverCapabilities.DesktopWidth, r.session.serverCapabilities.DesktopHeight, r.session.serverCapabilities.PreferredBitsPerPixel)
}

func TestRDPWindowsIsolation_Reactivation(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
	address, user, password := os.Getenv("RDP_WINDOWS_ADDRESS"), os.Getenv("RDP_WINDOWS_USER"), os.Getenv("RDP_WINDOWS_PASSWORD")
	pin, name := os.Getenv("RDP_WINDOWS_PIN"), os.Getenv("RDP_WINDOWS_SERVER_NAME")
	raw, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		t.Fatal("RDP_WINDOWS_CA_FILE holds no certificate")
	}
	dir := os.Getenv("RDP_WINDOWS_DUMP")
	var report []string
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		report = append(report, line)
	}
	defer func() {
		if dir != "" {
			_ = os.WriteFile(filepath.Join(dir, "reactivation.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
		}
	}()

	var failures []string
	for i := 1; i <= 2; i++ {
		run, err := openReactivationRun(address, pin, name, roots, user, password)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		werr := run.watch(10*time.Second, 120*time.Second)
		logf("connection %d: %s; stream: %v", i, run.state(), werr)
		if dir != "" && run.last != nil {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("reactivation-%d.png", i)), run.last, 0o644)
		}
		run.done() // the session stays on the target, disconnected
		if werr != nil {
			failures = append(failures, fmt.Sprintf("connection %d: %v", i, werr))
		}
		time.Sleep(5 * time.Second)
	}
	if len(failures) > 0 {
		t.Fatalf("the codec's stream ended: %s", strings.Join(failures, "; "))
	}
}
