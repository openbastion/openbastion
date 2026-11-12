package interfaces

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

// The measurements ADR-0090 (lot A) left open: how long the Video Recorder takes to acknowledge a
// frame, the delay every frame waits before the operator sees it (ADR-0070, ADR-0071 §4), alone and
// with several sessions at once. The real Video Recorder on PostgreSQL (TEST_DATABASE_URL), the
// real proxy client over mTLS. The object store is the in-process one of the recording test, so S3's
// own latency is not in the figures, unless RECORDER_MEASURE_S3_ENDPOINT names a real S3 endpoint:
// plain HTTP, access key "test", secret "test-secret", bucket "screens" created if absent (the
// settings startVideoRecorder gives). RECORDER_MEASURE_SESSIONS lists the numbers of sessions at
// once (1,5,10 by default). RECORDER_MEASURE=1; RECORDER_MEASURE_DUMP for the JSON.

type ackMeasure struct {
	Frame      string  `json:"frame"`
	FrameBytes int     `json:"frameBytes"`
	Sessions   int     `json:"sessions"`
	Frames     int     `json:"frames"`
	P50Ms      float64 `json:"p50Ms"`
	P95Ms      float64 `json:"p95Ms"`
	MaxMs      float64 `json:"maxMs"`
	PerSecond  float64 `json:"framesPerSecond"`
}

func TestVideoRecorderAckLatency(t *testing.T) {
	if os.Getenv("RECORDER_MEASURE") == "" {
		t.Skip("RECORDER_MEASURE not set: this measures the real Video Recorder")
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: the Video Recorder needs PostgreSQL")
	}
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "..")
	pkiDir := t.TempDir()
	ca, err := pki.InitDir(pkiDir, recordingTrustDomain, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{mtls.VideoRecorder, mtls.RDPVNCProxy, mtls.Authorization, mtls.AuditService} {
		if _, err := pki.IssueToDir(ca, pkiDir, service, pki.IssueOptions{TTL: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	identity := func(service string) *mtls.Runtime {
		rt, err := mtls.SetupWith(service, mtls.Settings{Mode: mtls.Required, TrustDomain: recordingTrustDomain,
			CertFile: pki.CertFile(pkiDir, service), KeyFile: pki.KeyFile(pkiDir, service), CAFile: pki.CAFile(pkiDir)})
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	s3URL := os.Getenv("RECORDER_MEASURE_S3_ENDPOINT")
	if s3URL == "" {
		s3URL = newRecordingObjectStore(t).URL
	}
	audit := &recordingAuditSpy{}
	auditURL := serveAs(t, identity(mtls.AuditService), http.MethodPost, "/audit/v1/emit-event", audit.ServeHTTP)
	authzURL := serveAs(t, identity(mtls.Authorization), http.MethodPost, "/authz/v1/check-access", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": false, "decision_reason": "no reads here"})
	})
	httpPort, grpcPort := freePort(t), freePort(t)
	video := startVideoRecorder(t, root, pkiDir, httpPort, grpcPort, dsn, s3URL, authzURL, auditURL)
	recorder, err := infrastructure.NewVideoRecorderClient(identity(mtls.RDPVNCProxy), "https://127.0.0.1:"+grpcPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	waitFor(t, 60*time.Second, "the Video Recorder to be ready", video, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return recorder.Ready(ctx) == nil
	})

	// The frames the figures of ADR-0090 and ADR-0092 describe: a partial frame of a few hundred
	// bytes, a key frame of a black desktop (about 30 KB) and of a wallpapered one (about 200 KB).
	kinds := []struct {
		name  string
		frame func(seq uint64) screenstream.Message
	}{
		{"partial, 1 rectangle", func(seq uint64) screenstream.Message {
			return screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: seq, Timestamp: time.Now().UTC(), Width: 1280, Height: 800,
				Rects: []screenstream.Rect{{X: 64, Y: 64, Width: 32, Height: 32, PNG: measurePNG(t, 32, 32, 0.3)}}}
		}},
		{"key, ~30 KB", keyFrameOf(measurePNG(t, 1280, 800, 0.004))},
		{"key, ~200 KB", keyFrameOf(measurePNG(t, 1280, 800, 0.03))},
	}
	var results []ackMeasure
	for _, kind := range kinds {
		for _, sessions := range measureSessions(t) {
			r := measureAcks(t, recorder, kind.name, kind.frame, sessions, 60, 50*time.Millisecond)
			results = append(results, r)
			t.Logf("MEASURE ack %s (%d bytes), %d session(s): %d frame(s), p50 %.1f ms, p95 %.1f ms, max %.1f ms, %.0f frames/s in all",
				r.Frame, r.FrameBytes, r.Sessions, r.Frames, r.P50Ms, r.P95Ms, r.MaxMs, r.PerSecond)
		}
	}
	if dir := os.Getenv("RECORDER_MEASURE_DUMP"); dir != "" {
		raw, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "ack.json"), raw, 0o644)
	}
}

// measureSessions is RECORDER_MEASURE_SESSIONS, a comma-separated list of numbers of sessions at
// once, from 1 to 200; 1, 5 and 10 when it is not set.
func measureSessions(t *testing.T) []int {
	raw := os.Getenv("RECORDER_MEASURE_SESSIONS")
	if raw == "" {
		return []int{1, 5, 10}
	}
	var out []int
	for _, field := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n < 1 || n > 200 {
			t.Fatalf("RECORDER_MEASURE_SESSIONS: %q is not a number of sessions from 1 to 200", field)
		}
		out = append(out, n)
	}
	return out
}

func keyFrameOf(pngData []byte) func(seq uint64) screenstream.Message {
	return func(seq uint64) screenstream.Message {
		return screenstream.Message{Type: screenstream.TypeFrame, Sequence: seq, Timestamp: time.Now().UTC(), Width: 1280, Height: 800, PNG: pngData}
	}
}

// measurePNG is a PNG of w×h whose share of noisy pixels sets its size: a flat screen with some detail.
func measurePNG(t *testing.T, w, h int, noise float64) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	random := rand.New(rand.NewSource(int64(w*h) + int64(noise*1e6)))
	for i := 0; i < len(img.Pix); i += 4 {
		if random.Float64() < noise {
			img.Pix[i], img.Pix[i+1], img.Pix[i+2] = byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256))
		}
		img.Pix[i+3] = 0xff
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// measureAcks records frames in sessions at once, each a key frame then frames at the interval, as
// the proxy does (one frame a segment, shown only once acknowledged), and times every acknowledgement.
func measureAcks(t *testing.T, recorder *infrastructure.VideoRecorderClient, name string, frame func(uint64) screenstream.Message,
	sessions, frames int, interval time.Duration) ackMeasure {
	t.Helper()
	var mu sync.Mutex
	var latencies []float64
	var wg sync.WaitGroup
	start := time.Now()
	for s := 0; s < sessions; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("measure-%d-%d", time.Now().UnixNano(), s)
			key := keyFrameOf(measurePNG(t, 1280, 800, 0))
			for seq := uint64(1); seq <= uint64(frames); seq++ {
				m := frame(seq)
				if seq == 1 && m.Type == screenstream.TypeFrameDelta {
					m = key(1) // a partial frame needs its key frame before it
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				sent := time.Now()
				ack, err := recorder.Record(ctx, sessionID, m)
				elapsed := time.Since(sent)
				cancel()
				if err != nil || ack != seq {
					t.Errorf("session %d, frame %d: ack %d, %v", s, seq, ack, err)
					return
				}
				mu.Lock()
				latencies = append(latencies, float64(elapsed.Microseconds())/1000)
				mu.Unlock()
				time.Sleep(interval)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := recorder.Seal(ctx, sessionID, uint64(frames)); err != nil {
				t.Errorf("session %d: seal: %v", s, err)
			}
		}(s)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	sort.Float64s(latencies)
	if len(latencies) == 0 {
		t.Fatalf("%s, %d session(s): no frame acknowledged", name, sessions)
	}
	sample := frame(2)
	size := len(sample.PNG)
	for _, r := range sample.Rects {
		size += len(r.PNG)
	}
	at := func(q float64) float64 { return latencies[int(q*float64(len(latencies)-1))] }
	return ackMeasure{Frame: name, FrameBytes: size, Sessions: sessions, Frames: len(latencies),
		P50Ms: at(0.5), P95Ms: at(0.95), MaxMs: latencies[len(latencies)-1], PerSecond: float64(len(latencies)) / elapsed}
}
