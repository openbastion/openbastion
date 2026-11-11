package engine

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The measurements of ADR-0090, lot A: on a real session, scene by scene, what the target sends,
// what the proxy makes of it, and what the operator waits for. A meter measures; the only thing it
// asserts is that the session lived and that something was measured.

// sceneMeasure is one scene's figures. Bytes are the target's (TLS payload read by the client),
// frames are those the codec handed to the relay, PNG sizes are what the Video Recorder stores.
type sceneMeasure struct {
	Target         string  `json:"target"`
	Scene          string  `json:"scene"`
	Seconds        float64 `json:"seconds"`
	TargetBytes    uint64  `json:"targetBytes"`
	TargetKiBps    float64 `json:"targetKiBps"`
	Frames         int     `json:"frames"`
	FramesPerSec   float64 `json:"framesPerSecond"`
	PNGBytesMean   int     `json:"pngBytesMean"`
	PNGBytesMax    int     `json:"pngBytesMax"`
	PNGKiBps       float64 `json:"pngKiBps"`
	EncodeMsMedian float64 `json:"encodeMsMedian"`
	HeapMiBPeak    float64 `json:"heapMiBPeak"`
	LatencyMsP50   float64 `json:"latencyMsP50,omitempty"`
	LatencyMsP90   float64 `json:"latencyMsP90,omitempty"`
}

type frameArrival struct {
	at   time.Time
	size int
}

type sessionMeter struct {
	t       *testing.T
	target  string
	session proxycore.ScreenSession
	bytes   func() uint64

	mu       sync.Mutex
	arrivals []frameArrival
	last     screenstream.Message
	ended    bool
	results  []sceneMeasure
}

// newSessionMeter consumes the session's frames from now on; bytes reads the target's counter.
func newSessionMeter(t *testing.T, target string, session proxycore.ScreenSession, bytes func() uint64) *sessionMeter {
	m := &sessionMeter{t: t, target: target, session: session, bytes: bytes}
	go func() {
		for frame := range session.Frames() {
			m.mu.Lock()
			m.arrivals = append(m.arrivals, frameArrival{at: time.Now(), size: len(frame.PNG)})
			m.last = frame
			m.mu.Unlock()
		}
		m.mu.Lock()
		m.ended = true
		m.mu.Unlock()
	}()
	return m
}

func (m *sessionMeter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ended {
		m.t.Fatalf("the stream ended during the measurements: %v", m.session.Err())
	}
	return len(m.arrivals)
}

// settle waits until no frame came for quiet, or limit passed.
func (m *sessionMeter) settle(quiet, limit time.Duration) {
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		m.mu.Lock()
		ended := m.ended
		lastAt := time.Time{}
		if n := len(m.arrivals); n > 0 {
			lastAt = m.arrivals[n-1].at
		}
		m.mu.Unlock()
		if ended {
			m.t.Fatalf("the stream ended: %v", m.session.Err())
		}
		if !lastAt.IsZero() && time.Since(lastAt) >= quiet {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitFrameAfter returns when the first frame after n arrived, or false after limit.
func (m *sessionMeter) waitFrameAfter(n int, limit time.Duration) (time.Time, bool) {
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		m.mu.Lock()
		if len(m.arrivals) > n {
			at := m.arrivals[n].at
			m.mu.Unlock()
			return at, true
		}
		m.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	return time.Time{}, false
}

// scene runs act, waits for the screen to settle, and records the figures of what happened from
// the start of act to the last frame it caused.
func (m *sessionMeter) scene(name string, act func()) *sceneMeasure {
	m.t.Helper()
	start, startBytes, startFrames := time.Now(), m.bytes(), m.count()
	// The heap's peak and the target's bytes, sampled: the bytes are read at the scene's end,
	// which is known only once the screen has settled.
	type byteSample struct {
		at    time.Time
		bytes uint64
	}
	peak := heapInUse()
	samples := []byteSample{{start, startBytes}}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case at := <-ticker.C:
				peak = math.Max(peak, heapInUse())
				samples = append(samples, byteSample{at, m.bytes()})
			}
		}
	}()
	act()
	actEnd := time.Now()
	m.settle(2*time.Second, 60*time.Second)
	close(stop)
	<-stopped

	m.mu.Lock()
	frames := append([]frameArrival(nil), m.arrivals[startFrames:]...)
	last := m.last
	m.mu.Unlock()
	// The scene lasts from its action to its action's end or its last frame, whichever is later.
	end := actEnd
	if n := len(frames); n > 0 && frames[n-1].at.After(end) {
		end = frames[n-1].at
	}
	if end.Before(start.Add(time.Millisecond)) {
		end = start.Add(time.Millisecond)
	}
	seconds := end.Sub(start).Seconds()
	result := sceneMeasure{Target: m.target, Scene: name, Seconds: round(seconds, 2), Frames: len(frames)}
	endBytes := startBytes
	for _, sample := range samples {
		if !sample.at.After(end.Add(100 * time.Millisecond)) {
			endBytes = sample.bytes
		}
	}
	result.TargetBytes = endBytes - startBytes
	result.TargetKiBps = round(float64(result.TargetBytes)/1024/seconds, 1)
	result.FramesPerSec = round(float64(len(frames))/seconds, 1)
	total := 0
	for _, f := range frames {
		total += f.size
		if f.size > result.PNGBytesMax {
			result.PNGBytesMax = f.size
		}
	}
	if len(frames) > 0 {
		result.PNGBytesMean = total / len(frames)
	}
	result.PNGKiBps = round(float64(total)/1024/seconds, 1)
	result.EncodeMsMedian = round(encodeMedianMs(m.t, last.PNG), 1)
	result.HeapMiBPeak = round(peak/(1<<20), 1)
	m.results = append(m.results, result)
	m.t.Logf("MEASURE %s %s: %.2f s, target %d bytes (%.1f KiB/s), %d frame(s) (%.1f/s), PNG mean %d max %d bytes (%.1f KiB/s), encode %.1f ms, heap peak %.1f MiB",
		m.target, name, seconds, result.TargetBytes, result.TargetKiBps, result.Frames, result.FramesPerSec,
		result.PNGBytesMean, result.PNGBytesMax, result.PNGKiBps, result.EncodeMsMedian, result.HeapMiBPeak)
	return &m.results[len(m.results)-1]
}

// latency presses press n times, each time measuring until the next frame; undo follows each.
func (m *sessionMeter) latency(name string, n int, press, undo func()) {
	m.t.Helper()
	var samples []float64
	result := m.scene(name, func() {
		for i := 0; i < n; i++ {
			m.settle(500*time.Millisecond, 5*time.Second)
			before := m.count()
			sent := time.Now()
			press()
			if at, ok := m.waitFrameAfter(before, 5*time.Second); ok {
				samples = append(samples, float64(at.Sub(sent).Microseconds())/1000)
			}
			undo()
		}
	})
	if len(samples) == 0 {
		m.t.Fatalf("%s: no key made a frame", name)
	}
	sort.Float64s(samples)
	result.LatencyMsP50 = round(samples[len(samples)/2], 1)
	result.LatencyMsP90 = round(samples[(len(samples)*9)/10], 1)
	m.t.Logf("MEASURE %s %s: key to frame, %d sample(s): p50 %.1f ms, p90 %.1f ms", m.target, name, len(samples), result.LatencyMsP50, result.LatencyMsP90)
}

// pointerCircle moves the operator's pointer around (cx, cy), n moves, interval apart.
func (m *sessionMeter) pointerCircle(cx, cy, radius, n int, interval time.Duration) {
	for i := 0; i < n; i++ {
		angle := 2 * math.Pi * float64(i) / float64(n)
		x, y := cx+int(float64(radius)*math.Cos(angle)), cy+int(float64(radius)*math.Sin(angle))
		if err := m.session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: uint16(x), Y: uint16(y)}); err != nil {
			m.t.Fatalf("pointer: %v", err)
		}
		time.Sleep(interval)
	}
}

// publish writes the figures as JSON beside the screens, for the CI artifact.
func (m *sessionMeter) publish(dir string) {
	if len(m.results) == 0 {
		m.t.Fatal("nothing was measured")
	}
	for _, r := range m.results {
		if r.Seconds <= 0 {
			m.t.Fatalf("scene %s has no duration", r.Scene)
		}
	}
	if dir == "" {
		return
	}
	raw, err := json.MarshalIndent(m.results, "", "  ")
	if err != nil {
		m.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "measure.json"), raw, 0o644); err != nil {
		m.t.Fatal(err)
	}
}

// encodeMedianMs re-encodes a frame as the codec does (image/png, default compression), five
// times, and returns the median: the cost of one frame of that screen.
func encodeMedianMs(t *testing.T, frame []byte) float64 {
	if len(frame) == 0 {
		return 0
	}
	decoded, err := png.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	rgba, ok := decoded.(*image.RGBA)
	if !ok {
		bounds := decoded.Bounds()
		rgba = image.NewRGBA(bounds)
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				rgba.Set(x, y, decoded.At(x, y))
			}
		}
	}
	var samples []float64
	for i := 0; i < 5; i++ {
		var out bytes.Buffer
		start := time.Now()
		if err := png.Encode(&out, rgba); err != nil {
			t.Fatal(err)
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000)
	}
	sort.Float64s(samples)
	return samples[len(samples)/2]
}

func heapInUse() float64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return float64(stats.HeapInuse)
}

func round(v float64, digits int) float64 {
	scale := math.Pow(10, float64(digits))
	return math.Round(v*scale) / scale
}

// The meter itself, against a fake target: figures come out, consistent with what was sent.
func TestSessionMeterMeasuresWhatItSees(t *testing.T) {
	session := openPointerSession(t, &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{grayDesktop(16, 16)}}, true)
	var sent atomic.Uint64
	m := newSessionMeter(t, "fake", session, sent.Load)
	m.settle(300*time.Millisecond, 5*time.Second)
	r := m.scene("pointer", func() {
		sent.Add(1000)
		m.pointerCircle(8, 8, 4, 5, 20*time.Millisecond)
	})
	if r.Frames != 5 || r.TargetBytes != 1000 || r.PNGBytesMean == 0 || r.PNGBytesMax < r.PNGBytesMean || r.EncodeMsMedian <= 0 {
		t.Fatalf("%+v: want 5 frames, 1000 target bytes, PNG sizes and an encoding time", *r)
	}
	m.latency("latency", 3, func() { m.pointerCircle(2, 2, 0, 1, 0) }, func() { m.pointerCircle(12, 12, 0, 1, 0) })
	got := m.results[len(m.results)-1]
	if got.LatencyMsP50 <= 0 || got.LatencyMsP90 < got.LatencyMsP50 {
		t.Fatalf("latency %+v", got)
	}
	dir := t.TempDir()
	m.publish(dir)
	raw, err := os.ReadFile(filepath.Join(dir, "measure.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back []sceneMeasure
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 2 || back[0].Scene != "pointer" {
		t.Fatalf("published %s, %v", raw, err)
	}
}

// rdpServerBytes reads the target's byte counter of an RDP screen session.
func rdpServerBytes(t *testing.T, session proxycore.ScreenSession) func() uint64 {
	t.Helper()
	adapter, ok := session.(*rdpScreenSessionAdapter)
	if !ok {
		t.Fatal("not an RDP screen session")
	}
	target, ok := adapter.target.(*rdpTargetSession)
	if !ok {
		t.Fatal("not a real RDP target")
	}
	return target.session.ServerBytes
}

// rdpKeys types scancodes as the Admin UI sends them: press, release, interval apart.
func rdpKeys(t *testing.T, session proxycore.ScreenSession, interval time.Duration, codes ...uint16) {
	t.Helper()
	for _, code := range codes {
		for _, flags := range []uint8{screenstream.KeyPressed, screenstream.KeyReleased} {
			if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: code, Flags: flags}); err != nil {
				t.Fatalf("key 0x%x: %v", code, err)
			}
		}
		time.Sleep(interval)
	}
}

// rdpChord holds modifier while code is pressed.
func rdpChord(t *testing.T, session proxycore.ScreenSession, modifier, code uint16) {
	t.Helper()
	press := func(c uint16, flags uint8) {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: c, Flags: flags}); err != nil {
			t.Fatalf("key 0x%x: %v", c, err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	press(modifier, screenstream.KeyPressed)
	press(code, screenstream.KeyPressed)
	press(code, screenstream.KeyReleased)
	press(modifier, screenstream.KeyReleased)
}

// A line of text in scancodes (US positions): "the quick brown fox jumps over the lazy dog 0123456789".
var rdpSentence = []uint16{
	0x14, 0x23, 0x12, 0x39, 0x10, 0x16, 0x17, 0x2e, 0x25, 0x39, 0x30, 0x13, 0x18, 0x11, 0x31, 0x39,
	0x21, 0x18, 0x2d, 0x39, 0x24, 0x16, 0x32, 0x19, 0x1f, 0x39, 0x18, 0x2f, 0x12, 0x13, 0x39, 0x14,
	0x23, 0x12, 0x39, 0x26, 0x1e, 0x2c, 0x15, 0x39, 0x20, 0x18, 0x22, 0x39, 0x0b, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
}
