package proxycore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// gateSink holds the first frame until released, then takes everything, recording the sequences.
type gateSink struct {
	mu      sync.Mutex
	got     []screenstream.Message
	release chan struct{}
	held    bool
}

func (s *gateSink) Send(ctx context.Context, m screenstream.Message) error {
	s.mu.Lock()
	first := !s.held
	s.held = true
	s.mu.Unlock()
	if first {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	s.got = append(s.got, m)
	s.mu.Unlock()
	return nil
}

func (s *gateSink) sequences() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []uint64
	for _, m := range s.got {
		out = append(out, m.Sequence)
	}
	return out
}

func displayKey(seq uint64) screenstream.Message {
	return screenstream.Message{Type: screenstream.TypeFrame, Sequence: seq, PNG: []byte("key")}
}

func displayDelta(seq uint64, size int) screenstream.Message {
	return screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: seq, Rects: []screenstream.Rect{{PNG: make([]byte, size)}}}
}

func waitDisplayIdle(t *testing.T, d *screenDisplay) {
	t.Helper()
	d.mu.Lock()
	idle := d.idle
	d.mu.Unlock()
	select {
	case <-idle:
	case <-time.After(2 * time.Second):
		t.Fatal("the display never went idle")
	}
}

// A browser that falls behind gets every partial frame in order while they fit, never one after a
// gap: past the bound, the display drops them, asks once for a key frame, and resumes at it.
func TestScreenDisplay_PartialFramesAreNeverSkipped(t *testing.T) {
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	requests := 0
	d.requestKey = func() { requests++ }

	d.offer(displayKey(1)) // in flight, held
	for seq := uint64(2); seq <= 40; seq++ {
		d.offer(displayDelta(seq, 10))
	}
	if requests != 1 {
		t.Fatalf("%d key frame requests, want one, when the waiting partial frames overflow", requests)
	}
	d.offer(displayDelta(41, 10)) // still waiting for the key frame: dropped, no new request
	if requests != 1 {
		t.Fatalf("%d key frame requests", requests)
	}
	d.offer(displayKey(42))
	d.offer(displayDelta(43, 10))
	close(sink.release)
	waitDisplayIdle(t, d)
	got := sink.sequences()
	want := []uint64{1, 42, 43}
	if len(got) != len(want) {
		t.Fatalf("sent %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sent %v, want %v", got, want)
		}
	}
}

func TestScreenDisplay_WaitingPartialFramesGoOutInOrder(t *testing.T) {
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	d.requestKey = func() { t.Error("a key frame asked for while the partial frames fit") }
	d.offer(displayKey(1))
	for seq := uint64(2); seq <= 33; seq++ { // 32 waiting: the bound, not past it
		d.offer(displayDelta(seq, 10))
	}
	close(sink.release)
	waitDisplayIdle(t, d)
	got := sink.sequences()
	if len(got) != 33 {
		t.Fatalf("sent %d frames, want 33", len(got))
	}
	for i, seq := range got {
		if seq != uint64(i+1) {
			t.Fatalf("frame %d sent as sequence %d: %v", i, seq, got)
		}
	}
}

func TestScreenDisplay_AKeyFrameReplacesWhatWaits(t *testing.T) {
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	d.offer(displayKey(1))
	d.offer(displayDelta(2, 10))
	d.offer(displayDelta(3, 10))
	d.offer(displayKey(4))
	close(sink.release)
	waitDisplayIdle(t, d)
	if got := sink.sequences(); len(got) != 2 || got[1] != 4 {
		t.Fatalf("sent %v, want [1 4]: the key frame makes the waiting partial frames needless", got)
	}
}

func TestScreenDisplay_PartialFramesAreBoundedInBytes(t *testing.T) {
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	requests := 0
	d.requestKey = func() { requests++ }
	d.offer(displayKey(1))
	d.offer(displayDelta(2, screenstream.MaxPNGBytes/2))
	d.offer(displayDelta(3, screenstream.MaxPNGBytes/2))
	if requests != 0 {
		t.Fatal("asked for a key frame within the byte bound")
	}
	d.offer(displayDelta(4, 1))
	if requests != 1 {
		t.Fatal("no key frame asked for past the byte bound")
	}
	close(sink.release)
	waitDisplayIdle(t, d)
	if got := sink.sequences(); len(got) != 1 {
		t.Fatalf("sent %v: the waiting partial frames were not dropped", got)
	}
}

// After the overflow, a partial frame that comes before the key frame is not sent, even if the
// browser catches up in between: it would apply to a screen the browser never had.
func TestScreenDisplay_NothingButAKeyFrameAfterTheOverflow(t *testing.T) {
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	d.requestKey = func() {}
	d.offer(displayKey(1))
	for seq := uint64(2); seq <= 40; seq++ {
		d.offer(displayDelta(seq, 10))
	}
	close(sink.release)
	waitDisplayIdle(t, d)
	d.offer(displayDelta(41, 10))
	time.Sleep(50 * time.Millisecond)
	if got := sink.sequences(); len(got) != 1 {
		t.Fatalf("sent %v: a partial frame went out before the key frame asked for", got)
	}
	d.offer(displayKey(42))
	waitDisplayIdle(t, d)
	if got := sink.sequences(); len(got) != 2 || got[1] != 42 {
		t.Fatalf("sent %v", got)
	}
}

// The bytes waiting go back to zero as the partial frames go out: the bound is on what waits now.
func TestScreenDisplay_TheByteBoundFollowsWhatWaits(t *testing.T) {
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	d.offer(displayKey(1))
	d.offer(displayDelta(2, 1000))
	d.offer(displayDelta(3, 1000))
	close(sink.release)
	waitDisplayIdle(t, d)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pendingBytes != 0 || len(d.pending) != 0 {
		t.Fatalf("%d bytes and %d frames still counted as waiting", d.pendingBytes, len(d.pending))
	}
}
