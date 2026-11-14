package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/rdp"
)

// The graphics pipeline in the screen proxy (ADR-0101, increment 5). The target's frames come on a
// dynamic channel, read by the same goroutine that reads the screen (ReadBitmapUpdate): that one
// now runs apart, a pump, and both what it reads and the frames the channel ends come to the reader
// as bitmap updates, in the order they were made. Each frame ended is acknowledged once it is handed
// on: a reader that falls behind holds the target back, as a slow socket would.

// rdpGraphics is the graphics pipeline of one session.
type rdpGraphics struct {
	mu         sync.Mutex
	pipeline   *rdp.RDPGraphicsPipeline
	compositor *rdp.RDPGraphicsCompositor
	// updates carries the pump's updates and the channel's frames to the reader; failed the
	// pump's end; closed is closed when the session closes, and frees a send waiting for a reader.
	updates  chan rdp.RDPBitmapUpdate
	failed   chan error
	closed   chan struct{}
	pumpOnce sync.Once
	stopOnce sync.Once
	// send sends on a dynamic channel: the session's, or a test's.
	send func(ctx context.Context, name string, data []byte, timeout time.Duration) error
	// frames counts the frames handed on, for the interoperability tests.
	frames int
}

func (s *rdpTargetSession) enableGraphics() {
	s.graphics = &rdpGraphics{updates: make(chan rdp.RDPBitmapUpdate), failed: make(chan error, 1), closed: make(chan struct{}),
		send: func(ctx context.Context, name string, data []byte, timeout time.Duration) error {
			return s.session.SendDynamicChannelMessage(ctx, name, data, timeout)
		}}
}

// channelOpened is told when a dynamic channel opens: the display control, or the graphics
// pipeline, whose capabilities are advertised at once. It may open again after a reactivation,
// with a state of its own.
func (s *rdpTargetSession) channelOpened(name string) {
	switch name {
	case rdp.RDPDisplayControlChannel:
		s.displayControlOpened(name)
	case rdp.RDPGraphicsChannel:
		if s.graphics != nil {
			s.graphics.opened()
		}
	}
}

// channelMessage reads a message of a dynamic channel: to the display control or the graphics
// pipeline; anything else ends the session.
func (s *rdpTargetSession) channelMessage(name string, message []byte) error {
	if name == rdp.RDPGraphicsChannel && s.graphics != nil {
		return s.graphics.message(message)
	}
	return s.displayControlMessage(name, message)
}

func (g *rdpGraphics) opened() {
	g.mu.Lock()
	g.pipeline, g.compositor = rdp.NewRDPGraphicsPipeline(), rdp.NewRDPGraphicsCompositor()
	advertise := g.pipeline.CapsAdvertise()
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), rdpInputTimeout)
	defer cancel()
	// A failed send ends nothing here: the target, without the capabilities, sends no frame.
	_ = g.send(ctx, rdp.RDPGraphicsChannel, advertise, rdpInputTimeout)
}

// message draws one message of the graphics channel, and hands on each frame it ends.
func (g *rdpGraphics) message(message []byte) error {
	g.mu.Lock()
	if g.pipeline == nil {
		g.mu.Unlock()
		return fmt.Errorf("%w: a message before the channel opened", rdp.ErrRDPGraphics)
	}
	pdus, err := g.pipeline.Read(message)
	if err != nil {
		g.mu.Unlock()
		return err
	}
	type ended struct {
		update  rdp.RDPBitmapUpdate
		changed bool
		ack     []byte
	}
	var frames []ended
	for _, pdu := range pdus {
		frame, end, err := g.compositor.Apply(pdu)
		if err != nil {
			g.mu.Unlock()
			return err
		}
		if end {
			update, changed := g.compositor.FrameUpdate(frame)
			frames = append(frames, ended{update, changed, rdp.MarshalGraphicsFrameAcknowledge(frame.ID, g.compositor.FramesDecoded())})
		}
	}
	g.mu.Unlock()
	for _, f := range frames {
		if f.changed {
			select {
			case g.updates <- f.update:
				g.mu.Lock()
				g.frames++
				g.mu.Unlock()
			case <-g.closed:
				return nil
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), rdpInputTimeout)
		err := g.send(ctx, rdp.RDPGraphicsChannel, f.ack, rdpInputTimeout)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

// next is the reader's next update: from the pump, which runs read, or from the channel.
func (g *rdpGraphics) next(ctx context.Context, read func() (rdp.RDPBitmapUpdate, error)) (rdp.RDPBitmapUpdate, error) {
	g.pumpOnce.Do(func() {
		go func() {
			for {
				update, err := read()
				if err != nil {
					g.failed <- err
					return
				}
				select {
				case g.updates <- update:
				case <-g.closed:
					return
				}
			}
		}()
	})
	select {
	case update := <-g.updates:
		return update, nil
	case err := <-g.failed:
		g.failed <- err // the next call sees it too
		return rdp.RDPBitmapUpdate{}, err
	case <-ctx.Done():
		return rdp.RDPBitmapUpdate{}, ctx.Err()
	}
}

func (g *rdpGraphics) close() { g.stopOnce.Do(func() { close(g.closed) }) }

// graphicsFrames is how many frames of the graphics pipeline were handed on.
func (s *rdpTargetSession) graphicsFrames() int {
	if s.graphics == nil {
		return 0
	}
	s.graphics.mu.Lock()
	defer s.graphics.mu.Unlock()
	return s.graphics.frames
}
