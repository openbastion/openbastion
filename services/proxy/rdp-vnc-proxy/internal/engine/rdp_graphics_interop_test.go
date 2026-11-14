package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/rdp"
)

// dumpGraphicsOutput writes the compositor's output to RDP_WINDOWS_DUMP, when set.
func dumpGraphicsOutput(t *testing.T, log *graphicsLog, name string) {
	t.Helper()
	dir := os.Getenv("RDP_WINDOWS_DUMP")
	if dir == "" || log.output == nil {
		return
	}
	var out bytes.Buffer
	if err := png.Encode(&out, log.output); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The graphics pipeline of ADR-0101 (increment 1) against real servers: the early capability set,
// the channel opened from the closed list, the capabilities advertised and one set confirmed, then
// what the target sends read, decompressed and bounded. Increments 2 and 3: every command without a
// codec, and the bitmaps in ClearCodec or uncompressed, drawn by the compositor, and every end of
// frame acknowledged (MS-RDPEGFX 2.2.2.13); a codec not drawn yet is counted by name, and the
// measure goes on. The output, as far as
// the commands drawn make it, goes to RDP_WINDOWS_DUMP.

type graphicsLog struct {
	mu        sync.Mutex
	opened    bool
	confirmed rdp.RDPGraphicsCapabilitySet
	commands  map[uint16]int
	codecs    map[uint16]int
	formats   map[byte]int
	messages  int
	bytesIn   int
	resets    []string
	surfaces  []string
	frames    int
	notDrawn  map[string]int
	changed   int // pixels of the output changed, frames summed
	output    *image.RGBA
	err       error
}

func (g *graphicsLog) String() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	names := func(m map[uint16]int) string {
		var out []string
		for k, v := range m {
			out = append(out, fmt.Sprintf("0x%04x x%d", k, v))
		}
		sort.Strings(out)
		return strings.Join(out, ", ")
	}
	return fmt.Sprintf("opened %v, confirmed version 0x%08x flags 0x%08x, %d message(s) of %d bytes; commands [%s]; codecs [%s]; pixel formats %v; resets %q; surfaces %q; %d frame(s) drawn and acknowledged, %d pixel(s) changed; not drawn %v; error %v",
		g.opened, g.confirmed.Version, g.confirmed.Flags, g.messages, g.bytesIn, names(g.commands), names(g.codecs), g.formats, g.resets, g.surfaces, g.frames, g.changed, g.notDrawn, g.err)
}

// readGraphicsPipeline runs the connection sequence with the pipeline announced, then reads the
// screen for read.
func readGraphicsPipeline(t *testing.T, client *rdp.CredSSPClientSession, user, password string, read time.Duration) *graphicsLog {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defer client.Close()
	settings := rdp.MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: rdpClientName,
		Timeout: 15 * time.Second, DynamicChannels: true, GraphicsPipeline: true}
	log := &graphicsLog{commands: map[uint16]int{}, codecs: map[uint16]int{}, formats: map[byte]int{}, notDrawn: map[string]int{}}
	var pipeline *rdp.RDPGraphicsPipeline
	var compositor *rdp.RDPGraphicsCompositor
	onOpen := func(name string) {
		if name != rdp.RDPGraphicsChannel {
			return
		}
		log.mu.Lock()
		log.opened = true
		log.mu.Unlock()
		pipeline, compositor = rdp.NewRDPGraphicsPipeline(), rdp.NewRDPGraphicsCompositor()
		if err := client.SendDynamicChannelMessage(ctx, rdp.RDPGraphicsChannel, pipeline.CapsAdvertise(), 15*time.Second); err != nil {
			log.mu.Lock()
			log.err = err
			log.mu.Unlock()
		}
	}
	onMessage := func(name string, data []byte) error {
		if name != rdp.RDPGraphicsChannel {
			return nil
		}
		pdus, err := pipeline.Read(data)
		log.mu.Lock()
		defer log.mu.Unlock()
		log.messages++
		log.bytesIn += len(data)
		if err != nil {
			log.err = err
			return err
		}
		log.confirmed, _ = pipeline.Confirmed()
		for _, pdu := range pdus {
			log.commands[pdu.Command]++
			switch pdu.Command {
			case rdp.RDPGraphicsWireToSurface1, rdp.RDPGraphicsWireToSurface2:
				if len(pdu.Body) >= 4 {
					log.codecs[binary.LittleEndian.Uint16(pdu.Body[2:4])]++
				}
				if pdu.Command == rdp.RDPGraphicsWireToSurface1 && len(pdu.Body) >= 5 {
					log.formats[pdu.Body[4]]++
				}
			case rdp.RDPGraphicsResetGraphics:
				if len(pdu.Body) >= 12 {
					log.resets = append(log.resets, fmt.Sprintf("%dx%d, %d monitor(s)", binary.LittleEndian.Uint32(pdu.Body[0:4]),
						binary.LittleEndian.Uint32(pdu.Body[4:8]), binary.LittleEndian.Uint32(pdu.Body[8:12])))
				}
			case rdp.RDPGraphicsCreateSurface:
				if len(pdu.Body) >= 7 && len(log.surfaces) < 16 {
					log.surfaces = append(log.surfaces, fmt.Sprintf("%d: %dx%d format 0x%02x", binary.LittleEndian.Uint16(pdu.Body[0:2]),
						binary.LittleEndian.Uint16(pdu.Body[2:4]), binary.LittleEndian.Uint16(pdu.Body[4:6]), pdu.Body[6]))
				}
			}
			frame, ended, err := compositor.Apply(pdu)
			if errors.Is(err, rdp.ErrRDPGraphicsCodec) {
				// A codec not drawn yet: counted, not drawn, and the measure goes on.
				log.notDrawn[err.Error()]++
				continue
			}
			if err != nil {
				log.err = err
				return err
			}
			if !ended {
				continue
			}
			log.frames++
			log.changed += frame.Changed.Dx() * frame.Changed.Dy()
			log.output = compositor.Output()
			// Sent from the reader: unlocked, as the channel's own answers are.
			log.mu.Unlock()
			err = client.SendDynamicChannelMessage(ctx, rdp.RDPGraphicsChannel, rdp.MarshalGraphicsFrameAcknowledge(frame.ID, compositor.FramesDecoded()), 15*time.Second)
			log.mu.Lock()
			if err != nil {
				log.err = err
				return err
			}
		}
		return nil
	}
	steps := []rdpConnectionStep{
		{"MCS connect", func() error { _, e := client.ConnectMCS(ctx, settings); return e }},
		{"MCS channels", func() error {
			if e := client.EnableDynamicChannels([]string{rdp.RDPDisplayControlChannel, rdp.RDPGraphicsChannel}, onOpen, onMessage); e != nil {
				return e
			}
			_, e := client.ConnectMCSChannels(ctx, 15*time.Second)
			return e
		}},
		{"client info", func() error {
			return client.SendClientInfo(ctx, rdp.RDPClientInfo{Username: user, Password: []byte(password)}, 15*time.Second)
		}},
		{"licensing", func() error { return client.CompleteLicensing(ctx, 15*time.Second) }},
		{"capabilities", func() error { _, e := client.ExchangeCapabilities(ctx, 15*time.Second); return e }},
		{"finalization", func() error { _, e := client.FinalizeConnection(ctx, 15*time.Second); return e }},
	}
	if err := runRDPConnectionSteps(ctx, steps); err != nil {
		t.Fatalf("the connection with the graphics pipeline announced: %v", err)
	}
	updates := 0
	var readErr error
	for deadline := time.Now().Add(read); time.Now().Before(deadline); {
		if _, readErr = client.ReadBitmapUpdate(ctx, time.Until(deadline)); readErr != nil {
			break
		}
		updates++
	}
	refused, refusals := client.DynamicChannelRefusals()
	t.Logf("%d bitmap update(s) outside the pipeline, the read ended by %v; %d channel(s) refused: %q", updates, readErr, refusals, refused)
	t.Logf("graphics pipeline: %s", log)
	if errors.Is(readErr, rdp.ErrRDPGraphics) || errors.Is(readErr, rdp.ErrRDPDynamicChannel) {
		t.Fatalf("the pipeline ended the session: %v", readErr)
	}
	return log
}

// FreeRDP's shadow server: what it does with the pipeline offered, read without a fault.
func TestRDPInterop_GraphicsPipeline(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client, err := target.authenticate(ctx, rdpInteropPassword)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	log := readGraphicsPipeline(t, client, rdpInteropUser, rdpInteropPassword, 10*time.Second)
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.err != nil {
		t.Fatalf("the pipeline: %v", log.err)
	}
}
