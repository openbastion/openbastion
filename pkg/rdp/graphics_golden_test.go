package rdp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// The first eight messages FreeRDP 3's shadow server sent on the graphics channel of a session
// (testdata/graphics/freerdp-progressive, captured by TestRDPInterop_GraphicsPipeline with
// RDP_GRAPHICS_CAPTURE): the capabilities confirmed, the output reset, a surface created and mapped,
// then a whole frame of RemoteFX Progressive tiles, RemoteFX's original DWT, compressed by ZGFX.
// Replayed through the pipeline and the compositor, the screen is FreeRDP's test display: a white
// xterm at the top left on black. Its hash pins every stage (ZGFX, RLGR1, dequantization, DWT,
// colour); the image was checked by eye when the hash was taken (ADR-0101, increment 4).
func TestGraphicsGolden_AFreeRDPProgressiveFrame(t *testing.T) {
	p, c := NewRDPGraphicsPipeline(), NewRDPGraphicsCompositor()
	frames := 0
	for i := range 8 {
		message, err := os.ReadFile(filepath.Join("testdata", "graphics", "freerdp-progressive", fmt.Sprintf("message-%03d.bin", i)))
		if err != nil {
			t.Fatal(err)
		}
		pdus, err := p.Read(message)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		for _, pdu := range pdus {
			if _, ended, err := c.Apply(pdu); err != nil {
				t.Fatalf("message %d, command 0x%04x: %v", i, pdu.Command, err)
			} else if ended {
				frames++
			}
		}
	}
	out := c.Output()
	if frames == 0 || out == nil {
		t.Fatalf("%d frame(s), output %v", frames, out != nil)
	}
	if dir := os.Getenv("RDP_GRAPHICS_GOLDEN_DUMP"); dir != "" {
		f, err := os.Create(filepath.Join(dir, "golden.png"))
		if err == nil {
			_ = png.Encode(f, out)
			_ = f.Close()
		}
	}
	white, black := [4]byte{0xff, 0xff, 0xff, 0xff}, [4]byte{0, 0, 0, 0xff}
	if pixel(out, 100, 100) != white || pixel(out, 800, 600) != black {
		t.Errorf("the xterm %v, the display %v", pixel(out, 100, 100), pixel(out, 800, 600))
	}
	sum := sha256.Sum256(out.Pix)
	if got := hex.EncodeToString(sum[:]); got != goldenFreeRDPProgressive {
		t.Fatalf("the screen's SHA-256 is %s, not %s", got, goldenFreeRDPProgressive)
	}
}

const goldenFreeRDPProgressive = "f0f24ebb069e8a357df232cbc144ee7ba64f5508ed4a08573cfbd53c113ad91e"
