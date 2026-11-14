package rdp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
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
	out := replayGraphics(t, "freerdp-progressive", 8, "golden-freerdp.png")
	white, black := [4]byte{0xff, 0xff, 0xff, 0xff}, [4]byte{0, 0, 0, 0xff}
	if pixel(out, 100, 100) != white || pixel(out, 800, 600) != black {
		t.Errorf("the xterm %v, the display %v", pixel(out, 100, 100), pixel(out, 800, 600))
	}
	checkGolden(t, out, goldenFreeRDPProgressive)
}

// The 17 messages a Windows Server 2022 sent on the graphics channel of a session in the CI of PR
// #199 (testdata/graphics/windows-2022, the artifact's graphics-messages): ClearCodec with NSCodec,
// and RemoteFX Progressive with the Reduce-Extrapolate DWT, which FreeRDP's frame does not cover.
// The screen is the CI's desktop: Notepad with the text the clipboard test pasted, the Windows
// wallpaper, the taskbar. Its hash was taken once the wallpaper came out blue, as it is, checked by
// eye (ADR-0101, increment 4: NSCodec's chroma, read signed before its shift, had made it orange,
// then green).
func TestGraphicsGolden_AWindowsServer2022Session(t *testing.T) {
	out := replayGraphics(t, "windows-2022", 17, "golden-windows.png")
	for _, p := range [][2]int{{815, 100}, {850, 100}, {1100, 740}} {
		px := pixel(out, p[0], p[1])
		if px[2] < 150 || px[0] > 40 || px[1] > 140 {
			t.Errorf("the wallpaper at %v is %v, not blue", p, px)
		}
	}
	checkGolden(t, out, goldenWindows2022)
}

// replayGraphics reads n captured messages through a pipeline and a compositor, and returns the
// output; RDP_GRAPHICS_GOLDEN_DUMP has it written as a PNG, to be looked at.
func replayGraphics(t *testing.T, dir string, n int, dump string) *image.RGBA {
	t.Helper()
	p, c := NewRDPGraphicsPipeline(), NewRDPGraphicsCompositor()
	frames := 0
	for i := range n {
		message, err := os.ReadFile(filepath.Join("testdata", "graphics", dir, fmt.Sprintf("message-%03d.bin", i)))
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
	if d := os.Getenv("RDP_GRAPHICS_GOLDEN_DUMP"); d != "" {
		if f, err := os.Create(filepath.Join(d, dump)); err == nil {
			_ = png.Encode(f, out)
			_ = f.Close()
		}
	}
	return out
}

func checkGolden(t *testing.T, out *image.RGBA, want string) {
	t.Helper()
	sum := sha256.Sum256(out.Pix)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("the screen's SHA-256 is %s, not %s", got, want)
	}
}

const (
	goldenFreeRDPProgressive = "f0f24ebb069e8a357df232cbc144ee7ba64f5508ed4a08573cfbd53c113ad91e"
	goldenWindows2022        = "0e0ef2b40221e29b785fed16c12f4f647b78f43aacfb7296a98d64dbe6966d4a"
)
