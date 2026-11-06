package rdp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

func TestRDPFramebufferAppliesPartialRectanglesToCompletePNG(t *testing.T) {
	fb, err := NewRDPFramebuffer(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(10, 0)
	first, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{Width: 1, Height: 1, Pixels: []byte{255, 0, 0, 255}}}}, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || first.Width != 2 || first.Height != 1 {
		t.Fatalf("first frame metadata = %+v", first)
	}
	img1, err := png.Decode(bytes.NewReader(first.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img1.At(0, 0)).(color.RGBA); got != (color.RGBA{R: 255, A: 255}) {
		t.Fatalf("pixel 0 = %#v", got)
	}
	if got := color.RGBAModel.Convert(img1.At(1, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("untouched pixel = %#v", got)
	}

	second, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Width: 1, Height: 1, Pixels: []byte{0, 255, 0, 255}}}}, stamp.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 2 {
		t.Fatalf("sequence = %d", second.Sequence)
	}
	img2, err := png.Decode(bytes.NewReader(second.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img2.At(0, 0)).(color.RGBA); got != (color.RGBA{R: 255, A: 255}) {
		t.Fatalf("preserved pixel = %#v", got)
	}
	if got := color.RGBAModel.Convert(img2.At(1, 0)).(color.RGBA); got != (color.RGBA{G: 255, A: 255}) {
		t.Fatalf("updated pixel = %#v", got)
	}
	if _, err := screenstream.Encode(second); err != nil {
		t.Fatalf("screenstream contract rejected frame: %v", err)
	}
}

func TestRDPFramebufferRejectsInvalidUpdateAtomically(t *testing.T) {
	fb, err := NewRDPFramebuffer(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{
		{Width: 1, Height: 1, Pixels: []byte{255, 0, 0, 255}},
		{X: 2, Width: 1, Height: 1, Pixels: []byte{0, 255, 0, 255}},
	}}, time.Now())
	if err == nil {
		t.Fatal("out-of-bounds rectangle accepted")
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Width: 1, Height: 1, Pixels: []byte{0, 0, 255, 255}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("invalid update partially mutated framebuffer: %#v", got)
	}
	if frame.Sequence != 1 {
		t.Fatalf("failed update consumed sequence: %d", frame.Sequence)
	}
}

func TestRDPFramebufferRejectsMalformedDstInvertPayload(t *testing.T) {
	fb, err := NewRDPFramebuffer(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 1, Pixels: []byte{0, 0, 0, 0xff}, operation: rdpBitmapRectangleDstInvert,
	}}}, time.Unix(19, 0))
	if err == nil {
		t.Fatal("DSTINVERT with replacement pixels accepted")
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff},
	}}}, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("malformed DSTINVERT consumed sequence: %d", frame.Sequence)
	}
}

func TestRDPFramebufferRejectsMalformedPatInvertPayload(t *testing.T) {
	fb, err := NewRDPFramebuffer(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, pixels := range [][]byte{nil, {0x0f, 0xf0, 0xaa, 0xff, 0x0f, 0xf0, 0xaa, 0xff}} {
		_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
			Width: 1, Height: 1, Pixels: pixels, operation: rdpBitmapRectanglePatInvert,
		}}}, time.Unix(20, 0))
		if err == nil {
			t.Fatalf("PATINVERT with %d-byte solid-brush pattern payload accepted", len(pixels))
		}
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff},
	}}}, time.Unix(21, 0))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("malformed PATINVERT consumed sequence: %d", frame.Sequence)
	}
}

func TestRDPFramebufferPatBooleanOperationsPreserveDestinationAlpha(t *testing.T) {
	for _, operation := range []rdpBitmapRectangleOperation{rdpBitmapRectanglePatAnd, rdpBitmapRectanglePatOr} {
		t.Run(map[rdpBitmapRectangleOperation]string{rdpBitmapRectanglePatAnd: "PATAND", rdpBitmapRectanglePatOr: "PATOR"}[operation], func(t *testing.T) {
			fb, err := NewRDPFramebuffer(1, 1)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
				Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff},
			}}}, time.Unix(24, 0))
			if err != nil {
				t.Fatal(err)
			}
			frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
				Width: 1, Height: 1, Pixels: []byte{0x0f, 0xf0, 0xaa, 0x00}, operation: operation,
			}}}, time.Unix(25, 0))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := png.Decode(bytes.NewReader(frame.PNG))
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, alpha := decoded.At(0, 0).RGBA()
			if alpha != 0xffff {
				t.Fatalf("destination alpha = %04x, want opaque 0xffff", alpha)
			}
		})
	}
}

func TestRDPFramebufferRejectsMalformedScrBltAtomically(t *testing.T) {
	fb, err := NewRDPFramebuffer(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, rect := range []RDPBitmapRectangle{
		{Width: 1, Height: 1, sourceX: 1, operation: rdpBitmapRectangleScrCopy},
		{Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff}, operation: rdpBitmapRectangleScrCopy},
	} {
		_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{rect}}, time.Unix(26, 0))
		if err == nil {
			t.Fatalf("malformed ScrBlt rectangle accepted: %+v", rect)
		}
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff},
	}}}, time.Unix(27, 0))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("invalid ScrBlt consumed sequence: %d", frame.Sequence)
	}
}

func TestRDPFramebufferRejectsMalformedPatBooleanPatternPayload(t *testing.T) {
	fb, err := NewRDPFramebuffer(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []rdpBitmapRectangleOperation{rdpBitmapRectanglePatAnd, rdpBitmapRectanglePatOr} {
		for _, pixels := range [][]byte{nil, {0x0f, 0xf0, 0xaa, 0xff, 0x0f, 0xf0, 0xaa, 0xff}} {
			_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
				Width: 1, Height: 1, Pixels: pixels, operation: operation,
			}}}, time.Unix(22, 0))
			if err == nil {
				t.Fatalf("operation %d with %d-byte pattern payload accepted", operation, len(pixels))
			}
		}
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff},
	}}}, time.Unix(23, 0))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("malformed pattern operations consumed sequence: %d", frame.Sequence)
	}
}

func TestRDPFramebufferRejectsUnknownRectangleOperationAtomically(t *testing.T) {
	fb, err := NewRDPFramebuffer(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 1, operation: rdpBitmapRectangleOperation(0xff),
	}}}, time.Unix(20, 0))
	if err == nil {
		t.Fatal("unknown rectangle operation accepted")
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		X: 1, Width: 1, Height: 1, Pixels: []byte{0, 0, 255, 255},
	}}}, time.Unix(21, 0))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("unknown operation mutated framebuffer: %#v", got)
	}
	if frame.Sequence != 1 {
		t.Fatalf("unknown operation consumed sequence: %d", frame.Sequence)
	}
}

func TestNewRDPFramebufferEnforcesPixelAndDimensionBounds(t *testing.T) {
	for _, tc := range []struct{ w, h uint16 }{{0, 1}, {1, 0}, {4096, 4097}} {
		if _, err := NewRDPFramebuffer(tc.w, tc.h); err == nil {
			t.Fatalf("accepted %dx%d", tc.w, tc.h)
		}
	}
	fb, err := NewRDPFramebuffer(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := fb.image.Bounds(); got != image.Rect(0, 0, 1, 1) {
		t.Fatalf("bounds = %v", got)
	}
}

func TestRDPFramebufferRejectsCumulativeOperationPixelLimit(t *testing.T) {
	const width, height = 4096, 4096
	fb, err := NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	update := RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{
		{Width: width, Height: 2049, operation: rdpBitmapRectangleDstInvert},
		{Width: width, Height: 2049, operation: rdpBitmapRectangleDstInvert},
	}}
	if _, err := fb.Apply(update, time.Now()); err == nil {
		t.Fatal("cumulative rectangle area above MaxPixels accepted")
	}
	if fb.sequence != 0 {
		t.Fatalf("rejected cumulative update consumed sequence: %d", fb.sequence)
	}
	if got := fb.image.Pix[0:4]; !bytes.Equal(got, []byte{0, 0, 0, 0xff}) {
		t.Fatalf("rejected cumulative update mutated framebuffer: %v", got)
	}
}

func TestRDPFramebufferRollsBackDstInvertWhenPNGExceedsScreenStreamLimit(t *testing.T) {
	const width, height = 1050, 1050
	fb, err := NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	state := uint32(0x9e3779b9)
	for i := range fb.image.Pix {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		fb.image.Pix[i] = byte(state)
	}
	before := append([]byte(nil), fb.image.Pix...)
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: width, Height: height, operation: rdpBitmapRectangleDstInvert,
	}}}, time.Now())
	if err == nil {
		t.Fatal("oversized DSTINVERT PNG was accepted")
	}
	if !bytes.Equal(fb.image.Pix, before) {
		t.Fatal("failed DSTINVERT encoding did not restore the framebuffer")
	}
	if fb.sequence != 0 {
		t.Fatalf("failed DSTINVERT consumed sequence: %d", fb.sequence)
	}
	clear(before)
}

func TestRDPFramebufferRollsBackWhenPNGExceedsScreenStreamLimit(t *testing.T) {
	const width, height = 1050, 1050
	fb, err := NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	pixels := make([]byte, int(width)*int(height)*4)
	state := uint32(0x9e3779b9)
	for i := range pixels {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		pixels[i] = byte(state)
	}
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{Width: width, Height: height, Pixels: pixels}}}, time.Now())
	if err == nil {
		t.Fatal("oversized PNG was accepted")
	}
	clear(pixels)

	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Y: 1, Width: 1, Height: 1, Pixels: []byte{0, 0, 255, 255}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("failed encode consumed sequence: %d", frame.Sequence)
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("oversized update was not rolled back: %#v", got)
	}
}

func TestRDPFramebufferAppliesPolygonSC(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	order := mcsTestPolygonSCOrder(0x09, true, 1, 1, 0x0d, 0x01, [3]byte{0x12, 0x34, 0x56}, 3, []byte{0x00, 3, 0, 0, 3, 0x7d, 0})
	update, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if !state.polygonSCUsed || len(update.Rectangles) != 1 || update.Rectangles[0].operation != rdpBitmapRectanglePolygon {
		t.Fatalf("PolygonSC update=%+v state=%+v", update, state)
	}
	message, err := framebuffer.Apply(update, time.Unix(61, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			inside := x >= 1 && x <= 3 && y >= 1 && y <= 3
			if inside && got != (color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}) {
				t.Fatalf("polygon pixel (%d,%d)=%#v", x, y, got)
			}
			if !inside && got != (color.RGBA{A: 0xff}) {
				t.Fatalf("unpainted pixel (%d,%d)=%#v", x, y, got)
			}
		}
	}
}

func TestRDPFramebufferRejectsMalformedPolygonAtomically(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	_, err = framebuffer.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 4, Height: 4, operation: rdpBitmapRectanglePolygon,
		polygonPoints: [][2]uint16{{1, 1}, {4, 1}, {4, 4}}, polygonColor: [4]byte{1, 2, 3, 0}, polygonFillMode: 0x01, polygonROP2: rdpROP2CopyPen,
	}}}, time.Unix(62, 0))
	if err == nil {
		t.Fatal("polygon with transparent color accepted")
	}
	_, err = framebuffer.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		X: 1, Y: 1, Width: 5, Height: 5, operation: rdpBitmapRectangleEllipse,
		ellipseColor: [4]byte{1, 2, 3, 0}, ellipseROP2: rdpROP2CopyPen,
	}}}, time.Unix(62, 1))
	if err == nil {
		t.Fatal("ellipse with transparent color accepted")
	}
	message, err := framebuffer.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		X: 1, Y: 1, Width: 1, Height: 1, Pixels: []byte{0x12, 0x34, 0x56, 0xff},
	}}}, time.Unix(63, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(decoded.At(1, 1)).(color.RGBA); got != (color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}) {
		t.Fatalf("rejected polygon changed framebuffer: %#v", got)
	}
	if message.Sequence != 1 {
		t.Fatalf("rejected polygon consumed sequence: %d", message.Sequence)
	}
}

func TestRDPFramebufferRollsBackPolygonWhenPNGExceedsScreenStreamLimit(t *testing.T) {
	const width, height = 1050, 1050
	framebuffer, err := NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	state := uint32(0x9e3779b9)
	for i := range framebuffer.image.Pix {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		framebuffer.image.Pix[i] = byte(state)
	}
	before := append([]byte(nil), framebuffer.image.Pix...)
	order := mcsTestPolygonSCOrder(0x09, true, 1, 1, 0x0d, 0x01, [3]byte{0x12, 0x34, 0x56}, 3, []byte{0x00, 3, 0, 0, 3, 0x7d, 0})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), width, height, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := framebuffer.Apply(update, time.Now()); err == nil {
		t.Fatal("oversized polygon PNG was accepted")
	}
	if !bytes.Equal(framebuffer.image.Pix, before) {
		t.Fatal("failed polygon encoding did not restore the framebuffer")
	}
	if framebuffer.sequence != 0 {
		t.Fatalf("failed polygon consumed sequence: %d", framebuffer.sequence)
	}
	clear(before)
}

func TestRDPFramebufferAppliesEllipseSC(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	order := mcsTestEllipseSCOrder(0x09, true, 1, 1, 5, 5, 0x0d, 0x01, [3]byte{0x12, 0x34, 0x56})
	update, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if !state.ellipseSCUsed || len(update.Rectangles) != 1 || update.Rectangles[0].operation != rdpBitmapRectangleEllipse {
		t.Fatalf("EllipseSC update=%+v state=%+v", update, state)
	}
	message, err := framebuffer.Apply(update, time.Unix(71, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			inside := (x == 2 || x == 3 || x == 4) && y == 1 || x >= 1 && x <= 5 && y >= 2 && y <= 4 ||
				(x == 2 || x == 3 || x == 4) && y == 5
			if inside && got != (color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}) {
				t.Fatalf("ellipse pixel (%d,%d)=%#v", x, y, got)
			}
			if !inside && got != (color.RGBA{A: 0xff}) {
				t.Fatalf("unpainted pixel (%d,%d)=%#v", x, y, got)
			}
		}
	}
}

func TestRDPFramebufferRollsBackEllipseWhenPNGExceedsScreenStreamLimit(t *testing.T) {
	const width, height = 1050, 1050
	framebuffer, err := NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	state := uint32(0x9e3779b9)
	for i := range framebuffer.image.Pix {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		framebuffer.image.Pix[i] = byte(state)
	}
	before := append([]byte(nil), framebuffer.image.Pix...)
	order := mcsTestEllipseSCOrder(0x09, true, 1, 1, 5, 5, 0x0d, 0x01, [3]byte{0x12, 0x34, 0x56})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), width, height, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := framebuffer.Apply(update, time.Now()); err == nil {
		t.Fatal("oversized ellipse PNG was accepted")
	}
	if !bytes.Equal(framebuffer.image.Pix, before) {
		t.Fatal("failed ellipse encoding did not restore the framebuffer")
	}
	if framebuffer.sequence != 0 {
		t.Fatalf("failed ellipse consumed sequence: %d", framebuffer.sequence)
	}
	clear(before)
}

func TestRDPFramebufferAppliesPolygonSCNotROP2(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(framebuffer.image.Pix); i += 4 {
		copy(framebuffer.image.Pix[i:i+4], []byte{0x12, 0x34, 0x56, 0xff})
	}
	order := mcsTestPolygonSCOrder(0x09, true, 1, 1, 0x06, 0x01, [3]byte{1, 2, 3}, 3, []byte{0x00, 3, 0, 0, 3, 0x7d, 0})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(72, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			want := color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}
			if x >= 1 && x <= 3 && y >= 1 && y <= 3 {
				want = color.RGBA{R: 0xed, G: 0xcb, B: 0xa9, A: 0xff}
			}
			if got != want {
				t.Fatalf("polygon R2_NOT pixel (%d,%d)=%#v want=%#v", x, y, got, want)
			}
		}
	}
}

func TestRDPFramebufferAppliesEllipseSCNotROP2(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(framebuffer.image.Pix); i += 4 {
		copy(framebuffer.image.Pix[i:i+4], []byte{0x12, 0x34, 0x56, 0xff})
	}
	order := mcsTestEllipseSCOrder(0x09, true, 1, 1, 5, 5, 0x06, 0x01, [3]byte{1, 2, 3})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(73, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			want := color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}
			inside := (x >= 2 && x <= 4 && y == 1) || (x >= 1 && x <= 5 && y >= 2 && y <= 4) || (x >= 2 && x <= 4 && y == 5)
			if inside {
				want = color.RGBA{R: 0xed, G: 0xcb, B: 0xa9, A: 0xff}
			}
			if got != want {
				t.Fatalf("ellipse R2_NOT pixel (%d,%d)=%#v want=%#v", x, y, got, want)
			}
		}
	}
}

func TestRDPFramebufferAppliesPolygonSCXorROP2(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(framebuffer.image.Pix); i += 4 {
		copy(framebuffer.image.Pix[i:i+4], []byte{0x12, 0x34, 0x56, 0xff})
	}
	order := mcsTestPolygonSCOrder(0x09, true, 1, 1, 0x07, 0x01, [3]byte{0x01, 0x02, 0x03}, 3, []byte{0x00, 3, 0, 0, 3, 0x7d, 0})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(74, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			want := color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}
			if x >= 1 && x <= 3 && y >= 1 && y <= 3 {
				want = color.RGBA{R: 0x13, G: 0x36, B: 0x55, A: 0xff}
			}
			if got != want {
				t.Fatalf("polygon R2_XORPEN pixel (%d,%d)=%#v want=%#v", x, y, got, want)
			}
		}
	}
}

func TestRDPFramebufferAppliesEllipseSCXorROP2(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(framebuffer.image.Pix); i += 4 {
		copy(framebuffer.image.Pix[i:i+4], []byte{0x12, 0x34, 0x56, 0xff})
	}
	order := mcsTestEllipseSCOrder(0x09, true, 1, 1, 5, 5, 0x07, 0x01, [3]byte{0x01, 0x02, 0x03})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(75, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			want := color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}
			inside := (x >= 2 && x <= 4 && y == 1) || (x >= 1 && x <= 5 && y >= 2 && y <= 4) || (x >= 2 && x <= 4 && y == 5)
			if inside {
				want = color.RGBA{R: 0x13, G: 0x36, B: 0x55, A: 0xff}
			}
			if got != want {
				t.Fatalf("ellipse R2_XORPEN pixel (%d,%d)=%#v want=%#v", x, y, got, want)
			}
		}
	}
}

func TestRDPFramebufferAppliesROP2AcrossPrimitives(t *testing.T) {
	linePixels := map[[2]int]bool{{1, 1}: true, {2, 1}: true, {3, 2}: true, {4, 2}: true}
	painted := func(kind string, x, y int) bool {
		switch kind {
		case "LineTo", "Polyline":
			return linePixels[[2]int{x, y}]
		case "PolygonSC":
			return x >= 1 && x <= 3 && y >= 1 && y <= 3
		case "EllipseSC":
			return (x >= 2 && x <= 4 && y == 1) || (x >= 1 && x <= 5 && y >= 2 && y <= 4) || (x >= 2 && x <= 4 && y == 5)
		default:
			return false
		}
	}
	for _, rop := range []struct {
		name  string
		value byte
		want  [3]byte
	}{{"R2_BLACK", rdpROP2Black, [3]byte{0x00, 0x00, 0x00}}, {"R2_NOTCOPYPEN", rdpROP2NotCopyPen, [3]byte{0xde, 0xbc, 0x9a}}, {"R2_MASKPENNOT", rdpROP2MaskPenNot, [3]byte{0x12, 0x34, 0x12}}, {"R2_MASKPEN", rdpROP2MaskPen, [3]byte{0x00, 0x00, 0x44}}, {"R2_WHITE", rdpROP2White, [3]byte{0xff, 0xff, 0xff}}, {"R2_NOTXORPEN", rdpROP2NotXorPen, [3]byte{0xcc, 0x88, 0xcc}}, {"R2_NOP", rdpROP2Nop, [3]byte{0x12, 0x34, 0x56}}} {
		for _, primitive := range []string{"LineTo", "Polyline", "PolygonSC", "EllipseSC"} {
			t.Run(primitive+"/"+rop.name, func(t *testing.T) {
				var order []byte
				switch primitive {
				case "LineTo":
					order = mcsTestLineToOrder(0x09, true, 1, 1, 5, 3, 0x21, 0x43, 0x65)
					order[17] = rop.value
				case "Polyline":
					order = mcsTestPolylineOrder(0x09, true, 1, 1, rop.value, 0, [3]byte{0x21, 0x43, 0x65}, 2, []byte{0x00, 2, 1, 2, 1})
				case "PolygonSC":
					order = mcsTestPolygonSCOrder(0x09, true, 1, 1, rop.value, 0x01, [3]byte{0x21, 0x43, 0x65}, 3, []byte{0x00, 3, 0, 0, 3, 0x7d, 0})
				case "EllipseSC":
					order = mcsTestEllipseSCOrder(0x09, true, 1, 1, 5, 5, rop.value, 0x01, [3]byte{0x21, 0x43, 0x65})
				}
				update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
				if err != nil {
					t.Fatalf("parse %s: %v", rop.name, err)
				}
				framebuffer, err := NewRDPFramebuffer(8, 8)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < len(framebuffer.image.Pix); i += 4 {
					copy(framebuffer.image.Pix[i:i+4], []byte{0x12, 0x34, 0x56, 0xff})
				}
				message, err := framebuffer.Apply(update, time.Unix(90, 0))
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := png.Decode(bytes.NewReader(message.PNG))
				if err != nil {
					t.Fatal(err)
				}
				for y := 0; y < 8; y++ {
					for x := 0; x < 8; x++ {
						got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
						want := color.RGBA{R: 0x12, G: 0x34, B: 0x56, A: 0xff}
						if painted(primitive, x, y) {
							want = color.RGBA{R: rop.want[0], G: rop.want[1], B: rop.want[2], A: 0xff}
						}
						if got != want {
							t.Fatalf("%s %s pixel (%d,%d)=%#v want=%#v", primitive, rop.name, x, y, got, want)
						}
					}
				}
			})
		}
	}
}
