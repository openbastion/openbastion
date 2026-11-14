package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"testing"
)

// The surfaces of ADR-0101, increment 2: each command drawn as MS-RDPEGFX says, the output made at
// the end of a frame, and what a target may not send refused.

type gfx struct{ b []byte }

func (g *gfx) u16(v ...int) *gfx {
	for _, x := range v {
		g.b = binary.LittleEndian.AppendUint16(g.b, uint16(x))
	}
	return g
}
func (g *gfx) u32(v ...uint32) *gfx {
	for _, x := range v {
		g.b = binary.LittleEndian.AppendUint32(g.b, x)
	}
	return g
}
func (g *gfx) raw(v ...byte) *gfx { g.b = append(g.b, v...); return g }

func pdu(command uint16, g *gfx) RDPGraphicsPDU { return RDPGraphicsPDU{Command: command, Body: g.b} }

func resetGraphics(w, h uint32) RDPGraphicsPDU {
	g := (&gfx{}).u32(w, h, 1).u32(0, 0, w-1, h-1, 1)
	g.raw(make([]byte, rdpGraphicsResetSize-len(g.b))...)
	return pdu(RDPGraphicsResetGraphics, g)
}
func createSurface(id, w, h int, format byte) RDPGraphicsPDU {
	return pdu(RDPGraphicsCreateSurface, (&gfx{}).u16(id, w, h).raw(format))
}
func mapSurface(id int, x, y uint32) RDPGraphicsPDU {
	return pdu(RDPGraphicsMapSurfaceToOutput, (&gfx{}).u16(id, 0).u32(x, y))
}
func solidFill(id int, bgra [4]byte, rects ...[4]int) RDPGraphicsPDU {
	g := (&gfx{}).u16(id).raw(bgra[:]...).u16(len(rects))
	for _, r := range rects {
		g.u16(r[0], r[1], r[2], r[3])
	}
	return pdu(RDPGraphicsSolidFill, g)
}
func wireToSurface1(id int, codec uint16, rect [4]int, data []byte) RDPGraphicsPDU {
	g := (&gfx{}).u16(id, int(codec)).raw(rdpGraphicsPixelXRGB).u16(rect[0], rect[1], rect[2], rect[3]).u32(uint32(len(data))).raw(data...)
	return pdu(RDPGraphicsWireToSurface1, g)
}
func startFrame(id uint32) RDPGraphicsPDU { return pdu(RDPGraphicsStartFrame, (&gfx{}).u32(0, id)) }
func endFrame(id uint32) RDPGraphicsPDU   { return pdu(RDPGraphicsEndFrame, (&gfx{}).u32(id)) }

func mustApply(t *testing.T, c *RDPGraphicsCompositor, pdus ...RDPGraphicsPDU) (frames []RDPGraphicsFrame) {
	t.Helper()
	for _, p := range pdus {
		frame, ok, err := c.Apply(p)
		if err != nil {
			t.Fatalf("command 0x%04x % x: %v", p.Command, p.Body, err)
		}
		if ok {
			frames = append(frames, frame)
		}
	}
	return frames
}

func pixel(img *image.RGBA, x, y int) [4]byte {
	i := img.PixOffset(x, y)
	return [4]byte(img.Pix[i : i+4])
}

func TestGraphicsSurfaces_FillCopyCacheAndPresent(t *testing.T) {
	c := NewRDPGraphicsCompositor()
	red, blue := [4]byte{0, 0, 0xff, 0}, [4]byte{0xff, 0, 0, 0}
	mustApply(t, c, resetGraphics(64, 48), createSurface(1, 32, 32, rdpGraphicsPixelXRGB), mapSurface(1, 16, 8))
	frames := mustApply(t, c, startFrame(7),
		// Red on the whole surface, blue on [0,0)-(4,4); COLOR32 is B, G, R, XA (2.2.1.3).
		solidFill(1, red, [4]int{0, 0, 32, 32}), solidFill(1, blue, [4]int{0, 0, 4, 4}),
		// The blue square copied to (10, 10) and (20, 0).
		pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 1).u16(0, 0, 4, 4).u16(2).u16(10, 10, 20, 0)),
		// Into slot 5, then out at (0, 28).
		pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0x11, 0x22).u16(5).u16(0, 0, 4, 4)),
		pdu(RDPGraphicsCacheToSurface, (&gfx{}).u16(5, 1, 1).u16(0, 28)),
		endFrame(7))
	if len(frames) != 1 || frames[0].ID != 7 || frames[0].Changed != image.Rect(16, 8, 48, 40) {
		t.Fatalf("frames %+v", frames)
	}
	out := c.Output()
	for _, check := range []struct {
		x, y int
		want [4]byte
	}{
		{0, 0, [4]byte{0, 0, 0, 0xff}},      // outside the surface: black
		{16, 8, [4]byte{0, 0, 0xff, 0xff}},  // the surface's (0, 0): blue
		{19, 11, [4]byte{0, 0, 0xff, 0xff}}, // (3, 3): blue
		{20, 12, [4]byte{0xff, 0, 0, 0xff}}, // (4, 4): red
		{26, 18, [4]byte{0, 0, 0xff, 0xff}}, // the copy at (10, 10)
		{36, 8, [4]byte{0, 0, 0xff, 0xff}},  // the copy at (20, 0)
		{16, 36, [4]byte{0, 0, 0xff, 0xff}}, // the cache entry at (0, 28)
		{47, 39, [4]byte{0xff, 0, 0, 0xff}}, // the surface's last pixel: red
		{48, 40, [4]byte{0, 0, 0, 0xff}},    // past it: black
	} {
		if got := pixel(out, check.x, check.y); got != check.want {
			t.Errorf("(%d, %d) = % x, want % x", check.x, check.y, got, check.want)
		}
	}
	if c.FramesDecoded() != 1 {
		t.Fatalf("%d frames decoded", c.FramesDecoded())
	}
	// Nothing changed: the next frame changes nothing; the acknowledgement is 20 bytes.
	if frames := mustApply(t, c, startFrame(8), endFrame(8)); !frames[0].Changed.Empty() {
		t.Fatalf("an empty frame changed %v", frames[0].Changed)
	}
	ack := MarshalGraphicsFrameAcknowledge(8, 2)
	want := (&gfx{}).u16(0x000d, 0).u32(20, 0, 8, 2).b
	if !bytes.Equal(ack, want) {
		t.Fatalf("FRAME_ACKNOWLEDGE % x, want % x", ack, want)
	}
}

// An overlapping copy within a surface moves the pixels as a whole (a memmove), down and right.
func TestGraphicsSurfaces_OverlappingCopy(t *testing.T) {
	c := NewRDPGraphicsCompositor()
	mustApply(t, c, createSurface(1, 8, 8, rdpGraphicsPixelXRGB))
	s := c.surfaces[1]
	for y := range 8 {
		for x := range 8 {
			s.pix[(y*8+x)*4] = byte(y*8 + x)
		}
	}
	before := append([]byte(nil), s.pix...)
	mustApply(t, c, pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 1).u16(0, 0, 6, 6).u16(1).u16(1, 2)))
	for y := range 6 {
		for x := range 6 {
			if got, want := s.pix[((y+2)*8+x+1)*4], before[(y*8+x)*4]; got != want {
				t.Fatalf("(%d, %d) = %d, want %d", x+1, y+2, got, want)
			}
		}
	}
}

func TestGraphicsSurfaces_AlphaAndTheOutput(t *testing.T) {
	c := NewRDPGraphicsCompositor()
	mustApply(t, c, resetGraphics(4, 4), createSurface(1, 4, 4, rdpGraphicsPixelARGB), createSurface(2, 4, 4, rdpGraphicsPixelXRGB),
		solidFill(1, [4]byte{1, 2, 3, 0x40}, [4]int{0, 0, 4, 4}), solidFill(2, [4]byte{1, 2, 3, 0x40}, [4]int{0, 0, 4, 4}))
	if got := [4]byte(c.surfaces[1].pix[:4]); got != [4]byte{3, 2, 1, 0x40} {
		t.Fatalf("ARGB keeps its alpha: % x", got)
	}
	if got := [4]byte(c.surfaces[2].pix[:4]); got != [4]byte{3, 2, 1, 0xff} {
		t.Fatalf("XRGB ignores XA: % x", got)
	}
	mustApply(t, c, mapSurface(1, 0, 0), startFrame(1), endFrame(1))
	if got := pixel(c.Output(), 0, 0); got != [4]byte{3, 2, 1, 0xff} {
		t.Fatalf("the output is opaque: % x", got)
	}
	// A reset keeps what the output showed, within the new size.
	mustApply(t, c, resetGraphics(2, 6))
	if c.Output().Rect != image.Rect(0, 0, 2, 6) || pixel(c.Output(), 1, 3) != [4]byte{3, 2, 1, 0xff} || pixel(c.Output(), 1, 5) != [4]byte{0, 0, 0, 0xff} {
		t.Fatalf("after the reset: %v", c.Output().Rect)
	}
	// A surface deleted is unmapped: created again under its ID, it shows nowhere until mapped.
	mustApply(t, c, pdu(RDPGraphicsDeleteSurface, (&gfx{}).u16(1)), createSurface(1, 4, 4, rdpGraphicsPixelXRGB),
		solidFill(1, [4]byte{9, 9, 9, 0}, [4]int{0, 0, 4, 4}), startFrame(9))
	if frames := mustApply(t, c, endFrame(9)); !frames[0].Changed.Empty() {
		t.Fatalf("a surface created again showed at once: %v", frames[0].Changed)
	}
	// A surface mapped partly outside the output is clipped to it.
	mustApply(t, c, mapSurface(2, 1, 4), startFrame(2))
	if frames := mustApply(t, c, endFrame(2)); frames[0].Changed != image.Rect(1, 4, 2, 6) {
		t.Fatalf("changed %v", frames[0].Changed)
	}
}

func TestGraphicsSurfaces_TheBoundsOfTheCacheAndSurfaces(t *testing.T) {
	c := NewRDPGraphicsCompositor()
	mustApply(t, c, createSurface(1, 2048, 2048, rdpGraphicsPixelXRGB))
	toCache := func(slot int) RDPGraphicsPDU {
		return pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(slot).u16(0, 0, 2048, 512))
	}
	// 4 MiB an entry: four fill the 16 MB, a fifth does not fit; a slot used again replaces.
	mustApply(t, c, toCache(1), toCache(2), toCache(3), toCache(4096), toCache(4096))
	if _, _, err := c.Apply(toCache(5)); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("a fifth 4 MiB entry: %v", err)
	}
	mustApply(t, c, pdu(RDPGraphicsEvictCacheEntry, (&gfx{}).u16(2)), toCache(5))
	if c.cacheBytes != maxGraphicsCacheBytes || len(c.cache) != 4 {
		t.Fatalf("%d bytes in %d slots", c.cacheBytes, len(c.cache))
	}
	// Surfaces: 64 MiB in all; deleting frees.
	mustApply(t, c, createSurface(2, 2048, 2048, rdpGraphicsPixelXRGB), createSurface(3, 2048, 2048, rdpGraphicsPixelXRGB),
		createSurface(4, 2048, 2048, rdpGraphicsPixelXRGB))
	if _, _, err := c.Apply(createSurface(5, 1, 1, rdpGraphicsPixelXRGB)); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("a surface past 64 MiB: %v", err)
	}
	mustApply(t, c, pdu(RDPGraphicsDeleteSurface, (&gfx{}).u16(4)), createSurface(5, 1, 1, rdpGraphicsPixelXRGB))
	c = NewRDPGraphicsCompositor()
	for id := range maxGraphicsSurfaces {
		mustApply(t, c, createSurface(id, 1, 1, rdpGraphicsPixelXRGB))
	}
	if _, _, err := c.Apply(createSurface(maxGraphicsSurfaces, 1, 1, rdpGraphicsPixelXRGB)); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("surface %d: %v", maxGraphicsSurfaces+1, err)
	}
}

func TestGraphicsSurfaces_RefusesWhatATargetMayNotSend(t *testing.T) {
	setup := []RDPGraphicsPDU{resetGraphics(64, 64), createSurface(1, 16, 16, rdpGraphicsPixelXRGB),
		pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(3).u16(0, 0, 2, 2))}
	shortReset := resetGraphics(8, 8)
	shortReset.Body = shortReset.Body[:100]
	for name, p := range map[string]RDPGraphicsPDU{
		"a reset of 108 bytes":           shortReset,
		"an output of 0 x 8":             resetGraphics(0, 8),
		"an output of 32767 wide":        resetGraphics(32767, 1),
		"an output past MaxPixels":       resetGraphics(8192, 4096),
		"a surface created twice":        createSurface(1, 4, 4, rdpGraphicsPixelXRGB),
		"a surface of 0 x 4":             createSurface(2, 0, 4, rdpGraphicsPixelXRGB),
		"a surface of format 0x22":       createSurface(2, 4, 4, 0x22),
		"a CreateSurface of 6 bytes":     pdu(RDPGraphicsCreateSurface, (&gfx{}).u16(2, 4, 4)),
		"a delete of no surface":         pdu(RDPGraphicsDeleteSurface, (&gfx{}).u16(9)),
		"a map of no surface":            mapSurface(9, 0, 0),
		"a map with reserved set":        pdu(RDPGraphicsMapSurfaceToOutput, (&gfx{}).u16(1, 1).u32(0, 0)),
		"a map at 32767":                 mapSurface(1, 32767, 0),
		"a scaled map, scaled":           pdu(RDPGraphicsMapSurfaceToScaledOut, (&gfx{}).u16(1, 0).u32(0, 0, 32, 32)),
		"a window map (RAIL)":            pdu(RDPGraphicsMapSurfaceToWindow, (&gfx{}).u16(1).u32(0, 0, 16, 16)),
		"a fill of no surface":           solidFill(9, [4]byte{}, [4]int{0, 0, 1, 1}),
		"a fill past the surface":        solidFill(1, [4]byte{}, [4]int{0, 0, 17, 1}),
		"a fill bottom above top":        solidFill(1, [4]byte{}, [4]int{0, 8, 2, 4}),
		"a fill upside down":             solidFill(1, [4]byte{}, [4]int{4, 4, 2, 8}),
		"a fill short of its rects":      pdu(RDPGraphicsSolidFill, (&gfx{}).u16(1).raw(0, 0, 0, 0).u16(2).u16(0, 0, 1, 1)),
		"a copy from no surface":         pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(9, 1).u16(0, 0, 1, 1).u16(1).u16(0, 0)),
		"a copy to no surface":           pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 9).u16(0, 0, 1, 1).u16(1).u16(0, 0)),
		"a copy past the source":         pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 1).u16(0, 0, 1, 17).u16(1).u16(0, 0)),
		"a copy past the destination":    pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 1).u16(0, 0, 4, 4).u16(1).u16(13, 0)),
		"a copy to a negative point":     pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 1).u16(0, 0, 4, 4).u16(1).u16(0xffff, 0)),
		"a copy short of its points":     pdu(RDPGraphicsSurfaceToSurface, (&gfx{}).u16(1, 1).u16(0, 0, 4, 4).u16(2).u16(0, 0)),
		"a cache slot 0":                 pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(0).u16(0, 0, 2, 2)),
		"a cache slot 4097":              pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(4097).u16(0, 0, 2, 2)),
		"an empty cache entry":           pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(4).u16(2, 2, 2, 2)),
		"a cache entry past the surface": pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(4).u16(0, 0, 2, 17)),
		"an empty slot to a surface":     pdu(RDPGraphicsCacheToSurface, (&gfx{}).u16(4, 1, 1).u16(0, 0)),
		"a slot to no surface":           pdu(RDPGraphicsCacheToSurface, (&gfx{}).u16(3, 9, 1).u16(0, 0)),
		"a slot past the surface":        pdu(RDPGraphicsCacheToSurface, (&gfx{}).u16(3, 1, 1).u16(15, 0)),
		"an empty slot evicted":          pdu(RDPGraphicsEvictCacheEntry, (&gfx{}).u16(4)),
		"a context of no surface":        pdu(RDPGraphicsDeleteEncodingContext, (&gfx{}).u16(9).u32(1)),
		"an end with no start":           endFrame(1),
		"a StartFrame of 4 bytes":        pdu(RDPGraphicsStartFrame, (&gfx{}).u32(1)),
		"a cache import reply":           pdu(RDPGraphicsCacheImportReply, (&gfx{}).u16(0)),
	} {
		c := NewRDPGraphicsCompositor()
		mustApply(t, c, setup...)
		if _, _, err := c.Apply(p); !errors.Is(err, ErrRDPGraphics) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Frames: a start inside a frame, an end of another frame.
	c := NewRDPGraphicsCompositor()
	mustApply(t, c, startFrame(1))
	if _, _, err := c.Apply(startFrame(2)); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a start inside a frame: %v", err)
	}
	if _, _, err := c.Apply(endFrame(2)); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("the end of another frame: %v", err)
	}
	// A codec not drawn says which: Planar in a WireToSurface1, RemoteFX progressive in a 2.
	mustApply(t, c, createSurface(1, 8, 8, rdpGraphicsPixelXRGB))
	if _, _, err := c.Apply(wireToSurface1(1, 0x000a, [4]int{0, 0, 1, 1}, []byte{0})); !errors.Is(err, ErrRDPGraphicsCodec) {
		t.Errorf("WireToSurface1 in Planar: %v", err)
	}
	if _, _, err := c.Apply(pdu(RDPGraphicsWireToSurface2, (&gfx{}).u16(1, 9))); !errors.Is(err, ErrRDPGraphicsCodec) {
		t.Errorf("WireToSurface2: %v", err)
	}
}

func FuzzRDPGraphicsCompositor(f *testing.F) {
	seed := []RDPGraphicsPDU{resetGraphics(32, 32), createSurface(1, 16, 16, rdpGraphicsPixelARGB), mapSurface(1, 4, 4),
		startFrame(1), solidFill(1, [4]byte{1, 2, 3, 4}, [4]int{0, 0, 8, 8}),
		pdu(RDPGraphicsSurfaceToCache, (&gfx{}).u16(1).u32(0, 0).u16(3).u16(0, 0, 2, 2)),
		pdu(RDPGraphicsCacheToSurface, (&gfx{}).u16(3, 1, 1).u16(5, 5)), endFrame(1)}
	var stream []byte
	for _, p := range seed {
		stream = append(stream, marshalGraphicsPDU(p.Command, p.Body)...)
	}
	f.Add(stream)
	f.Fuzz(func(t *testing.T, data []byte) {
		c := NewRDPGraphicsCompositor()
		for len(data) >= rdpGraphicsHeaderSize {
			n := int(binary.LittleEndian.Uint32(data[4:8]))
			if n < rdpGraphicsHeaderSize || n > len(data) {
				return
			}
			p := RDPGraphicsPDU{Command: binary.LittleEndian.Uint16(data[0:2]), Body: data[rdpGraphicsHeaderSize:n]}
			data = data[n:]
			if _, _, err := c.Apply(p); err != nil {
				if !errors.Is(err, ErrRDPGraphics) {
					t.Fatalf("an error outside ErrRDPGraphics: %v", err)
				}
				return
			}
			if c.surfaceBytes > maxGraphicsSurfaceBytes || c.cacheBytes > maxGraphicsCacheBytes || len(c.surfaces) > maxGraphicsSurfaces {
				t.Fatalf("past the bounds: %d, %d, %d", c.surfaceBytes, c.cacheBytes, len(c.surfaces))
			}
		}
	})
}
