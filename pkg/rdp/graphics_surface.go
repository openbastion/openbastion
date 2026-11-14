package rdp

import (
	"encoding/binary"
	"fmt"
	"image"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The surfaces of the graphics pipeline (MS-RDPEGFX 3.3.1), ADR-0101 increment 2: what the target
// draws without a codec. Surfaces are bitmaps the target creates, fills, copies within and between,
// caches and maps onto the output; at the end of a frame every mapped surface updated is copied to
// the output (3.3.5.12), which is what the operator sees and what is recorded. Every command is
// checked against what exists: an unknown surface, a rectangle outside its surface, an empty cache
// slot, a frame ended that was not started, is outside the protocol and ends the session. The spec
// says nothing of these cases; refusing is the strict reading, and the CI against Windows says
// whether Windows keeps to it.

const (
	// maxGraphicsSurfaces bounds the surfaces alive at once; Windows creates one (CI of PR #194).
	maxGraphicsSurfaces = 64
	// maxGraphicsSurfaceBytes bounds the pixels of every surface alive, 4 bytes each: four desktops
	// of 2048 x 2048.
	maxGraphicsSurfaceBytes = 64 << 20
	// The bitmap cache of SMALL_CACHE, the only one advertised (3.3.1.4): 4096 slots numbered from
	// 1, 16 MB of bitmap data in all.
	maxGraphicsCacheSlots = 4096
	maxGraphicsCacheBytes = 16 << 20

	rdpGraphicsPixelXRGB = byte(0x20)
	rdpGraphicsPixelARGB = byte(0x21)

	rdpGraphicsResetSize = 340 - rdpGraphicsHeaderSize
	maxGraphicsMonitors  = 16
)

// ErrRDPGraphicsCodec says a WireToSurface came with a codec this client does not draw (yet).
var ErrRDPGraphicsCodec = fmt.Errorf("%w: a codec not drawn", ErrRDPGraphics)

type graphicsSurface struct {
	width, height int
	alpha         bool   // ARGB_8888: the alpha is the surface's; XRGB_8888: always opaque
	pix           []byte // RGBA, row after row
	dirty         image.Rectangle
}

type graphicsMapping struct {
	x, y int
}

type graphicsCacheEntry struct {
	width, height int
	pix           []byte
}

// RDPGraphicsFrame is a frame the target ended: its ID, to acknowledge, and the part of the output
// it changed (empty when nothing mapped changed).
type RDPGraphicsFrame struct {
	ID      uint32
	Changed image.Rectangle
}

// RDPGraphicsCompositor draws the commands of one graphics channel onto its output.
type RDPGraphicsCompositor struct {
	output       *image.RGBA
	surfaces     map[uint16]*graphicsSurface
	surfaceBytes int
	mappings     map[uint16]graphicsMapping
	cache        map[uint16]*graphicsCacheEntry
	cacheBytes   int
	clear        *clearCodec
	progressive  *progressiveCodec
	frameOpen    bool
	frameID      uint32
	decoded      uint32
}

// NewRDPGraphicsCompositor is a compositor with no output yet: the target sizes it (ResetGraphics).
func NewRDPGraphicsCompositor() *RDPGraphicsCompositor {
	return &RDPGraphicsCompositor{surfaces: map[uint16]*graphicsSurface{}, mappings: map[uint16]graphicsMapping{},
		cache: map[uint16]*graphicsCacheEntry{}}
}

// Output is the image the operator sees, nil before the target sized it. It belongs to the
// compositor: read it between two calls to Apply.
func (c *RDPGraphicsCompositor) Output() *image.RGBA { return c.output }

// FramesDecoded counts the frames ended since the channel opened.
func (c *RDPGraphicsCompositor) FramesDecoded() uint32 { return c.decoded }

func graphicsRefused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRDPGraphics}, args...)...)
}

// graphicsRect reads an RDPGFX_RECT16 (2.2.1.2): exclusive right and bottom.
func graphicsRect(b []byte) image.Rectangle {
	return image.Rect(int(binary.LittleEndian.Uint16(b[0:2])), int(binary.LittleEndian.Uint16(b[2:4])),
		int(binary.LittleEndian.Uint16(b[4:6])), int(binary.LittleEndian.Uint16(b[6:8])))
}

// rectWithin reads a rectangle and checks it is ordered and inside a surface of w x h; an empty one
// is allowed and draws nothing.
func rectWithin(b []byte, w, h int) (image.Rectangle, bool) {
	left, top := int(binary.LittleEndian.Uint16(b[0:2])), int(binary.LittleEndian.Uint16(b[2:4]))
	right, bottom := int(binary.LittleEndian.Uint16(b[4:6])), int(binary.LittleEndian.Uint16(b[6:8]))
	if left > right || top > bottom || right > w || bottom > h {
		return image.Rectangle{}, false
	}
	return image.Rect(left, top, right, bottom), true
}

// points reads count RDPGFX_POINT16 (2.2.1.1, signed), which must be all of body.
func points(body []byte, count int) ([]image.Point, bool) {
	if len(body) != 4*count {
		return nil, false
	}
	out := make([]image.Point, count)
	for i := range out {
		out[i] = image.Pt(int(int16(binary.LittleEndian.Uint16(body[4*i:]))), int(int16(binary.LittleEndian.Uint16(body[4*i+2:]))))
	}
	return out, true
}

func (c *RDPGraphicsCompositor) surface(id uint16) (*graphicsSurface, error) {
	s := c.surfaces[id]
	if s == nil {
		return nil, graphicsRefused("surface %d does not exist", id)
	}
	return s, nil
}

// copyPixels copies a w x h block between two RGBA buffers of row widths srcW and dstW, overlap
// allowed (copy is a memmove).
func copyPixels(dst []byte, dstW int, dx, dy int, src []byte, srcW int, sx, sy, w, h int) {
	if &dst[0] == &src[0] && dy > sy {
		for y := h - 1; y >= 0; y-- {
			copy(dst[((dy+y)*dstW+dx)*4:((dy+y)*dstW+dx+w)*4], src[((sy+y)*srcW+sx)*4:((sy+y)*srcW+sx+w)*4])
		}
		return
	}
	for y := range h {
		copy(dst[((dy+y)*dstW+dx)*4:((dy+y)*dstW+dx+w)*4], src[((sy+y)*srcW+sx)*4:((sy+y)*srcW+sx+w)*4])
	}
}

// Apply draws one PDU. A frame's end returns the frame (ok true); everything else returns ok false.
func (c *RDPGraphicsCompositor) Apply(pdu RDPGraphicsPDU) (frame RDPGraphicsFrame, ok bool, err error) {
	body := pdu.Body
	switch pdu.Command {
	case RDPGraphicsResetGraphics:
		// 2.2.2.14: 340 bytes; width, height, monitorCount, the monitors (20 bytes each), padding.
		if len(body) != rdpGraphicsResetSize {
			return frame, false, graphicsRefused("a ResetGraphics of %d bytes", len(body)+rdpGraphicsHeaderSize)
		}
		w, h := binary.LittleEndian.Uint32(body[0:4]), binary.LittleEndian.Uint32(body[4:8])
		monitors := binary.LittleEndian.Uint32(body[8:12])
		if w == 0 || h == 0 || w > 32766 || h > 32766 || uint64(w)*uint64(h) > screenstream.MaxPixels ||
			monitors == 0 || monitors > maxGraphicsMonitors {
			return frame, false, graphicsRefused("an output of %d x %d, %d monitor(s)", w, h, monitors)
		}
		// The output is resized (3.3.5.14); surfaces, mappings and cache stay as they are: the
		// spec says no more, and a target that wants them gone deletes them.
		output := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
		for i := 3; i < len(output.Pix); i += 4 {
			output.Pix[i] = 0xff
		}
		if c.output != nil {
			copyPixels(output.Pix, int(w), 0, 0, c.output.Pix, c.output.Rect.Dx(), 0, 0,
				min(int(w), c.output.Rect.Dx()), min(int(h), c.output.Rect.Dy()))
		}
		c.output = output
		return frame, false, nil
	case RDPGraphicsCreateSurface:
		// 2.2.2.9: surfaceId, width, height, pixelFormat.
		if len(body) != 7 {
			return frame, false, graphicsRefused("a CreateSurface of %d bytes", len(body))
		}
		id := binary.LittleEndian.Uint16(body[0:2])
		w, h := int(binary.LittleEndian.Uint16(body[2:4])), int(binary.LittleEndian.Uint16(body[4:6]))
		format := body[6]
		if c.surfaces[id] != nil {
			return frame, false, graphicsRefused("surface %d created twice", id)
		}
		if w == 0 || h == 0 || (format != rdpGraphicsPixelXRGB && format != rdpGraphicsPixelARGB) {
			return frame, false, graphicsRefused("a surface of %d x %d, format 0x%02x", w, h, format)
		}
		if len(c.surfaces) >= maxGraphicsSurfaces || c.surfaceBytes+w*h*4 > maxGraphicsSurfaceBytes {
			return frame, false, graphicsRefused("surface %d past the bounds: %d surfaces, %d bytes", id, len(c.surfaces), c.surfaceBytes)
		}
		s := &graphicsSurface{width: w, height: h, alpha: format == rdpGraphicsPixelARGB, pix: make([]byte, w*h*4)}
		if !s.alpha {
			for i := 3; i < len(s.pix); i += 4 {
				s.pix[i] = 0xff
			}
		}
		c.surfaces[id] = s
		c.surfaceBytes += len(s.pix)
		return frame, false, nil
	case RDPGraphicsDeleteSurface:
		if len(body) != 2 {
			return frame, false, graphicsRefused("a DeleteSurface of %d bytes", len(body))
		}
		id := binary.LittleEndian.Uint16(body)
		s, err := c.surface(id)
		if err != nil {
			return frame, false, err
		}
		c.surfaceBytes -= len(s.pix)
		delete(c.surfaces, id)
		delete(c.mappings, id)
		if c.progressive != nil && c.progressive.surfaces[id] != nil {
			c.progressive.tiles -= len(c.progressive.surfaces[id].tiles)
			delete(c.progressive.surfaces, id)
		}
		return frame, false, nil
	case RDPGraphicsMapSurfaceToOutput, RDPGraphicsMapSurfaceToScaledOut:
		// 2.2.2.15: surfaceId, reserved, outputOriginX, outputOriginY; 2.2.2.22 adds targetWidth and
		// targetHeight, accepted only when they are the surface's own: no scaling is done.
		want := 12
		if pdu.Command == RDPGraphicsMapSurfaceToScaledOut {
			want = 20
		}
		if len(body) != want || binary.LittleEndian.Uint16(body[2:4]) != 0 {
			return frame, false, graphicsRefused("a surface mapping of %d bytes", len(body))
		}
		id := binary.LittleEndian.Uint16(body[0:2])
		s, err := c.surface(id)
		if err != nil {
			return frame, false, err
		}
		x, y := binary.LittleEndian.Uint32(body[4:8]), binary.LittleEndian.Uint32(body[8:12])
		if x > 32766 || y > 32766 {
			return frame, false, graphicsRefused("surface %d mapped at %d, %d", id, x, y)
		}
		if want == 20 {
			tw, th := binary.LittleEndian.Uint32(body[12:16]), binary.LittleEndian.Uint32(body[16:20])
			if tw != uint32(s.width) || th != uint32(s.height) {
				return frame, false, graphicsRefused("surface %d of %d x %d scaled to %d x %d", id, s.width, s.height, tw, th)
			}
		}
		c.mappings[id] = graphicsMapping{x: int(x), y: int(y)}
		s.dirty = image.Rect(0, 0, s.width, s.height)
		return frame, false, nil
	case RDPGraphicsSolidFill:
		// 2.2.2.4: surfaceId, fillPixel (B, G, R, XA), fillRectCount, the rectangles.
		if len(body) < 8 {
			return frame, false, graphicsRefused("a SolidFill of %d bytes", len(body))
		}
		s, err := c.surface(binary.LittleEndian.Uint16(body[0:2]))
		if err != nil {
			return frame, false, err
		}
		color := [4]byte{body[4], body[3], body[2], body[5]}
		if !s.alpha {
			color[3] = 0xff
		}
		count := int(binary.LittleEndian.Uint16(body[6:8]))
		if len(body) != 8+8*count {
			return frame, false, graphicsRefused("a SolidFill of %d rectangle(s) in %d bytes", count, len(body))
		}
		for i := range count {
			r, ok := rectWithin(body[8+8*i:], s.width, s.height)
			if !ok {
				return frame, false, graphicsRefused("a fill of %v outside a %d x %d surface", graphicsRect(body[8+8*i:]), s.width, s.height)
			}
			for y := r.Min.Y; y < r.Max.Y; y++ {
				row := s.pix[(y*s.width+r.Min.X)*4 : (y*s.width+r.Max.X)*4]
				for x := 0; x < len(row); x += 4 {
					copy(row[x:x+4], color[:])
				}
			}
			s.dirty = s.dirty.Union(r)
		}
		return frame, false, nil
	case RDPGraphicsSurfaceToSurface:
		// 2.2.2.5: surfaceIdSrc, surfaceIdDest, rectSrc, destPtsCount, the points.
		if len(body) < 14 {
			return frame, false, graphicsRefused("a SurfaceToSurface of %d bytes", len(body))
		}
		src, err := c.surface(binary.LittleEndian.Uint16(body[0:2]))
		if err != nil {
			return frame, false, err
		}
		dst, err := c.surface(binary.LittleEndian.Uint16(body[2:4]))
		if err != nil {
			return frame, false, err
		}
		r, ok := rectWithin(body[4:12], src.width, src.height)
		if !ok {
			return frame, false, graphicsRefused("a copy of %v outside a %d x %d surface", graphicsRect(body[4:12]), src.width, src.height)
		}
		pts, ok := points(body[14:], int(binary.LittleEndian.Uint16(body[12:14])))
		if !ok {
			return frame, false, graphicsRefused("a SurfaceToSurface of %d bytes", len(body))
		}
		for _, p := range pts {
			to := r.Sub(r.Min).Add(p)
			if p.X < 0 || p.Y < 0 || to.Max.X > dst.width || to.Max.Y > dst.height {
				return frame, false, graphicsRefused("a copy to %v outside a %d x %d surface", to, dst.width, dst.height)
			}
			if !r.Empty() {
				copyPixels(dst.pix, dst.width, p.X, p.Y, src.pix, src.width, r.Min.X, r.Min.Y, r.Dx(), r.Dy())
				dst.dirty = dst.dirty.Union(to)
			}
		}
		return frame, false, nil
	case RDPGraphicsSurfaceToCache:
		// 2.2.2.6: surfaceId, cacheKey, cacheSlot, rectSrc.
		if len(body) != 20 {
			return frame, false, graphicsRefused("a SurfaceToCache of %d bytes", len(body))
		}
		s, err := c.surface(binary.LittleEndian.Uint16(body[0:2]))
		if err != nil {
			return frame, false, err
		}
		slot := binary.LittleEndian.Uint16(body[10:12])
		r, ok := rectWithin(body[12:20], s.width, s.height)
		if slot == 0 || slot > maxGraphicsCacheSlots || !ok || r.Empty() {
			return frame, false, graphicsRefused("a cache entry of %v in slot %d", graphicsRect(body[12:20]), slot)
		}
		entry := &graphicsCacheEntry{width: r.Dx(), height: r.Dy(), pix: make([]byte, r.Dx()*r.Dy()*4)}
		bytes := c.cacheBytes + len(entry.pix)
		if old := c.cache[slot]; old != nil {
			bytes -= len(old.pix) // a slot used again holds the new bitmap
		}
		if bytes > maxGraphicsCacheBytes {
			return frame, false, graphicsRefused("a cache of more than %d bytes", maxGraphicsCacheBytes)
		}
		copyPixels(entry.pix, entry.width, 0, 0, s.pix, s.width, r.Min.X, r.Min.Y, r.Dx(), r.Dy())
		c.cache[slot], c.cacheBytes = entry, bytes
		return frame, false, nil
	case RDPGraphicsCacheToSurface:
		// 2.2.2.7: cacheSlot, surfaceId, destPtsCount, the points.
		if len(body) < 6 {
			return frame, false, graphicsRefused("a CacheToSurface of %d bytes", len(body))
		}
		slot := binary.LittleEndian.Uint16(body[0:2])
		entry := c.cache[slot]
		if entry == nil {
			return frame, false, graphicsRefused("cache slot %d is empty", slot)
		}
		s, err := c.surface(binary.LittleEndian.Uint16(body[2:4]))
		if err != nil {
			return frame, false, err
		}
		pts, ok := points(body[6:], int(binary.LittleEndian.Uint16(body[4:6])))
		if !ok {
			return frame, false, graphicsRefused("a CacheToSurface of %d bytes", len(body))
		}
		for _, p := range pts {
			to := image.Rect(p.X, p.Y, p.X+entry.width, p.Y+entry.height)
			if p.X < 0 || p.Y < 0 || to.Max.X > s.width || to.Max.Y > s.height {
				return frame, false, graphicsRefused("a cache entry to %v outside a %d x %d surface", to, s.width, s.height)
			}
			copyPixels(s.pix, s.width, p.X, p.Y, entry.pix, entry.width, 0, 0, entry.width, entry.height)
			s.dirty = s.dirty.Union(to)
		}
		return frame, false, nil
	case RDPGraphicsEvictCacheEntry:
		if len(body) != 2 {
			return frame, false, graphicsRefused("an EvictCacheEntry of %d bytes", len(body))
		}
		slot := binary.LittleEndian.Uint16(body)
		entry := c.cache[slot]
		if entry == nil {
			return frame, false, graphicsRefused("cache slot %d evicted, empty", slot)
		}
		c.cacheBytes -= len(entry.pix)
		delete(c.cache, slot)
		return frame, false, nil
	case RDPGraphicsDeleteEncodingContext:
		// 2.2.2.3: surfaceId, codecContextId. No codec keeps a context yet: the surface must exist.
		if len(body) != 6 {
			return frame, false, graphicsRefused("a DeleteEncodingContext of %d bytes", len(body))
		}
		_, err := c.surface(binary.LittleEndian.Uint16(body[0:2]))
		return frame, false, err
	case RDPGraphicsStartFrame:
		// 2.2.2.11: timestamp, frameId.
		if len(body) != 8 || c.frameOpen {
			return frame, false, graphicsRefused("a StartFrame of %d bytes, a frame open %v", len(body), c.frameOpen)
		}
		c.frameOpen, c.frameID = true, binary.LittleEndian.Uint32(body[4:8])
		return frame, false, nil
	case RDPGraphicsEndFrame:
		if len(body) != 4 || !c.frameOpen || binary.LittleEndian.Uint32(body) != c.frameID {
			return frame, false, graphicsRefused("an EndFrame of %d bytes, not the frame started", len(body))
		}
		c.frameOpen = false
		c.decoded++
		return RDPGraphicsFrame{ID: c.frameID, Changed: c.present()}, true, nil
	case RDPGraphicsWireToSurface1:
		return frame, false, c.wireToSurface1(body)
	case RDPGraphicsWireToSurface2:
		return frame, false, c.wireToSurface2(body)
	}
	// The cache import reply answers an offer this client never makes; a window mapping is RAIL.
	return frame, false, graphicsRefused("command 0x%04x not drawn", pdu.Command)
}

// The codecs drawn (2.2.2.1): uncompressed and ClearCodec. The others are named and refused.
const (
	rdpGraphicsCodecUncompressed = uint16(0x0000)
	rdpGraphicsCodecClear        = uint16(0x0008)
)

// wireToSurface1 draws an RDPGFX_WIRE_TO_SURFACE_PDU_1 (2.2.2.1): surfaceId, codecId, pixelFormat,
// destRect, bitmapDataLength, the data. The rectangle must be inside its surface (strict reading).
func (c *RDPGraphicsCompositor) wireToSurface1(body []byte) error {
	if len(body) < 17 || uint64(binary.LittleEndian.Uint32(body[13:17])) != uint64(len(body)-17) {
		return graphicsRefused("a WireToSurface1 of %d bytes", len(body))
	}
	codec, format := binary.LittleEndian.Uint16(body[2:4]), body[4]
	if codec != rdpGraphicsCodecUncompressed && codec != rdpGraphicsCodecClear {
		return fmt.Errorf("%w: 0x%04x", ErrRDPGraphicsCodec, codec)
	}
	s, err := c.surface(binary.LittleEndian.Uint16(body[0:2]))
	if err != nil {
		return err
	}
	r, ok := rectWithin(body[5:13], s.width, s.height)
	if !ok || r.Empty() || (format != rdpGraphicsPixelXRGB && format != rdpGraphicsPixelARGB) {
		return graphicsRefused("a bitmap of %v, format 0x%02x, on a %d x %d surface", graphicsRect(body[5:13]), format, s.width, s.height)
	}
	data := body[17:]
	t := clearTarget{s: s, x: r.Min.X, y: r.Min.Y, w: r.Dx(), h: r.Dy()}
	switch codec {
	case rdpGraphicsCodecUncompressed:
		// "Pixels ... are ordered from left to right and then top to bottom"; four bytes each,
		// blue, green, red, then alpha or nothing, as RDPGFX_COLOR32. Not sent by the CI's targets.
		if len(data) != 4*t.w*t.h {
			return graphicsRefused("%d uncompressed bytes for %d x %d", len(data), t.w, t.h)
		}
		for i := range t.w * t.h {
			t.set(i%t.w, i/t.w, data[4*i], data[4*i+1], data[4*i+2])
		}
	case rdpGraphicsCodecClear:
		if c.clear == nil {
			c.clear = &clearCodec{}
		}
		if err := c.clear.decode(data, t); err != nil {
			return err
		}
	}
	s.dirty = s.dirty.Union(r)
	return nil
}

// wireToSurface2 draws an RDPGFX_WIRE_TO_SURFACE_PDU_2 (2.2.2.2): surfaceId, codecId,
// codecContextId, pixelFormat, bitmapDataLength, the data; RemoteFX Progressive only. The
// progressive state is kept by surface, as FreeRDP keeps it; the context ID is not needed to decode.
func (c *RDPGraphicsCompositor) wireToSurface2(body []byte) error {
	if len(body) < 13 || uint64(binary.LittleEndian.Uint32(body[9:13])) != uint64(len(body)-13) {
		return graphicsRefused("a WireToSurface2 of %d bytes", len(body))
	}
	codec, format := binary.LittleEndian.Uint16(body[2:4]), body[8]
	if codec != rdpGraphicsCodecProgressive {
		return fmt.Errorf("%w: 0x%04x", ErrRDPGraphicsCodec, codec)
	}
	id := binary.LittleEndian.Uint16(body[0:2])
	s, err := c.surface(id)
	if err != nil {
		return err
	}
	if format != rdpGraphicsPixelXRGB && format != rdpGraphicsPixelARGB {
		return graphicsRefused("a progressive bitmap of format 0x%02x", format)
	}
	if c.progressive == nil {
		c.progressive = &progressiveCodec{surfaces: map[uint16]*progSurface{}}
	}
	return c.progressive.decode(body[13:], id, s, c.frameID)
}

// present copies what changed of every mapped surface onto the output (3.3.5.12), opaque.
func (c *RDPGraphicsCompositor) present() image.Rectangle {
	var changed image.Rectangle
	for id, m := range c.mappings {
		s := c.surfaces[id]
		if s == nil || s.dirty.Empty() || c.output == nil {
			continue
		}
		at := s.dirty.Add(image.Pt(m.x, m.y)).Intersect(c.output.Rect)
		s.dirty = image.Rectangle{}
		if at.Empty() {
			continue
		}
		w := c.output.Rect.Dx()
		for y := at.Min.Y; y < at.Max.Y; y++ {
			from := s.pix[((y-m.y)*s.width+at.Min.X-m.x)*4 : ((y-m.y)*s.width+at.Max.X-m.x)*4]
			to := c.output.Pix[(y*w+at.Min.X)*4 : (y*w+at.Max.X)*4]
			copy(to, from)
			for x := 3; x < len(to); x += 4 {
				to[x] = 0xff
			}
		}
		changed = changed.Union(at)
	}
	return changed
}

// MarshalGraphicsFrameAcknowledge is the RDPGFX_FRAME_ACKNOWLEDGE_PDU (2.2.2.13) of a frame ended,
// queueDepth QUEUE_DEPTH_UNAVAILABLE: what the client sends after each end of frame.
func MarshalGraphicsFrameAcknowledge(frameID, totalFramesDecoded uint32) []byte {
	body := binary.LittleEndian.AppendUint32(nil, 0)
	body = binary.LittleEndian.AppendUint32(body, frameID)
	body = binary.LittleEndian.AppendUint32(body, totalFramesDecoded)
	return marshalGraphicsPDU(rdpGraphicsFrameAcknowledge, body)
}

// FrameUpdate is the part of the output a frame changed, as a bitmap update the framebuffer draws
// (ADR-0101 increment 5): one rectangle of RGBA pixels, on a desktop of the output's size, which a
// ResetGraphics may have changed. ok is false when the frame changed nothing, or before the output
// exists.
func (c *RDPGraphicsCompositor) FrameUpdate(frame RDPGraphicsFrame) (update RDPBitmapUpdate, ok bool) {
	if c.output == nil {
		return update, false
	}
	r := frame.Changed.Intersect(c.output.Rect)
	if r.Empty() {
		return update, false
	}
	pixels := make([]byte, 0, r.Dx()*r.Dy()*4)
	for y := r.Min.Y; y < r.Max.Y; y++ {
		pixels = append(pixels, c.output.Pix[c.output.PixOffset(r.Min.X, y):c.output.PixOffset(r.Max.X, y)]...)
	}
	w, h := c.output.Rect.Dx(), c.output.Rect.Dy()
	return RDPBitmapUpdate{
		Rectangles:   []RDPBitmapRectangle{{X: uint16(r.Min.X), Y: uint16(r.Min.Y), Width: uint16(r.Dx()), Height: uint16(r.Dy()), Pixels: pixels}},
		DesktopWidth: uint16(w), DesktopHeight: uint16(h),
	}, true
}
