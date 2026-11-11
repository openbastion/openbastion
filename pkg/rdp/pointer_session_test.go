package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"image"
	"image/draw"
	"image/png"
	"net"
	"testing"
	"time"
)

// slowPathShareData wraps a Share Data payload of pduType2 in its Share Data Header, MCS Send Data
// Indication on the I/O channel and TPKT, as a server sends it.
func slowPathShareData(shareID uint32, pduType2 byte, payload []byte) []byte {
	share := make([]byte, 18+len(payload))
	binary.LittleEndian.PutUint16(share[:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint16(share[4:6], rdpServerChannelID)
	binary.LittleEndian.PutUint32(share[6:10], shareID)
	share[11] = 2
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(share)))
	share[14] = pduType2
	copy(share[18:], payload)
	mcs := []byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x70}
	mcs = appendPERLength(mcs, len(share))
	mcs = append(mcs, share...)
	packet := make([]byte, 7+len(mcs))
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
}

// readUpdatesFrom serves stream over TLS and reads up to n updates from it, as the proxy does, with
// the pointer drawn or not. It stops at the first error.
func readUpdatesFrom(t *testing.T, stream []byte, pointerShapes bool, n int) ([]RDPBitmapUpdate, error) {
	t.Helper()
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if tlsConn.Handshake() == nil {
			_ = writeFull(tlsConn, stream)
			var one [1]byte
			_, _ = tlsConn.Read(one[:])
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
		mcsResponse:        MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		mcsSettings:        MCSClientSettings{PointerShapes: pointerShapes},
		serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32},
	}
	defer session.Close()
	var updates []RDPBitmapUpdate
	for len(updates) < n {
		update, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
		if err != nil {
			return updates, err
		}
		updates = append(updates, update)
	}
	return updates, nil
}

func pointerStream() []byte {
	white := []byte{0xff, 0xff, 0xff, 0xff}
	shape := newPointer(32, colorPointer(3, 0, 0, 1, 1, 32, [][]byte{white}, [][]bool{{false}}))
	bitmap := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))
	var stream []byte
	stream = append(stream, fastPathPDU(rdpFastPathPointerNew, 0, shape)...)
	stream = append(stream, fastPathPDU(rdpFastPathPointerPosition, 0, []byte{4, 0, 5, 0})...)
	stream = append(stream, slowPathShareData(0x000103ea, rdpPDU2Pointer, pointerPDU(rdpPointerMessageCached, []byte{3, 0}))...)
	stream = append(stream, fastPathPDU(rdpFastPathPointerHidden, 0, nil)...)
	return append(stream, bitmap...)
}

// Drawn, the pointer's updates come out of ReadBitmapUpdate in order, Fast-Path and slow-path, and
// the bitmap after them; not drawn, they are ignored as before, and the bitmap is the first update.
func TestReadBitmapUpdateReturnsThePointerWhenItIsDrawn(t *testing.T) {
	updates, err := readUpdatesFrom(t, pointerStream(), true, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []RDPPointerKind{RDPPointerShape, RDPPointerPosition, RDPPointerCached, RDPPointerHidden}
	for i, kind := range want {
		if updates[i].Pointer == nil || updates[i].Pointer.Kind != kind || len(updates[i].Rectangles) != 0 {
			t.Fatalf("update %d: %+v, want a pointer update of kind %d", i, updates[i], kind)
		}
	}
	if updates[0].Pointer.CacheIndex != 3 || updates[0].Pointer.Shape == nil || updates[1].Pointer.X != 4 ||
		updates[1].Pointer.Y != 5 || updates[2].Pointer.CacheIndex != 3 {
		t.Fatalf("pointer updates %+v %+v %+v", updates[0].Pointer, updates[1].Pointer, updates[2].Pointer)
	}
	if updates[4].Pointer != nil || len(updates[4].Rectangles) != 1 || updates[0].DesktopWidth != 8 || updates[4].Reactivated {
		t.Fatalf("the bitmap after the pointer: %+v", updates[4])
	}

	updates, err = readUpdatesFrom(t, pointerStream(), false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if updates[0].Pointer != nil || len(updates[0].Rectangles) != 1 {
		t.Fatalf("not drawn, the pointer is ignored: %+v", updates[0])
	}
}

// Drawn, a pointer update outside the profile closes the session, said as a pointer refusal; not
// drawn, the same bytes are ignored, as they were before ADR-0091.
func TestReadBitmapUpdateRefusesAPointerOutsideTheProfile(t *testing.T) {
	bitmap := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))
	for name, bad := range map[string][]byte{
		"fast-path new at 16 bpp": fastPathPDU(rdpFastPathPointerNew, 0,
			newPointer(16, colorPointer(0, 0, 0, 1, 1, 16, [][]byte{{1, 2}}, [][]bool{{false}}))),
		"fast-path position of 3 bytes": fastPathPDU(rdpFastPathPointerPosition, 0, []byte{1, 2, 3}),
		"slow-path system pointer of another kind": slowPathShareData(0x000103ea, rdpPDU2Pointer,
			pointerPDU(rdpPointerMessageSystem, []byte{1, 0, 0, 0})),
	} {
		_, err := readUpdatesFrom(t, append(append([]byte(nil), bad...), bitmap...), true, 1)
		if !errors.Is(err, ErrRDPPointer) || !errors.Is(err, ErrMCSConnection) {
			t.Errorf("%s, drawn: %v, want ErrRDPPointer", name, err)
		}
		updates, err := readUpdatesFrom(t, append(append([]byte(nil), bad...), bitmap...), false, 1)
		if err != nil || len(updates[0].Rectangles) != 1 {
			t.Errorf("%s, not drawn: %+v, %v; want it ignored", name, updates, err)
		}
	}
}

func TestPointerCacheIsAnnouncedOnlyWhenThePointerIsDrawn(t *testing.T) {
	pointerCapability := func(settings MCSClientSettings) []byte {
		caps := marshalRDPClientCapabilitySets(settings, 32)
		for offset := 0; offset+4 <= len(caps); {
			kind, length := binary.LittleEndian.Uint16(caps[offset:]), int(binary.LittleEndian.Uint16(caps[offset+2:]))
			if kind == rdpCapPointer {
				return caps[offset : offset+length]
			}
			offset += length
		}
		t.Fatal("no Pointer Capability Set")
		return nil
	}
	drawn := pointerCapability(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, PointerShapes: true})
	if len(drawn) != 10 || binary.LittleEndian.Uint16(drawn[4:6]) != 1 ||
		binary.LittleEndian.Uint16(drawn[6:8]) != rdpPointerCacheSize || binary.LittleEndian.Uint16(drawn[8:10]) != rdpPointerCacheSize {
		t.Fatalf("drawn: %x, want colour pointers and both caches at %d", drawn, rdpPointerCacheSize)
	}
	if off := pointerCapability(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800}); binary.LittleEndian.Uint16(off[6:8]) != 0 ||
		binary.LittleEndian.Uint16(off[8:10]) != 0 {
		t.Fatalf("not drawn: %x, want no cache", off)
	}
}

// The frame carries the pointer; the framebuffer does not keep it: the next frame without it is the
// desktop as the target drew it.
func TestFrameWithPointerDrawsOnACopy(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	pointer := NewRDPPointer()
	plain, err := framebuffer.FrameWithPointer(time.Unix(1, 0), pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.MoveTo(3, 3)
	drawn, err := framebuffer.FrameWithPointer(time.Unix(2, 0), pointer)
	if err != nil {
		t.Fatal(err)
	}
	after, err := framebuffer.Frame(time.Unix(3, 0))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain.PNG) == string(drawn.PNG) {
		t.Fatal("the placed pointer is not in the frame")
	}
	if string(plain.PNG) != string(after.PNG) {
		t.Fatal("the pointer stayed in the framebuffer")
	}
	if drawn.Sequence != plain.Sequence+1 || after.Sequence != drawn.Sequence+1 {
		t.Fatal("a frame with the pointer is a frame of the sequence like any other")
	}
	tip := decodePNG(t, drawn.PNG).RGBAAt(3, 3)
	if tip.R != 0 || tip.A != 0xff || decodePNG(t, drawn.PNG).RGBAAt(4, 5).R != 0xff {
		t.Fatalf("the arrow is not where it was placed: tip %v", tip)
	}
}

func decodePNG(t *testing.T, data []byte) *image.RGBA {
	t.Helper()
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(decoded.Bounds())
	draw.Draw(img, img.Bounds(), decoded, image.Point{}, draw.Src)
	return img
}
