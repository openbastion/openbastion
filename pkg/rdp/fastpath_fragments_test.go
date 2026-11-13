package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// fastPathPDU is one Fast-Path PDU carrying one update of code with fragmentation frag.
func fastPathPDU(code, frag byte, data []byte) []byte {
	update := append([]byte{code | frag<<4, 0, 0}, data...)
	binary.LittleEndian.PutUint16(update[1:3], uint16(len(data)))
	length := len(update) + 3
	return append([]byte{0, 0x80 | byte(length>>8), byte(length)}, update...)
}

func TestSplitRDPFastPathUpdate(t *testing.T) {
	code, frag, data, err := splitRDPFastPathUpdate(fastPathPDU(1, rdpFastPathFragmentFirst, []byte{1, 2, 3}))
	if err != nil || code != 1 || frag != rdpFastPathFragmentFirst || !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatalf("%d %d %v %v", code, frag, data, err)
	}
	compressed := fastPathPDU(1, 0, []byte{1})
	compressed[3] |= 0x80                                   // FASTPATH_OUTPUT_COMPRESSION_USED: not negotiated
	two := append(fastPathPDU(1, 0, []byte{1}), 0x03, 0, 0) // a second update in the same PDU
	binary.BigEndian.PutUint16(two[1:3], 0x8000|uint16(len(two)))
	for name, bad := range map[string][]byte{
		"compressed":         compressed,
		"two updates":        two,
		"encrypted (action)": append([]byte{0x80}, fastPathPDU(1, 0, []byte{1})[1:]...),
		"short":              {0, 3, 1},
	} {
		if _, _, _, err := splitRDPFastPathUpdate(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRDPFastPathAssembler(t *testing.T) {
	var a rdpFastPathAssembler
	steps := []struct {
		frag byte
		data []byte
	}{{rdpFastPathFragmentFirst, []byte{1, 2}}, {rdpFastPathFragmentNext, []byte{3}}, {rdpFastPathFragmentLast, []byte{4, 5}}}
	for i, s := range steps {
		got, done, err := a.add(9, s.frag, s.data)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if done != (i == len(steps)-1) {
			t.Fatalf("step %d: done %v", i, done)
		}
		if done && !bytes.Equal(got, []byte{1, 2, 3, 4, 5}) {
			t.Fatalf("reassembled %v", got)
		}
	}
	if got, done, err := a.add(1, rdpFastPathFragmentSingle, []byte{7}); err != nil || !done || !bytes.Equal(got, []byte{7}) {
		t.Fatalf("single after a complete sequence: %v %v %v", got, done, err)
	}
}

// What a server cannot make the client do: a sequence out of order, a code changing mid-way, an
// update past the size the client announced, or a sequence that never ends.
func TestRDPFastPathAssemblerRefuses(t *testing.T) {
	type step struct {
		code, frag byte
		data       []byte
	}
	big := make([]byte, maxRDPFastPathReassembly/2+1)
	cases := map[string][]step{
		"next without first":         {{1, rdpFastPathFragmentNext, []byte{1}}},
		"next without first, code 0": {{0, rdpFastPathFragmentNext, []byte{1}}},
		"last without first":         {{1, rdpFastPathFragmentLast, []byte{1}}},
		"first after first":          {{1, rdpFastPathFragmentFirst, []byte{1}}, {1, rdpFastPathFragmentFirst, []byte{1}}},
		"single mid-sequence":        {{1, rdpFastPathFragmentFirst, []byte{1}}, {1, rdpFastPathFragmentSingle, []byte{1}}},
		"code changes":               {{1, rdpFastPathFragmentFirst, []byte{1}}, {9, rdpFastPathFragmentLast, []byte{1}}},
		"past the announced":         {{1, rdpFastPathFragmentFirst, big}, {1, rdpFastPathFragmentLast, big}},
		"empty fragment":             {{1, rdpFastPathFragmentFirst, nil}},
		"too many fragments":         append([]step{{1, rdpFastPathFragmentFirst, []byte{1}}}, repeatSteps(step{1, rdpFastPathFragmentNext, []byte{1}}, maxRDPFastPathFragments)...),
	}
	for name, steps := range cases {
		var a rdpFastPathAssembler
		var err error
		for _, s := range steps {
			if _, _, err = a.add(s.code, s.frag, s.data); err != nil {
				break
			}
		}
		if !errors.Is(err, ErrMCSConnection) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func repeatSteps[T any](s T, n int) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// The client announces the size it reassembles (TS_MULTIFRAGMENTUPDATE_CAPABILITYSET), which is
// the bound it holds the server to.
func TestClientAnnouncesItsReassemblySize(t *testing.T) {
	caps := marshalRDPClientCapabilitySets(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800}, 32)
	for rest := caps; len(rest) >= 4; {
		kind, size := binary.LittleEndian.Uint16(rest[:2]), int(binary.LittleEndian.Uint16(rest[2:4]))
		if kind == rdpCapMultifragmentUpdate {
			if size != 8 || binary.LittleEndian.Uint32(rest[4:8]) != maxRDPFastPathReassembly {
				t.Fatalf("multifragment set %x", rest[:size])
			}
			return
		}
		rest = rest[size:]
	}
	t.Fatal("no TS_MULTIFRAGMENTUPDATE_CAPABILITYSET")
}

func FuzzRDPFastPathAssembler(f *testing.F) {
	f.Add([]byte{0x21, 0x31, 0x11})
	f.Fuzz(func(t *testing.T, headers []byte) {
		var a rdpFastPathAssembler
		total := 0
		for _, h := range headers {
			got, done, err := a.add(h&0x0f, h>>4&0x3, []byte{h})
			if err != nil {
				return
			}
			total++
			if done && len(got) > maxRDPFastPathReassembly {
				t.Fatalf("%d bytes", len(got))
			}
		}
		_ = total
	})
}

// Over TLS, through ReadBitmapUpdate: a bitmap update in three fragments behind a fragmented
// pointer comes out whole; a sequence a TPKT interrupts ends the session.
func TestReadBitmapUpdateReassemblesFastPathFragments(t *testing.T) {
	bitmap := append(binary.LittleEndian.AppendUint16(nil, rdpUpdateBitmap), 1, 0)
	bitmap = append(bitmap, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0})...)
	pieces := [][]byte{bitmap[:5], bitmap[5:12], bitmap[12:]}
	stream := append(fastPathPDU(9, rdpFastPathFragmentFirst, []byte{1, 2}), fastPathPDU(9, rdpFastPathFragmentLast, []byte{3})...)
	stream = append(stream, fastPathPDU(1, rdpFastPathFragmentFirst, pieces[0])...)
	stream = append(stream, fastPathPDU(1, rdpFastPathFragmentNext, pieces[1])...)
	stream = append(stream, fastPathPDU(1, rdpFastPathFragmentLast, pieces[2])...)
	session := fastPathTestSession(t, stream)
	update, err := session.ReadBitmapUpdate(context.Background(), time.Second)
	session.Close()
	if err != nil || len(update.Rectangles) != 1 || !bytes.Equal(update.Rectangles[0].Pixels, []byte{0xff, 0, 0, 0xff}) {
		t.Fatalf("%+v, %v", update, err)
	}

	interrupted := append(fastPathPDU(1, rdpFastPathFragmentFirst, pieces[0]), mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))...)
	session = fastPathTestSession(t, interrupted)
	defer session.Close()
	if _, err := session.ReadBitmapUpdate(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("interrupted: %v", err)
	}
}

func fastPathTestSession(t *testing.T, stream []byte) *CredSSPClientSession {
	t.Helper()
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
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
	return &CredSSPClientSession{
		transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
		mcsResponse:        MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32},
	}
}

// The isolations' reader reassembles as the codec does: nothing until LAST, nothing for a pointer.
func TestReassembleFastPathForIsolations(t *testing.T) {
	bitmap := append(binary.LittleEndian.AppendUint16(nil, rdpUpdateBitmap), 1, 0)
	bitmap = append(bitmap, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0})...)
	caps := RDPServerCapabilities{DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32}
	var a rdpFastPathAssembler
	if u, err := reassembleFastPath(&a, fastPathPDU(9, 0, []byte{1}), caps); u != nil || err != nil {
		t.Fatalf("pointer: %v %v", u, err)
	}
	if u, err := reassembleFastPath(&a, fastPathPDU(1, rdpFastPathFragmentFirst, bitmap[:6]), caps); u != nil || err != nil {
		t.Fatalf("first: %v %v", u, err)
	}
	u, err := reassembleFastPath(&a, fastPathPDU(1, rdpFastPathFragmentLast, bitmap[6:]), caps)
	if err != nil || u == nil || len(u.Rectangles) != 1 {
		t.Fatalf("last: %v %v", u, err)
	}
}

// A refused fragmented update says which rule refused it: a LAST refused on Windows Server 2019
// after a reactivation did not say whether it had no FIRST or crossed a bound (CI of PR #157).
func TestFastPathAssembler_SaysWhichRuleRefused(t *testing.T) {
	for want, steps := range map[string][][2]byte{
		"no first fragment before it": {{rdpFastPathUpdateBitmap, rdpFastPathFragmentLast}},
		"inside a fragmented one":     {{rdpFastPathUpdateBitmap, rdpFastPathFragmentFirst}, {rdpFastPathUpdateBitmap, rdpFastPathFragmentSingle}},
		"inside code":                 {{rdpFastPathUpdateBitmap, rdpFastPathFragmentFirst}, {rdpFastPathPointerPosition, rdpFastPathFragmentLast}},
	} {
		var a rdpFastPathAssembler
		var err error
		for _, step := range steps {
			if _, _, err = a.add(step[0], step[1], []byte{1}); err != nil {
				break
			}
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
	}
	var a rdpFastPathAssembler
	a.add(rdpFastPathUpdateBitmap, rdpFastPathFragmentFirst, make([]byte, maxRDPFastPathReassembly-1))
	if _, _, err := a.add(rdpFastPathUpdateBitmap, rdpFastPathFragmentLast, []byte{1, 2}); err == nil || !strings.Contains(err.Error(), "reassembly bound") {
		t.Errorf("past the bound: %v", err)
	}
}
