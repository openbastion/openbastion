package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReadStartupPacketParsesProtocolV3Parameters(t *testing.T) {
	wire := startupPacket(ProtocolVersion3, []byte("user\x00app\x00database\x00inventory\x00application_name\x00openbastion-test\x00\x00"))
	got, err := ReadStartupPacket(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadStartupPacket: %v", err)
	}
	if got.Kind != Startup || got.ProtocolVersion != ProtocolVersion3 {
		t.Fatalf("packet kind/version = %v/%d", got.Kind, got.ProtocolVersion)
	}
	if got.Parameters["user"] != "app" || got.Parameters["database"] != "inventory" || got.Parameters["application_name"] != "openbastion-test" {
		t.Fatalf("unexpected parameters: %#v", got.Parameters)
	}
}

func TestReadStartupPacketRecognizesSpecialRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
		kind PacketKind
	}{
		{name: "ssl", code: SSLRequestCode, kind: SSLRequest},
		{name: "gss", code: GSSENCRequestCode, kind: GSSENCRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadStartupPacket(bytes.NewReader(startupPacket(tc.code, nil)))
			if err != nil {
				t.Fatalf("ReadStartupPacket: %v", err)
			}
			if got.Kind != tc.kind {
				t.Fatalf("kind = %v, want %v", got.Kind, tc.kind)
			}
		})
	}

	cancel := make([]byte, 16)
	binary.BigEndian.PutUint32(cancel[:4], uint32(len(cancel)))
	binary.BigEndian.PutUint32(cancel[4:8], CancelRequestCode)
	binary.BigEndian.PutUint32(cancel[8:12], 1234)
	binary.BigEndian.PutUint32(cancel[12:16], 5678)
	got, err := ReadStartupPacket(bytes.NewReader(cancel))
	if err != nil {
		t.Fatalf("CancelRequest: %v", err)
	}
	if got.Kind != CancelRequest || got.CancelPID != 1234 || got.CancelSecret != 5678 {
		t.Fatalf("unexpected cancel request: %#v", got)
	}
}

func TestReadStartupPacketRejectsMalformedInput(t *testing.T) {
	validParams := []byte("user\x00app\x00\x00")
	cases := []struct {
		name string
		wire []byte
	}{
		{name: "short header", wire: []byte{0, 0, 0}},
		{name: "length below header", wire: []byte{0, 0, 0, 7, 0, 3, 0, 0}},
		{name: "truncated body", wire: startupPacket(ProtocolVersion3, validParams)[:10]},
		{name: "missing parameter terminator", wire: startupPacket(ProtocolVersion3, []byte("user\x00app\x00"))},
		{name: "empty parameter name", wire: startupPacket(ProtocolVersion3, []byte("\x00value\x00\x00"))},
		{name: "duplicate parameter", wire: startupPacket(ProtocolVersion3, []byte("user\x00one\x00user\x00two\x00\x00"))},
		{name: "unsupported protocol", wire: startupPacket(0x00020000, validParams)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadStartupPacket(bytes.NewReader(tc.wire)); err == nil {
				t.Fatal("malformed packet was accepted")
			}
		})
	}
}

func TestReadStartupPacketRejectsOversizedLengthBeforeAllocation(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxStartupPacketBytes+1)
	if _, err := ReadStartupPacket(bytes.NewReader(header[:])); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("error = %v, want ErrPacketTooLarge", err)
	}
}

func TestReadFrontendMessageBoundsAndReadsPayload(t *testing.T) {
	wire := frontendMessage('Q', []byte("select 1\x00"))
	got, err := ReadFrontendMessage(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadFrontendMessage: %v", err)
	}
	if got.Type != 'Q' || string(got.Payload) != "select 1\x00" {
		t.Fatalf("unexpected message: %#v", got)
	}
}

func TestReadFrontendMessageRejectsInvalidLengths(t *testing.T) {
	for _, length := range []uint32{0, 3, MaxFrontendMessageBytes + 1} {
		var wire bytes.Buffer
		wire.WriteByte('Q')
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], length)
		wire.Write(header[:])
		_, err := ReadFrontendMessage(&wire)
		if err == nil {
			t.Fatalf("length %d was accepted", length)
		}
	}
}

func TestWriteBackendMessageUsesPostgreSQLFraming(t *testing.T) {
	var got bytes.Buffer
	if err := WriteBackendMessage(&got, 'R', []byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("WriteBackendMessage: %v", err)
	}
	want := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("wire = %v, want %v", got.Bytes(), want)
	}
}

func TestWriteSSLResponse(t *testing.T) {
	var got bytes.Buffer
	if err := WriteSSLResponse(&got, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), []byte{'S'}) {
		t.Fatalf("accepted response = %q", got.Bytes())
	}
	got.Reset()
	if err := WriteSSLResponse(&got, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), []byte{'N'}) {
		t.Fatalf("refused response = %q", got.Bytes())
	}
}

func TestReadStartupPacketPropagatesUnexpectedEOF(t *testing.T) {
	_, err := ReadStartupPacket(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want EOF", err)
	}
}

func startupPacket(code uint32, payload []byte) []byte {
	wire := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(wire[:4], uint32(len(wire)))
	binary.BigEndian.PutUint32(wire[4:8], code)
	copy(wire[8:], payload)
	return wire
}

func frontendMessage(kind byte, payload []byte) []byte {
	wire := make([]byte, 5+len(payload))
	wire[0] = kind
	binary.BigEndian.PutUint32(wire[1:5], uint32(4+len(payload)))
	copy(wire[5:], payload)
	return wire
}

func FuzzReadStartupPacket(f *testing.F) {
	f.Add(startupPacket(ProtocolVersion3, []byte("user\x00app\x00\x00")))
	f.Add(startupPacket(SSLRequestCode, nil))
	f.Add(startupPacket(GSSENCRequestCode, nil))
	cancel := make([]byte, 16)
	binary.BigEndian.PutUint32(cancel[:4], 16)
	binary.BigEndian.PutUint32(cancel[4:8], CancelRequestCode)
	f.Add(cancel)
	f.Add([]byte{0, 0, 0, 8, 0, 3, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > int(MaxStartupPacketBytes)+1 {
			t.Skip()
		}
		_, _ = ReadStartupPacket(bytes.NewReader(wire))
	})
}

func FuzzReadFrontendMessage(f *testing.F) {
	f.Add(frontendMessage('Q', []byte("select 1\x00")))
	f.Add([]byte{'Q', 0, 0, 0, 4})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > int(MaxFrontendMessageBytes)+1 {
			t.Skip()
		}
		_, _ = ReadFrontendMessage(bytes.NewReader(wire))
	})
}
