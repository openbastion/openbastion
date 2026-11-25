package pgwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParsePasswordMessageReturnsBytesWithoutTerminator(t *testing.T) {
	got, err := ParsePasswordMessage(FrontendMessage{Type: 'p', Payload: []byte("opaque-ticket\x00")})
	if err != nil {
		t.Fatalf("ParsePasswordMessage: %v", err)
	}
	if string(got) != "opaque-ticket" {
		t.Fatalf("password = %q", got)
	}
}

func TestParsePasswordMessageRejectsWrongTypeAndMalformedCString(t *testing.T) {
	cases := []FrontendMessage{
		{Type: 'Q', Payload: []byte("ticket\x00")},
		{Type: 'p', Payload: []byte("ticket")},
		{Type: 'p', Payload: []byte("ticket\x00extra\x00")},
		{Type: 'p', Payload: nil},
	}
	for i, input := range cases {
		if _, err := ParsePasswordMessage(input); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
}

func TestAuthenticationMessagesUsePostgreSQLWireCodes(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteAuthenticationRequest(&wire, AuthenticationCleartextPassword, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("AuthenticationCleartextPassword = %v", wire.Bytes())
	}
	wire.Reset()
	if err := WriteAuthenticationRequest(&wire, AuthenticationOK, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}) {
		t.Fatalf("AuthenticationOK = %v", wire.Bytes())
	}
}

func TestWriteBackendKeyDataAndReadyForQuery(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteBackendKeyData(&wire, 11, 22); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{'K', 0, 0, 0, 12, 0, 0, 0, 11, 0, 0, 0, 22}) {
		t.Fatalf("BackendKeyData = %v", wire.Bytes())
	}
	wire.Reset()
	if err := WriteReadyForQuery(&wire, 'I'); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{'Z', 0, 0, 0, 5, 'I'}) {
		t.Fatalf("ReadyForQuery = %v", wire.Bytes())
	}
}

func TestParseCommandCompleteTag(t *testing.T) {
	got, err := ParseCommandComplete(FrontendMessage{Type: 'C', Payload: []byte("UPDATE 7\x00")})
	if err != nil || got != "UPDATE 7" {
		t.Fatalf("tag=%q err=%v", got, err)
	}
	for _, payload := range [][]byte{nil, []byte("UPDATE 7"), []byte("UPDATE\x00junk\x00")} {
		if _, err := ParseCommandComplete(FrontendMessage{Type: 'C', Payload: payload}); err == nil {
			t.Errorf("malformed command tag %q was accepted", payload)
		}
	}
}

func TestWriteErrorResponseIncludesOnlyCallerProvidedFields(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteErrorResponse(&wire, "ERROR", "28000", "authentication failed"); err != nil {
		t.Fatal(err)
	}
	got := wire.Bytes()
	if got[0] != 'E' || binary.BigEndian.Uint32(got[1:5]) != uint32(len(got)-1) {
		t.Fatalf("invalid ErrorResponse frame: %v", got)
	}
	if bytes.Contains(got, []byte("password")) {
		t.Fatal("ErrorResponse contains a secret-like field")
	}
}
