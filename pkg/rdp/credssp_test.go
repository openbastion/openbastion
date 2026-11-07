package rdp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func TestTSRequestDERRoundTrip(t *testing.T) {
	code := uint32(0x80070005)
	want := TSRequest{
		Version: 6, NegoTokens: [][]byte{{0x60, 0x03, 0x06, 0x01, 0x2b}, {0x01, 0x02}},
		AuthInfo: []byte{1, 2, 3}, PubKeyAuth: []byte{4, 5}, ErrorCode: &code,
		ClientNonce: bytes.Repeat([]byte{0xa5}, 32),
	}
	encoded, err := MarshalTSRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTSRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, want)
	}
	encodedAgain, err := MarshalTSRequest(got)
	if err != nil || !bytes.Equal(encoded, encodedAgain) {
		t.Fatalf("DER encoding is not stable: %v", err)
	}
}

func TestTSRequestDERKnownInitialMessage(t *testing.T) {
	encoded, err := MarshalTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{{0x01, 0x02, 0x03}}})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "3012a003020106a10b30093007a0050403010203"
	if got := hex.EncodeToString(encoded); got != expected {
		t.Fatalf("DER = %s, want %s", got, expected)
	}
}

func TestTSRequestParsesSignedNTSTATUSErrorCodes(t *testing.T) {
	cases := []struct {
		name string
		der  []byte
		want uint32
	}{
		{"logon failure", []byte{0xc0, 0x00, 0x00, 0x6d}, 0xc000006d},
		{"wrong password", []byte{0xc0, 0x00, 0x00, 0x6a}, 0xc000006a},
		{"unsigned positive encoding", []byte{0x00, 0x80, 0x07, 0x00, 0x05}, 0x80070005},
		{"small positive", []byte{0x01}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			integer := derWrap(0x02, tc.der)
			encoded := derWrap(0x30, append(derWrap(0xa0, derWrap(0x02, []byte{6})), derWrap(0xa4, integer)...))
			got, err := ParseTSRequest(encoded)
			if err != nil || got.ErrorCode == nil || *got.ErrorCode != tc.want {
				t.Fatalf("ParseTSRequest() = %#v, %v; want errorCode %#08x", got, err, tc.want)
			}
		})
	}
}

func TestTSRequestRejectsNonCanonicalOrOutOfRangeErrorCode(t *testing.T) {
	cases := map[string][]byte{
		"redundant positive sign": {0x00, 0x01},
		"redundant negative sign": {0xff, 0x80},
		"out of signed range":     {0xff, 0x7f, 0xff, 0xff, 0xff},
		"too wide":                {0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
	}
	for name, integer := range cases {
		t.Run(name, func(t *testing.T) {
			encoded := derWrap(0x30, append(derWrap(0xa0, derWrap(0x02, []byte{6})), derWrap(0xa4, derWrap(0x02, integer))...))
			if _, err := ParseTSRequest(encoded); !errors.Is(err, ErrCredSSPMessage) {
				t.Fatalf("ParseTSRequest() error = %v, want ErrCredSSPMessage", err)
			}
		})
	}
}

func TestTSRequestRejectsMalformedDER(t *testing.T) {
	valid, err := MarshalTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{{1, 2, 3}}})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":               nil,
		"trailing":            append(append([]byte(nil), valid...), 0),
		"truncated":           valid[:len(valid)-1],
		"indefinite length":   {0x30, 0x80, 0, 0},
		"noncanonical length": {0x30, 0x81, 0x03, 0xa0, 0x01, 0x00},
		"missing version":     {0x30, 0x00},
		"duplicate version":   {0x30, 0x0a, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa0, 0x03, 0x02, 0x01, 0x06},
		"unsupported version": {0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x07},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTSRequest(data); !errors.Is(err, ErrCredSSPMessage) {
				t.Fatalf("got %v, want ErrCredSSPMessage", err)
			}
		})
	}
}

func TestTSRequestBoundsPayloads(t *testing.T) {
	cases := []TSRequest{
		{Version: 6, NegoTokens: [][]byte{{}}},
		{Version: 6, NegoTokens: [][]byte{bytes.Repeat([]byte{1}, maxCredSSPToken+1)}},
		{Version: 6, AuthInfo: bytes.Repeat([]byte{1}, maxCredSSPToken+1)},
		{Version: 6, ClientNonce: []byte{1}},
		{Version: 1},
		{Version: 7},
	}
	for i, req := range cases {
		if _, err := MarshalTSRequest(req); !errors.Is(err, ErrCredSSPMessage) {
			t.Errorf("case %d: got %v, want ErrCredSSPMessage", i, err)
		}
	}
}

func FuzzParseTSRequest(f *testing.F) {
	seed, _ := MarshalTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{{1, 2, 3}}})
	f.Add(seed)
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add([]byte("CredSSP"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxCredSSPMessage*2 {
			t.Skip()
		}
		_, _ = ParseTSRequest(data)
	})
}
