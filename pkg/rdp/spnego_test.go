package rdp

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"
)

func wrapDERForTest(t testing.TB, tag byte, value []byte) []byte {
	t.Helper()
	return derWrap(tag, value)
}
func marshalOIDForTest(t testing.TB, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, e := asn1.Marshal(oid)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func initialSPNEGOTokenForTest(t testing.TB) []byte {
	t.Helper()
	mech := wrapDERForTest(t, 0x30, marshalOIDForTest(t, ntlmOID))
	fields := wrapDERForTest(t, 0xa0, mech)
	fields = append(fields, wrapDERForTest(t, 0xa1, wrapDERForTest(t, 0x03, []byte{0}))...)
	fields = append(fields, wrapDERForTest(t, 0xa2, wrapDERForTest(t, 0x04, []byte("challenge")))...)
	fields = append(fields, wrapDERForTest(t, 0xa3, wrapDERForTest(t, 0x04, []byte("mic")))...)
	return wrapDERForTest(t, 0x60, append(marshalOIDForTest(t, spnegoOID), wrapDERForTest(t, 0xa0, wrapDERForTest(t, 0x30, fields))...))
}
func responseSPNEGOTokenForTest(t testing.TB, state byte) []byte {
	t.Helper()
	fields := wrapDERForTest(t, 0xa0, wrapDERForTest(t, 0x0a, []byte{state}))
	fields = append(fields, wrapDERForTest(t, 0xa1, marshalOIDForTest(t, ntlmOID))...)
	fields = append(fields, wrapDERForTest(t, 0xa2, wrapDERForTest(t, 0x04, []byte("response")))...)
	fields = append(fields, wrapDERForTest(t, 0xa3, wrapDERForTest(t, 0x04, []byte("mic")))...)
	return wrapDERForTest(t, 0xa1, wrapDERForTest(t, 0x30, fields))
}
func TestParseSPNEGOInit(t *testing.T) {
	got, err := ParseSPNEGONegTokenInit(initialSPNEGOTokenForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Mechanisms) != 1 || !got.Mechanisms[0].Equal(ntlmOID) || !bytes.Equal(got.MechanismToken, []byte("challenge")) || !bytes.Equal(got.MechanismListMIC, []byte("mic")) {
		t.Fatalf("unexpected result: %#v", got)
	}
}
func TestParseSPNEGOResp(t *testing.T) {
	got, err := ParseSPNEGONegTokenResp(responseSPNEGOTokenForTest(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != 1 || !got.SupportedMech.Equal(ntlmOID) || !bytes.Equal(got.ResponseToken, []byte("response")) {
		t.Fatalf("unexpected result: %#v", got)
	}
}
func TestParseSPNEGORejectsUnsupportedMechanisms(t *testing.T) {
	k := asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	mech := wrapDERForTest(t, 0x30, marshalOIDForTest(t, k))
	init := wrapDERForTest(t, 0x60, append(marshalOIDForTest(t, spnegoOID), wrapDERForTest(t, 0xa0, wrapDERForTest(t, 0x30, wrapDERForTest(t, 0xa0, mech)))...))
	if _, e := ParseSPNEGONegTokenInit(init); !errors.Is(e, ErrSPNEGOMechanism) {
		t.Fatalf("init: %v", e)
	}
	resp := wrapDERForTest(t, 0xa1, wrapDERForTest(t, 0x30, wrapDERForTest(t, 0xa1, marshalOIDForTest(t, k))))
	if _, e := ParseSPNEGONegTokenResp(resp); !errors.Is(e, ErrSPNEGOMechanism) {
		t.Fatalf("resp: %v", e)
	}
}
func TestParseSPNEGORejectsBadStateAndMalformed(t *testing.T) {
	if _, e := ParseSPNEGONegTokenResp(responseSPNEGOTokenForTest(t, 2)); !errors.Is(e, ErrSPNEGONegotiation) {
		t.Fatalf("reject state: %v", e)
	}
	if _, e := ParseSPNEGONegTokenResp(responseSPNEGOTokenForTest(t, 3)); !errors.Is(e, ErrSPNEGONegotiation) {
		t.Fatalf("request mic state: %v", e)
	}
	good := initialSPNEGOTokenForTest(t)
	if _, e := ParseSPNEGONegTokenInit(append(good, 0)); e == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, e := ParseSPNEGONegTokenInit(make([]byte, maxSPNEGOToken+1)); !errors.Is(e, ErrSPNEGOToken) {
		t.Fatalf("oversize: %v", e)
	}
}
func FuzzParseSPNEGOTokens(f *testing.F) {
	f.Add(initialSPNEGOTokenForTest(f))
	f.Add(responseSPNEGOTokenForTest(f, 1))
	f.Add([]byte{0xa1, 0})
	f.Add([]byte{0x60, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseSPNEGONegTokenInit(b); _, _ = ParseSPNEGONegTokenResp(b) })
}

func TestParseSPNEGORejectsDuplicateAndOutOfOrderFields(t *testing.T) {
	mech := wrapDERForTest(t, 0x30, marshalOIDForTest(t, ntlmOID))
	duplicate := append(wrapDERForTest(t, 0xa0, mech), wrapDERForTest(t, 0xa0, mech)...)
	init := wrapDERForTest(t, 0x60, append(marshalOIDForTest(t, spnegoOID), wrapDERForTest(t, 0xa0, wrapDERForTest(t, 0x30, duplicate))...))
	if _, err := ParseSPNEGONegTokenInit(init); !errors.Is(err, ErrSPNEGOToken) {
		t.Fatalf("duplicate field error = %v", err)
	}
	responseFields := append(wrapDERForTest(t, 0xa1, marshalOIDForTest(t, ntlmOID)), wrapDERForTest(t, 0xa0, wrapDERForTest(t, 0x0a, []byte{1}))...)
	response := wrapDERForTest(t, 0xa1, wrapDERForTest(t, 0x30, responseFields))
	if _, err := ParseSPNEGONegTokenResp(response); !errors.Is(err, ErrSPNEGOToken) {
		t.Fatalf("out-of-order field error = %v", err)
	}
}
