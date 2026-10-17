package infrastructure

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const testKeyHex = "abababababababababababababababababababababababababababababababab" // 32 bytes

func TestNewLocalKEKFromHexKey_RejectsAnythingButAValidKey(t *testing.T) {
	cases := map[string]string{
		"empty — no silent random fallback": "",
		"not hex":                           strings.Repeat("zz", 32),
		"31 bytes":                          strings.Repeat("ab", 31),
		"33 bytes":                          strings.Repeat("ab", 33),
		"odd length":                        strings.Repeat("a", 63),
	}
	for name, key := range cases {
		if _, err := NewLocalKEKFromHexKey(key); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := NewLocalKEKFromHexKey(testKeyHex); err != nil {
		t.Fatalf("a valid 32-byte key must be accepted: %v", err)
	}
}

func TestLocalKEK_WrapUnwrapRoundTripsAndIsBoundToItsAAD(t *testing.T) {
	kek, _ := NewLocalKEKFromHexKey(testKeyHex)
	dek, _ := newDEK()
	aad := dekAAD(kek.KeyID(), "session-A")

	wrapped, err := kek.Wrap(dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("the wrapped key contains the data key in the clear")
	}
	got, err := kek.Unwrap(wrapped, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap: %v (equal=%v)", err, bytes.Equal(got, dek))
	}

	if _, err := kek.Unwrap(wrapped, dekAAD(kek.KeyID(), "session-B")); err == nil {
		t.Fatal("a wrapped key must not unwrap for a different session")
	}
	other, _ := NewLocalKEKFromHexKey(strings.Repeat("cd", 32))
	if _, err := other.Unwrap(wrapped, aad); err == nil {
		t.Fatal("a wrapped key must not unwrap under a different KEK")
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := kek.Unwrap(tampered, aad); err == nil {
		t.Fatal("a tampered wrapped key must not unwrap")
	}
	if _, err := kek.Unwrap(wrapped[:5], aad); err == nil {
		t.Fatal("a truncated wrapped key must not unwrap")
	}

	again, _ := kek.Wrap(dek, aad)
	if bytes.Equal(again, wrapped) {
		t.Fatal("wrapping twice must not give the same bytes (fresh nonce each time)")
	}
}

func TestSealCommand_RoundTripsAndIsBoundToSessionAndTimestamp(t *testing.T) {
	dek, _ := newDEK()
	ts := time.Date(2026, 10, 16, 8, 30, 15, 123456000, time.UTC) // microsecond precision

	sealed, err := sealCommand(dek, "session-A", ts, "cat /etc/passwd")
	if err != nil {
		t.Fatalf("sealCommand: %v", err)
	}
	if bytes.Contains(sealed, []byte("passwd")) {
		t.Fatal("the sealed command contains the plaintext")
	}
	got, err := openCommand(dek, "session-A", ts, sealed)
	if err != nil || got != "cat /etc/passwd" {
		t.Fatalf("openCommand: %q, %v", got, err)
	}

	// The same instant expressed in another zone is the same timestamp.
	paris := time.FixedZone("CEST", 2*3600)
	if got, err := openCommand(dek, "session-A", ts.In(paris), sealed); err != nil || got != "cat /etc/passwd" {
		t.Fatalf("the same instant in another zone must open: %q, %v", got, err)
	}

	if _, err := openCommand(dek, "session-B", ts, sealed); err == nil {
		t.Fatal("a command moved to another session must not open")
	}
	if _, err := openCommand(dek, "session-A", ts.Add(time.Microsecond), sealed); err == nil {
		t.Fatal("a command whose timestamp was edited must not open")
	}
	otherDEK, _ := newDEK()
	if _, err := openCommand(otherDEK, "session-A", ts, sealed); err == nil {
		t.Fatal("a command must not open under another data key")
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)/2] ^= 0x80
	if _, err := openCommand(dek, "session-A", ts, flipped); err == nil {
		t.Fatal("an altered ciphertext must not open")
	}

	again, _ := sealCommand(dek, "session-A", ts, "cat /etc/passwd")
	if bytes.Equal(again, sealed) {
		t.Fatal("sealing the same command twice must give different bytes (fresh nonce each time)")
	}
}

func TestSealCommand_EmptyAndMultibyteCommands(t *testing.T) {
	dek, _ := newDEK()
	ts := time.Now().UTC().Truncate(time.Microsecond)
	for _, cmd := range []string{"", "echo 'héllo ✓'", strings.Repeat("é", 4000)} {
		sealed, err := sealCommand(dek, "s", ts, cmd)
		if err != nil {
			t.Fatalf("seal %q: %v", cmd, err)
		}
		if got, err := openCommand(dek, "s", ts, sealed); err != nil || got != cmd {
			t.Fatalf("round trip of %q: got %q, %v", cmd, got, err)
		}
	}
}

func TestZero_ClearsTheKeyMaterial(t *testing.T) {
	dek, _ := newDEK()
	zero(dek)
	if !bytes.Equal(dek, make([]byte, 32)) {
		t.Fatal("zero must clear every byte")
	}
}

// A wrapped data key is bound to the session AND the KEK it was wrapped for.
// The row-level tests would still catch a swapped key (its entries would fail
// to open), but the binding is a property worth pinning on its own: it makes
// a swap fail at the earliest point, before any entry is touched.
func TestDEKAAD_IsBoundToSessionAndKEK(t *testing.T) {
	base := dekAAD("kek-1", "session-a")
	if bytes.Equal(base, dekAAD("kek-1", "session-b")) {
		t.Fatal("the wrapped-key AAD does not depend on the session")
	}
	if bytes.Equal(base, dekAAD("kek-2", "session-a")) {
		t.Fatal("the wrapped-key AAD does not depend on the KEK")
	}
	// No ambiguity from joining: ("a|b","c") must not equal ("a","b|c").
	if bytes.Equal(dekAAD("a|b", "c"), dekAAD("a", "b|c")) {
		t.Fatal("the AAD is ambiguous: shifting a '|' between the KEK id and the session id gives the same bytes")
	}
}
