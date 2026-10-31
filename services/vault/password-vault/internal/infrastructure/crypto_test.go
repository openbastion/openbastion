package infrastructure_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

func TestLocalKMS_SealThenOpen_RoundTrips(t *testing.T) {
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	sealed, err := kms.Seal([]byte("super-secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := kms.Open(kms.KeyID(), sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened) != "super-secret" {
		t.Fatalf("got %q, want %q", opened, "super-secret")
	}
}

func TestNewLocalKMS_GeneratesADifferentKeyEachTime(t *testing.T) {
	// The exact property that made the original, key-less NewLocalKMS
	// unsafe to use across a process restart: two instances cannot read
	// each other's sealed material.
	kms1, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("NewLocalKMS (1): %v", err)
	}
	kms2, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("NewLocalKMS (2): %v", err)
	}
	sealed, err := kms1.Seal([]byte("secret-from-process-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := kms2.Open(kms2.KeyID(), sealed); err == nil {
		t.Fatal("expected a second, independently generated LocalKMS to be unable to open the first's sealed material")
	}
}

func TestNewLocalKMSFromHexKey_SameKeyAcrossInstancesCanDecryptEachOthers(t *testing.T) {
	// The fix: two LocalKMS instances built from the SAME hex key —
	// exactly what two password-vault processes do when both are given
	// the same KMS_KEY_HEX — can read each other's sealed material. This
	// is the property a restarted process actually depends on when
	// DATABASE_URL points it at data a previous process sealed.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	hexKey := hex.EncodeToString(raw[:])

	kms1, err := infrastructure.NewLocalKMSFromHexKey(hexKey)
	if err != nil {
		t.Fatalf("NewLocalKMSFromHexKey (1): %v", err)
	}
	kms2, err := infrastructure.NewLocalKMSFromHexKey(hexKey)
	if err != nil {
		t.Fatalf("NewLocalKMSFromHexKey (2): %v", err)
	}

	sealed, err := kms1.Seal([]byte("secret-sealed-by-process-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := kms2.Open(kms2.KeyID(), sealed)
	if err != nil {
		t.Fatalf("expected the second instance, built from the same hex key, to open the first's sealed material: %v", err)
	}
	if string(opened) != "secret-sealed-by-process-1" {
		t.Fatalf("got %q, want %q", opened, "secret-sealed-by-process-1")
	}
}

func TestNewLocalKMSFromHexKey_EmptyKeyFallsBackToRandomPerInstance(t *testing.T) {
	kms1, err := infrastructure.NewLocalKMSFromHexKey("")
	if err != nil {
		t.Fatalf("NewLocalKMSFromHexKey(\"\") (1): %v", err)
	}
	kms2, err := infrastructure.NewLocalKMSFromHexKey("")
	if err != nil {
		t.Fatalf("NewLocalKMSFromHexKey(\"\") (2): %v", err)
	}
	sealed, err := kms1.Seal([]byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := kms2.Open(kms2.KeyID(), sealed); err == nil {
		t.Fatal("expected two empty-key instances to each get their own random key, unable to open one another's material")
	}
}

func TestNewLocalKMSFromHexKey_RejectsInvalidHex(t *testing.T) {
	if _, err := infrastructure.NewLocalKMSFromHexKey("not-hex-at-all-zz"); err == nil {
		t.Fatal("expected an error for a non-hex KMS_KEY_HEX value")
	}
}

func TestNewLocalKMSFromHexKey_RejectsWrongLength(t *testing.T) {
	// 16 bytes (AES-128 length) is valid hex but the wrong size for this
	// AES-256 implementation — must be rejected explicitly, not silently
	// truncated or zero-padded.
	shortKey := hex.EncodeToString(make([]byte, 16))
	if _, err := infrastructure.NewLocalKMSFromHexKey(shortKey); err == nil {
		t.Fatal("expected an error for a key that isn't exactly 32 bytes")
	}
}
