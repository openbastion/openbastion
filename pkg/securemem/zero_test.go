package securemem

import "testing"

func TestZeroOverwritesBackingArray(t *testing.T) {
	backing := []byte("secret-material")
	view := backing[1:]
	Zero(view)
	for i, b := range backing[1:] {
		if b != 0 {
			t.Fatalf("byte %d was not cleared: %x", i+1, b)
		}
	}
	if string(backing[:1]) != "s" {
		t.Fatalf("Zero modified bytes outside the supplied slice: %q", backing)
	}
}
