package application

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B (SHA-1, secret "12345678901234567890"), the last six of its eight digits.
func TestTOTPAt_TheRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		if got := totpAt(secret, unix/30); got != want {
			t.Fatalf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestMatchTOTP_OneStepEitherSide_AfterTheLastOnly_SixDigitsOnly(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	cur := now.Unix() / 30
	for _, c := range []struct {
		step  int64
		last  int64
		match bool
	}{{cur, 0, true}, {cur - 1, 0, true}, {cur + 1, 0, true}, {cur - 2, 0, false}, {cur + 2, 0, false}, {cur, cur, false}, {cur, cur - 1, true}} {
		step, ok := matchTOTP(secret, totpAt(secret, c.step), now, c.last)
		if ok != c.match || (ok && step != c.step) {
			t.Fatalf("code of step %+d after last %+d: step %d ok %v, want %v", c.step-cur, c.last-cur, step-cur, ok, c.match)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456", " 50471", "050471\n"} {
		if _, ok := matchTOTP(secret, bad, now, 0); ok {
			t.Fatalf("%q matched", bad)
		}
	}
}
