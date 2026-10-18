package infrastructure

import "testing"

// The decision behind PostgresStore.Ready for the cases a single test server
// cannot produce: a hot standby (pg_is_in_recovery) and a read-only
// transaction. Fail closed on anything it does not recognise.
func TestWritableOrError(t *testing.T) {
	cases := []struct {
		name       string
		readOnly   string
		inRecovery bool
		wantReady  bool
	}{
		{"a primary accepting writes", "off", false, true},
		{"a hot standby", "on", true, false},
		{"a standby even if the setting said off", "off", true, false},
		{"a read-only transaction on a primary", "on", false, false},
		{"an unexpected value fails closed", "", false, false},
	}
	for _, c := range cases {
		if got := writableOrError(c.readOnly, c.inRecovery) == nil; got != c.wantReady {
			t.Errorf("%s: ready=%v, want %v", c.name, got, c.wantReady)
		}
	}
}
