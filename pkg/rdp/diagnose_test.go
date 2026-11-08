package rdp

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// What ReadBitmapUpdate refuses at the MCS layer is said (ADR-0071): a reconnection to Windows ended
// with a bare refusal, which left nothing to go on.
func TestReadBitmapUpdateDescribesWhatItRefusesAtTheMCSLayer(t *testing.T) {
	ultimatum := []byte{3, 0, 0, 9, 2, 0xf0, 0x80, 0x21, 0x80} // Disconnect Provider Ultimatum
	otherChannel := mcsTestServerShare(testDeactivateAll(reactivationOldShare))
	otherChannel[11] = 0xef // channel 1007, the user's, not the I/O channel
	for name, c := range map[string]struct {
		packet []byte
		want   string
	}{
		"a Disconnect Provider Ultimatum": {ultimatum, "MCS PDU 0x21"},
		"a PDU on another channel":        {otherChannel, "channel 1007"},
	} {
		t.Run(name, func(t *testing.T) {
			session, _ := reactivationSession(t, func(conn net.Conn) error {
				if err := writeFull(conn, c.packet); err != nil {
					return err
				}
				_, _ = conn.Read(make([]byte, 64))
				return nil
			})
			_, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
			if !errors.Is(err, ErrMCSConnection) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want it to say %q", err, c.want)
			}
		})
	}
}
