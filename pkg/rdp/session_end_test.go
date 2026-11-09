package rdp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// How a target ends a session (ADR-0071 §3, "Fin"): a Disconnect Provider Ultimatum is the session's
// end, said as such. A connection that only closes is not: crypto/tls gives io.EOF for close_notify
// and for a dead target alike, and a dead target stays a failure; so does a packet cut short.
func TestReadBitmapUpdateTellsAnEndFromAFailure(t *testing.T) {
	ultimatum := []byte{3, 0, 0, 9, 2, 0xf0, 0x80, 0x21, 0x80} // reason rn-user-requested
	truncated := mcsTestBitmapUpdatePacket(reactivationOldShare, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))
	for name, c := range map[string]struct {
		stream []byte
		ended  bool
	}{
		"a Disconnect Provider Ultimatum":      {ultimatum, true},
		"TLS closed between two packets":       {nil, false},
		"TLS closed in the middle of a packet": {truncated[:len(truncated)-3], false},
		"an ultimatum on a TPKT that lies":     {append([]byte{3, 0, 0, 10}, ultimatum[4:]...), false},
	} {
		t.Run(name, func(t *testing.T) {
			session, _ := reactivationSession(t, func(conn net.Conn) error {
				return writeFull(conn, c.stream) // then the server closes, with close_notify
			})
			_, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
			if ended := errors.Is(err, ErrSessionEnded); ended != c.ended || err == nil {
				t.Fatalf("%v: ended %v, want %v", err, ended, c.ended)
			}
			if !c.ended && !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("%v, want ErrMCSConnection", err)
			}
		})
	}
}
