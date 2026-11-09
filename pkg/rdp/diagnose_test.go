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

// The MCS data priority says nothing this client depends on: Windows Server 2022 sent a Share Data
// PDU at top priority (0x30, CI of PR #94), which the reader refused, ending the session. Any
// priority is read; the reserved bits stay zero.
func TestReadBitmapUpdateReadsAnyMCSDataPriority(t *testing.T) {
	bitmap := mcsTestBitmapUpdatePacket(reactivationOldShare, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))
	errorInfo := mcsTestFinalizationResponse(reactivationOldShare, 0x2f, 0, []byte{0, 0, 0, 0}) // Set Error Info, ignored
	for _, priority := range []byte{0x00, 0x40, 0x80, 0xc0} {
		top := append([]byte(nil), errorInfo...)
		top[12] = priority | 0x30
		session, _ := reactivationSession(t, func(conn net.Conn) error {
			if err := writeFull(conn, append(top, bitmap...)); err != nil {
				return err
			}
			_, _ = conn.Read(make([]byte, 64))
			return nil
		})
		update, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
		if err != nil || len(update.Rectangles) != 1 {
			t.Fatalf("priority 0x%02x: %v", priority, err)
		}
	}
	reserved := append([]byte(nil), errorInfo...)
	reserved[12] = 0x71
	session, _ := reactivationSession(t, func(conn net.Conn) error {
		_ = writeFull(conn, append(reserved, bitmap...))
		_, _ = conn.Read(make([]byte, 64))
		return nil
	})
	if _, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("reserved bits set: %v", err)
	}
}
