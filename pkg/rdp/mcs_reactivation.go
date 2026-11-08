package rdp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"time"
)

// The deactivation-reactivation sequence (MS-RDPBCGR 1.3.1.3): a server that changes what it shows
// (the desktop's size or depth, the session behind the connection) sends a Deactivate All, then a
// new Demand Active. The client answers as at the first activation: a Confirm Active, then the
// finalization, under the new share. Until it is over, the client sends no input.
//
// FreeRDP's shadow server does it as soon as a client asks for another size than its screen's
// (ADR-0071, increment 71): the session then carries on at the server's size.

const (
	rdpDeactivateAllPDU = uint16(0x16) // PDUTYPE_DEACTIVATEALLPDU | TS_PROTOCOL_VERSION
	// maxRDPReactivations bounds what a server can make a session do over and over: a server that
	// reactivates without end gets the session closed, not a loop.
	maxRDPReactivations = 16
	// rdpReactivationTimeout bounds the whole sequence, from the Deactivate All to the Font Map.
	rdpReactivationTimeout = 30 * time.Second
)

// rdpIsDeactivateAll says whether a Share Control PDU is a Deactivate All, without validating it.
func rdpIsDeactivateAll(data []byte) bool {
	return len(data) >= 6 && binary.LittleEndian.Uint16(data[2:4]) == rdpDeactivateAllPDU
}

// parseRDPDeactivateAll validates a TS_DEACTIVATE_ALL_PDU (MS-RDPBCGR 2.2.3.1) of the share in force:
// its length, its share, a printable source descriptor.
func parseRDPDeactivateAll(data []byte, shareID uint32) error {
	if len(data) < 12 || len(data) > 12+64 || int(binary.LittleEndian.Uint16(data[0:2])) != len(data) ||
		binary.LittleEndian.Uint16(data[2:4]) != rdpDeactivateAllPDU ||
		binary.LittleEndian.Uint32(data[6:10]) != shareID ||
		12+int(binary.LittleEndian.Uint16(data[10:12])) != len(data) {
		return ErrMCSConnection
	}
	for _, b := range data[12:] {
		if b != 0 && (b < 0x20 || b > 0x7e) {
			return ErrMCSConnection
		}
	}
	return nil
}

// reactivate runs the sequence after a Deactivate All read by ReadBitmapUpdate, which holds readMu.
// It holds writeMu, so that no input goes out under a share being replaced; on success the session
// carries the new share, size and depth, and its primary-order state starts again. Any error is
// terminal: the caller closes the transport.
func (s *CredSSPClientSession) reactivate(ctx context.Context, conn *tls.Conn, deactivate []byte, readDeadline time.Time) error {
	s.mu.Lock()
	shareID, count := s.serverCapabilities.ShareID, s.reactivations
	ioChannelID, userID, settings := s.mcsResponse.IOChannelID, s.userChannelID, s.mcsSettings
	s.mu.Unlock()
	if err := parseRDPDeactivateAll(deactivate, shareID); err != nil {
		return fmt.Errorf("%w: Deactivate All refused: %s", ErrMCSConnection, describeRDPShareControl(deactivate))
	}
	if count >= maxRDPReactivations {
		return fmt.Errorf("%w: reactivation refused: %d already in this session", ErrMCSConnection, count)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	s.capabilitiesExchanged, s.connectionFinalized = false, false
	s.mu.Unlock()

	deadline := time.Now().Add(rdpReactivationTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if conn.SetDeadline(deadline) != nil || ctx.Err() != nil {
		return ErrMCSConnection
	}
	packet, err := readMCSConnectResponse(conn)
	if err != nil {
		return fmt.Errorf("%w: reactivation: no Demand Active", ErrMCSConnection)
	}
	capabilities, err := parseRDPDemandActive(packet, ioChannelID)
	if err != nil {
		described := fmt.Errorf("%w: reactivation: Demand Active refused: %s", ErrMCSConnection, describeRDPServerPacket(packet))
		clear(packet)
		return described
	}
	clear(packet)
	// The Confirm Active states the size the server now shows, as FreeRDP's client does.
	settings.DesktopWidth, settings.DesktopHeight = capabilities.DesktopWidth, capabilities.DesktopHeight
	confirm, err := marshalRDPConfirmActive(capabilities, settings, userID)
	if err != nil {
		return ErrMCSConnection
	}
	writeErr := writeFull(conn, confirm)
	clear(confirm)
	if writeErr != nil || ctx.Err() != nil {
		return ErrMCSConnection
	}
	if _, err := finalizeRDPConnection(ctx, conn, ioChannelID, capabilities.ShareID, userID); err != nil {
		return fmt.Errorf("%w: reactivation: finalization refused", ErrMCSConnection)
	}
	// Back to the deadlines of the read in progress: none for writes, the caller's for reads.
	if conn.SetWriteDeadline(time.Time{}) != nil || conn.SetReadDeadline(readDeadline) != nil || ctx.Err() != nil {
		return ErrMCSConnection
	}

	s.mu.Lock()
	s.serverCapabilities = cloneRDPServerCapabilities(capabilities)
	s.primaryOrderState = rdpPrimaryOrderState{}
	s.capabilitiesExchanged, s.connectionFinalized = true, true
	s.reactivations++
	s.mu.Unlock()
	return nil
}

// describeRDPShareControl names a Share Control PDU without its content: type and length.
func describeRDPShareControl(data []byte) string {
	if len(data) < 6 {
		return fmt.Sprintf("%d bytes", len(data))
	}
	return fmt.Sprintf("share PDU type %d, %d bytes (totalLength %d)", binary.LittleEndian.Uint16(data[2:4])&0x0f, len(data), binary.LittleEndian.Uint16(data[0:2]))
}
