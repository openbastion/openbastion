package rdp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/tlspin"
)

const (
	protocolHybrid = uint32(0x00000002)
	maxTPKTPacket  = 4096
	rdpNegReq      = byte(1)
	rdpNegResp     = byte(2)
	rdpNegFailure  = byte(3)
)

var (
	ErrInvalidTarget       = errors.New("rdp: invalid target configuration")
	ErrNegotiation         = errors.New("rdp: invalid X.224 or RDP negotiation packet")
	ErrUnsupportedProtocol = errors.New("rdp: server did not select NLA/CredSSP security")
	ErrTLSVerification     = errors.New("rdp: target TLS verification failed")
)

// TransportConfig contains only target identity and connection settings. It has
// no credential field: the caller cannot send a Vault secret until DialHybrid
// has completed both the HYBRID negotiation and verified TLS handshake.
type TransportConfig struct {
	Address        string
	TLSFingerprint string
	TLSRoots       *x509.CertPool
	TLSServerName  string
	DialTimeout    time.Duration
}

// Transport owns a TLS connection negotiated with PROTOCOL_HYBRID and a
// cancellation hook. CredSSP must be layered on top only after this returns.
type Transport struct {
	Conn       *tls.Conn
	stopCancel func() bool
	closeOnce  sync.Once
}

func (t *Transport) Close() error {
	if t == nil || t.Conn == nil {
		return nil
	}
	var err error
	t.closeOnce.Do(func() {
		if t.stopCancel != nil {
			t.stopCancel()
		}
		err = t.Conn.Close()
	})
	return err
}

// DialHybrid connects to one explicit host:port, requests only PROTOCOL_HYBRID,
// and verifies TLS chain, name, and leaf-certificate pin before returning. It
// deliberately stops before CredSSP so callers cannot accidentally downgrade.
func DialHybrid(ctx context.Context, cfg TransportConfig) (*Transport, error) {
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" || port == "" {
		return nil, ErrInvalidTarget
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 || cfg.TLSRoots == nil || cfg.TLSFingerprint == "" || cfg.DialTimeout < 0 {
		return nil, ErrInvalidTarget
	}
	serverName := cfg.TLSServerName
	if serverName == "" {
		serverName = host
	}
	tlsConfig, err := tlspin.ServerConfig(cfg.TLSFingerprint, cfg.TLSRoots, serverName)
	if err != nil {
		return nil, fmt.Errorf("%w: TLS pin configuration", ErrInvalidTarget)
	}
	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", cfg.Address)
	if err != nil {
		return nil, errors.New("rdp: target connection failed")
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	keep := false
	defer func() {
		if !keep {
			stopCancel()
			_ = conn.Close()
		}
	}()
	if deadline, ok := dialCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if err := writeFull(conn, connectionRequest()); err != nil {
		return nil, fmt.Errorf("rdp: X.224 connection request failed")
	}
	if err := readConnectionConfirm(conn); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLSVerification, err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	keep = true
	return &Transport{Conn: tlsConn, stopCancel: stopCancel}, nil
}

func connectionRequest() []byte {
	// TPKT + X.224 Connection Request + RDP_NEG_REQ. No username cookie or
	// credential is included; the only requested security protocol is HYBRID.
	packet := []byte{
		3, 0, 0, 19, // TPKT header and length
		14, 0xe0, 0, 0, 0, 0, 0, // X.224 CR
		rdpNegReq, 0, 8, 0, // RDP_NEG_REQ type, flags, length
		0, 0, 0, 0, // requested protocols, filled below
	}
	binary.LittleEndian.PutUint32(packet[15:19], protocolHybrid)
	return packet
}

func readConnectionConfirm(r io.Reader) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("rdp: reading X.224 connection confirm failed")
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || length < 19 || length > maxTPKTPacket {
		return ErrNegotiation
	}
	packet := make([]byte, length)
	copy(packet, header[:])
	if _, err := io.ReadFull(r, packet[4:]); err != nil {
		return fmt.Errorf("rdp: truncated X.224 connection confirm")
	}
	if packet[4] != byte(length-5) || packet[5] != 0xd0 || packet[6] != 0 || packet[7] != 0 || packet[10] != 0 {
		return ErrNegotiation
	}
	neg := packet[11:]
	if len(neg) != 8 {
		return ErrNegotiation
	}
	if binary.LittleEndian.Uint16(neg[2:4]) != 8 || neg[1] != 0 {
		return ErrNegotiation
	}
	if neg[0] == rdpNegFailure {
		return fmt.Errorf("%w: server returned negotiation failure code %d", ErrUnsupportedProtocol, binary.LittleEndian.Uint32(neg[4:8]))
	}
	if neg[0] != rdpNegResp {
		return ErrNegotiation
	}
	if binary.LittleEndian.Uint32(neg[4:8]) != protocolHybrid {
		return ErrUnsupportedProtocol
	}
	return nil
}

func writeFull(w io.Writer, packet []byte) error {
	for len(packet) > 0 {
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}
