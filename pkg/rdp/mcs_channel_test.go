package rdp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestMarshalMCSChannelConnectionRequests(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"erect domain", marshalMCSErectDomainRequest(), []byte{3, 0, 0, 12, 2, 0xf0, 0x80, 0x04, 1, 0, 1, 0}},
		{"attach user", marshalMCSAttachUserRequest(), []byte{3, 0, 0, 8, 2, 0xf0, 0x80, 0x28}},
		{"join user channel", marshalMCSChannelJoinRequest(1007, 1007), []byte{3, 0, 0, 12, 2, 0xf0, 0x80, 0x38, 0, 6, 3, 0xef}},
		{"join io channel", marshalMCSChannelJoinRequest(1007, mcsGlobalChannelID), []byte{3, 0, 0, 12, 2, 0xf0, 0x80, 0x38, 0, 6, 3, 0xeb}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.got) != string(tc.want) {
				t.Fatalf("PDU = %x, want %x", tc.got, tc.want)
			}
		})
	}
}

func TestParseMCSAttachUserConfirm(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
		want uint16
		ok   bool
	}{
		{"success", []byte{3, 0, 0, 11, 2, 0xf0, 0x80, 0x2e, 0, 0, 6}, 1007, true},
		{"rejected", []byte{3, 0, 0, 11, 2, 0xf0, 0x80, 0x2e, 1, 0, 6}, 0, false},
		{"missing initiator", []byte{3, 0, 0, 9, 2, 0xf0, 0x80, 0x2e, 0}, 0, false},
		{"wrong choice", []byte{3, 0, 0, 11, 2, 0xf0, 0x80, 0x2c, 0, 0, 6}, 0, false},
		{"reserved global user id", []byte{3, 0, 0, 11, 2, 0xf0, 0x80, 0x2e, 0, 0, 2}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMCSAttachUserConfirm(tc.pdu)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("parse = %d, %v; want %d, success=%v", got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestParseMCSChannelJoinConfirm(t *testing.T) {
	valid := mcsTestChannelJoinConfirm(1007, 1007)
	cases := map[string][]byte{
		"valid":                   valid,
		"wrong choice":            append([]byte{3, 0, 0, 15, 2, 0xf0, 0x80, 0x3c}, valid[8:]...),
		"rejected":                mcsTestChannelJoinConfirmWithResult(1, 1007, 1007, 1007),
		"wrong initiator":         mcsTestChannelJoinConfirm(1008, 1007),
		"wrong requested channel": mcsTestChannelJoinConfirm(1007, 1003),
		"wrong joined channel":    mcsTestChannelJoinConfirmWithJoined(1007, 1007, 1008),
		"truncated":               valid[:len(valid)-1],
		"trailing bytes":          append(append([]byte(nil), valid...), 0),
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseMCSChannelJoinConfirm(packet, 1007, 1007)
			if name == "valid" {
				if err != nil || got != 1007 {
					t.Fatalf("parse = %d, %v", got, err)
				}
			} else if !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestCredSSPSessionConnectMCSChannelsOverTLS(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		initial, acceptErr := readTestTPKT(tlsConn)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = parseMCSClientConnectInitialForTest(initial); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestConnectResponse(protocolHybrid, 0, 0, 0)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		want := [][]byte{
			{3, 0, 0, 12, 2, 0xf0, 0x80, 0x04, 1, 0, 1, 0},
			{3, 0, 0, 8, 2, 0xf0, 0x80, 0x28},
			{3, 0, 0, 12, 2, 0xf0, 0x80, 0x38, 0, 6, 3, 0xef},
			{3, 0, 0, 12, 2, 0xf0, 0x80, 0x38, 0, 6, 3, 0xeb},
		}
		for i, expected := range want {
			got, readErr := readTestTPKT(tlsConn)
			if readErr != nil {
				serverResult <- readErr
				return
			}
			if string(got) != string(expected) {
				serverResult <- errors.New("unexpected MCS request sequence at step " + string(rune('0'+i)))
				return
			}
			if i == 1 {
				if readErr = writeFull(tlsConn, mcsTestAttachUserConfirm(1007)); readErr != nil {
					serverResult <- readErr
					return
				}
			}
			if i == 2 {
				if readErr = writeFull(tlsConn, mcsTestChannelJoinConfirm(1007, 1007)); readErr != nil {
					serverResult <- readErr
					return
				}
			}
			if i == 3 {
				if readErr = writeFull(tlsConn, mcsTestChannelJoinConfirm(1007, mcsGlobalChannelID)); readErr != nil {
					serverResult <- readErr
					return
				}
			}
		}
		serverResult <- nil
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{transport: &Transport{Conn: clientTLS}, credentialsDelegated: true}
	if _, err := session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second}); err != nil {
		t.Fatalf("ConnectMCS: %v", err)
	}
	channels, err := session.ConnectMCSChannels(context.Background(), time.Second)
	if err != nil {
		select {
		case serverErr := <-serverResult:
			t.Fatalf("ConnectMCSChannels: %v; fake server: %v", err, serverErr)
		default:
			t.Fatalf("ConnectMCSChannels: %v", err)
		}
	}
	if channels.UserChannelID != 1007 || channels.IOChannelID != mcsGlobalChannelID || !session.channelsConnected || session.userChannelID != 1007 {
		t.Fatalf("channels = %+v, connected=%v", channels, session.channelsConnected)
	}
	if _, err := session.ConnectMCSChannels(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("second channel connection error = %v", err)
	}
	session.Close()
	if err := <-serverResult; err != nil {
		t.Fatalf("fake MCS server: %v", err)
	}
}

func TestCredSSPSessionConnectMCSChannelsClosesOnBadJoinConfirm(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestConnectResponse(protocolHybrid, 0, 0, 0)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		for i := 0; i < 3; i++ {
			if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
				serverResult <- acceptErr
				return
			}
			if i == 1 {
				if acceptErr = writeFull(tlsConn, mcsTestAttachUserConfirm(1007)); acceptErr != nil {
					serverResult <- acceptErr
					return
				}
			}
			if i == 2 {
				if acceptErr = writeFull(tlsConn, mcsTestChannelJoinConfirm(1007, 1008)); acceptErr != nil {
					serverResult <- acceptErr
					return
				}
			}
		}
		_ = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		n, readErr := tlsConn.Read(one[:])
		if n != 0 || readErr == nil {
			serverResult <- errors.New("client kept transport open after bad channel confirmation")
			return
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			serverResult <- errors.New("client did not close after bad channel confirmation")
			return
		}
		serverResult <- nil
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{transport: &Transport{Conn: clientTLS}, credentialsDelegated: true}
	if _, err := session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	_, err = session.ConnectMCSChannels(context.Background(), time.Second)
	if !errors.Is(err, ErrMCSConnection) || session.transport != nil {
		t.Fatalf("error=%v transportClosed=%v", err, session.transport == nil)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func mcsTestAttachUserConfirm(userID uint16) []byte {
	packet := []byte{3, 0, 0, 11, 2, 0xf0, 0x80, 0x2e, 0, 0, 6}
	binary.BigEndian.PutUint16(packet[9:11], userID-1001)
	return packet
}

func mcsTestChannelJoinConfirm(initiator, channel uint16) []byte {
	return mcsTestChannelJoinConfirmWithJoined(initiator, channel, channel)
}

func mcsTestChannelJoinConfirmWithResult(result byte, initiator, requested, joined uint16) []byte {
	packet := mcsTestChannelJoinConfirmWithJoined(initiator, requested, joined)
	packet[8] = result
	return packet
}

func mcsTestChannelJoinConfirmWithJoined(initiator, requested, joined uint16) []byte {
	packet := []byte{3, 0, 0, 15, 2, 0xf0, 0x80, 0x3e, 0, 0, 6, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(packet[9:11], initiator-1001)
	binary.BigEndian.PutUint16(packet[11:13], requested)
	binary.BigEndian.PutUint16(packet[13:15], joined)
	return packet
}

func TestCredSSPSessionConnectMCSChannelsRequiresBasicSettings(t *testing.T) {
	session := &CredSSPClientSession{credentialsDelegated: true}
	if _, err := session.ConnectMCSChannels(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("ConnectMCSChannels error = %v, want ErrMCSConnection", err)
	}
	if session.channelsConnected || session.userChannelID != 0 {
		t.Fatalf("invalid channel state after rejected transition: %+v", session)
	}
}

func TestCredSSPSessionConnectMCSChannelsClosesOnRejectedAttach(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestConnectResponse(protocolHybrid, 0, 0, 0)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestAttachUserConfirmWithResult(14)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		_ = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		n, readErr := tlsConn.Read(one[:])
		if n != 0 || readErr == nil {
			serverResult <- errors.New("client sent a channel join after attach rejection")
			return
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			serverResult <- errors.New("client did not close after attach rejection")
			return
		}
		serverResult <- nil
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{transport: &Transport{Conn: clientTLS}, credentialsDelegated: true}
	if _, err := session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	_, err = session.ConnectMCSChannels(context.Background(), time.Second)
	if !errors.Is(err, ErrMCSConnection) || session.transport != nil || session.channelsConnected {
		t.Fatalf("error=%v transportClosed=%v channelsConnected=%v", err, session.transport == nil, session.channelsConnected)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func mcsTestAttachUserConfirmWithResult(result byte) []byte {
	return []byte{3, 0, 0, 9, 2, 0xf0, 0x80, 0x2e, result}
}

func FuzzParseMCSAttachUserConfirm(f *testing.F) {
	f.Add(mcsTestAttachUserConfirm(1007))
	f.Add([]byte("not an MCS attach confirm"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) <= maxTPKTPacket {
			_, _ = parseMCSAttachUserConfirm(packet)
		}
	})
}

func FuzzParseMCSChannelJoinConfirm(f *testing.F) {
	f.Add(mcsTestChannelJoinConfirm(1007, 1007), uint16(1007), uint16(1007))
	f.Add([]byte("not an MCS join confirm"), uint16(1007), uint16(1003))
	f.Fuzz(func(t *testing.T, packet []byte, userID, channelID uint16) {
		if len(packet) <= maxTPKTPacket {
			_, _ = parseMCSChannelJoinConfirm(packet, userID, channelID)
		}
	})
}

func TestCredSSPSessionConnectMCSChannelsClosesOnContextCancellation(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	attachReceived := make(chan struct{})
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestConnectResponse(protocolHybrid, 0, 0, 0)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		close(attachReceived)
		_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		n, readErr := tlsConn.Read(one[:])
		if n != 0 || readErr == nil {
			serverResult <- errors.New("client sent a channel join after context cancellation")
			return
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			serverResult <- errors.New("client did not close after context cancellation")
			return
		}
		serverResult <- nil
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{transport: &Transport{Conn: clientTLS}, credentialsDelegated: true}
	if _, err := session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, connectErr := session.ConnectMCSChannels(ctx, 2*time.Second); result <- connectErr }()
	select {
	case <-attachReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not send Attach User Request")
	}
	cancel()
	select {
	case connectErr := <-result:
		if !errors.Is(connectErr, ErrMCSConnection) || session.transport != nil {
			t.Fatalf("error=%v transportClosed=%v", connectErr, session.transport == nil)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ConnectMCSChannels did not stop after cancellation")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
