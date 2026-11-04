package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

var ErrCredSSPClient = errors.New("rdp: CredSSP client negotiation failed")

const defaultCredSSPTimeout = 10 * time.Second

// CredSSPClientConfig contains the credentials used for NTLMv2 and delegated
// TSPasswordCreds. Password is borrowed read-only and is never modified.
// EstablishCredSSP delegates it only after successful TLS public-key binding,
// sealed with the negotiated NTLMSSP confidentiality context.
type CredSSPClientConfig struct {
	Version  uint32
	Username string
	Domain   string
	Password []byte
	Timeout  time.Duration
}

// CredSSPClientSession represents a completed NLA exchange and owns the
// already verified TLS transport. The NTLM confidentiality keys are erased
// immediately after the one-shot authInfo message is sent.
type CredSSPClientSession struct {
	mu                    sync.Mutex
	transport             *Transport
	version               uint32
	credentialsDelegated  bool
	mcsConnected          bool
	mcsResponse           MCSConnectResponse
	channelsConnected     bool
	userChannelID         uint16
	clientInfoSent        bool
	licensingComplete     bool
	mcsSettings           MCSClientSettings
	capabilitiesExchanged bool
	serverCapabilities    RDPServerCapabilities
}

func (s *CredSSPClientSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transport != nil {
		_ = s.transport.Close()
		s.transport = nil
	}
}

// EstablishCredSSP performs the strict NTLM-only SPNEGO exchange over the
// already TLS-verified and certificate-pinned transport. It delegates password
// credentials only after verifying the server's v5/v6 pubKeyAuth response.
func (t *Transport) EstablishCredSSP(ctx context.Context, cfg CredSSPClientConfig) (session *CredSSPClientSession, err error) {
	if t == nil || t.Conn == nil || ctx == nil || ctx.Err() != nil || cfg.Version < 5 || cfg.Version > 6 ||
		cfg.Username == "" || len(cfg.Password) == 0 || cfg.Timeout < 0 {
		return nil, ErrCredSSPClient
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultCredSSPTimeout
	}
	deadline := time.Now().Add(cfg.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := t.Conn.SetDeadline(deadline); err != nil {
		return nil, ErrCredSSPClient
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = t.Conn.SetDeadline(time.Now()) })
	defer func() {
		if !stopCancel() && ctx.Err() != nil && err == nil {
			if session != nil {
				session.Close()
				session = nil
			}
			err = ErrCredSSPClient
		}
		if err != nil {
			_ = t.Close() // Any uncertain protocol state is terminal.
		} else {
			_ = t.Conn.SetDeadline(time.Time{})
		}
	}()

	binding, err := t.NewCredSSPPublicKeyBinding()
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(binding.ClientNonce[:])
	defer clear(binding.ClientToServerHash[:])
	defer clear(binding.ServerToClientHash[:])

	negotiate := MarshalNTLMSSPNegotiate()
	defer clear(negotiate)
	initialToken, err := MarshalSPNEGONTLMInit(negotiate)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(initialToken)
	initial, err := MarshalTSRequest(TSRequest{Version: cfg.Version, NegoTokens: [][]byte{initialToken}})
	if err != nil || writeFull(t.Conn, initial) != nil {
		clear(initial)
		return nil, ErrCredSSPClient
	}
	clear(initial)

	serverMessage, err := readTSRequest(t.Conn)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	serverRequest, err := ParseTSRequest(serverMessage)
	clear(serverMessage)
	defer clearTSRequest(&serverRequest)
	if err != nil || serverRequest.Version < 5 || serverRequest.ErrorCode != nil ||
		len(serverRequest.NegoTokens) != 1 || serverRequest.AuthInfo != nil ||
		serverRequest.PubKeyAuth != nil || serverRequest.ClientNonce != nil {
		return nil, ErrCredSSPClient
	}
	negotiatedVersion := cfg.Version
	if serverRequest.Version < negotiatedVersion {
		negotiatedVersion = serverRequest.Version
	}
	serverSPNEGO, err := ParseSPNEGONegTokenResp(serverRequest.NegoTokens[0])
	defer clear(serverSPNEGO.ResponseToken)
	defer clear(serverSPNEGO.MechanismListMIC)
	if err != nil || serverSPNEGO.State != 1 || !serverSPNEGO.SupportedMech.Equal(ntlmOID) ||
		len(serverSPNEGO.ResponseToken) == 0 || len(serverSPNEGO.MechanismListMIC) != 0 {
		return nil, ErrCredSSPClient
	}
	challenge, err := ParseNTLMSSPChallenge(serverSPNEGO.ResponseToken, ntlmSSPNegotiateFlags)
	defer clear(challenge.TargetName)
	defer clear(challenge.TargetInfo)
	if err != nil {
		return nil, ErrCredSSPClient
	}

	clientChallenge, err := GenerateNTLMv2ClientChallenge()
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(clientChallenge[:])
	timestamp := ntlmCurrentFiletime()
	channelBinding, err := NTLMv2ChannelBindings(t.Conn.ConnectionState())
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(channelBinding[:])
	targetName, err := NTLMv2TargetName(t.targetServerName)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(targetName)
	response, err := ComputeNTLMv2Response(cfg.Username, cfg.Domain, cfg.Password, challenge.ServerChallenge, clientChallenge, timestamp, challenge.TargetInfo)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer response.Purge()
	security, err := NewNTLMSSPClientSecurityContext(response, challenge)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer security.Close()
	ntlmAuthenticate, err := MarshalNTLMSSPAuthenticateWithBindings(negotiate, serverSPNEGO.ResponseToken, cfg.Username, cfg.Domain, response, NTLMv2ClientBindings{TargetName: targetName, ChannelBindings: channelBinding})
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(ntlmAuthenticate)
	finalToken, err := MarshalSPNEGONTLMResponse(ntlmAuthenticate)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(finalToken)
	bindingRequest, err := NewCredSSPClientBindingRequest(negotiatedVersion, finalToken, binding, security)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clearTSRequest(&bindingRequest)
	outbound, err := MarshalTSRequest(bindingRequest)
	if err != nil {
		security.Close()
		return nil, ErrCredSSPClient
	}
	if err := writeFull(t.Conn, outbound); err != nil {
		clear(outbound)
		security.Close()
		return nil, ErrCredSSPClient
	}
	clear(outbound)

	serverBindingResponse, err := readTSRequest(t.Conn)
	if err != nil {
		security.Close()
		return nil, ErrCredSSPClient
	}
	if err := VerifyCredSSPServerBindingResponse(serverBindingResponse, negotiatedVersion, binding, security); err != nil {
		clear(serverBindingResponse)
		return nil, ErrCredSSPClient
	}
	clear(serverBindingResponse)
	if ctx.Err() != nil {
		return nil, ErrCredSSPClient
	}

	credentials, err := marshalCredSSPPasswordCredentials(cfg.Domain, cfg.Username, cfg.Password)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(credentials)
	authInfo, err := security.WrapClientToServer(credentials)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(authInfo)
	authInfoRequest, err := MarshalTSRequest(TSRequest{Version: negotiatedVersion, AuthInfo: authInfo})
	if err != nil || !tsRequestContainsOnlyVersionAndAuthInfo(authInfoRequest) {
		clear(authInfoRequest)
		return nil, ErrCredSSPClient
	}
	if err := writeFull(t.Conn, authInfoRequest); err != nil {
		clear(authInfoRequest)
		return nil, ErrCredSSPClient
	}
	clear(authInfoRequest)
	if ctx.Err() != nil {
		return nil, ErrCredSSPClient
	}
	security.Close()
	return &CredSSPClientSession{transport: t, version: negotiatedVersion, credentialsDelegated: true}, nil
}

// ConnectMCS starts the Basic Settings Exchange after CredSSP has delegated
// credentials. It is a one-shot transition: any ambiguous wire state closes
// the transport, and a successful response leaves channel connection for the
// next protocol step.
func (s *CredSSPClientSession) ConnectMCS(ctx context.Context, cfg MCSClientSettings) (response MCSConnectResponse, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || cfg.Timeout < 0 {
		return response, ErrMCSConnection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The caller may have been canceled while waiting for the session lock.
	if ctx.Err() != nil {
		return response, ErrMCSConnection
	}
	if s.transport == nil || s.transport.Conn == nil || !s.credentialsDelegated || s.mcsConnected ||
		!s.transport.Conn.ConnectionState().HandshakeComplete {
		return response, ErrMCSConnection
	}
	packet, err := MarshalMCSConnectInitial(cfg)
	if err != nil {
		return response, err
	}
	defer clear(packet)

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultCredSSPTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn := s.transport.Conn
	if err := conn.SetDeadline(deadline); err != nil {
		s.closeTransportLocked()
		return response, ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	// Close rather than risk writing after cancellation or racing the deadline
	// callback; the TLS connection is no longer safe to reuse in that state.
	if ctx.Err() != nil {
		stopCancel()
		s.closeTransportLocked()
		return response, ErrMCSConnection
	}
	if err := writeFull(conn, packet); err != nil {
		stopCancel()
		s.closeTransportLocked()
		return response, ErrMCSConnection
	}
	serverPacket, readErr := readMCSConnectResponse(conn)
	if readErr != nil {
		stopCancel()
		s.closeTransportLocked()
		return response, ErrMCSConnection
	}
	response, err = ParseMCSConnectResponse(serverPacket)
	clear(serverPacket)
	cancelStopped := stopCancel()
	if err != nil || ctx.Err() != nil || !cancelStopped {
		s.closeTransportLocked()
		return MCSConnectResponse{}, ErrMCSConnection
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.closeTransportLocked()
		return MCSConnectResponse{}, ErrMCSConnection
	}
	if ctx.Err() != nil {
		s.closeTransportLocked()
		return MCSConnectResponse{}, ErrMCSConnection
	}
	s.mcsConnected = true
	s.mcsResponse = response
	s.mcsSettings = cfg
	return response, nil
}

func (s *CredSSPClientSession) closeTransportLocked() {
	if s.transport != nil {
		_ = s.transport.Close()
		s.transport = nil
	}
}

func ntlmCurrentFiletime() (value [8]byte) {
	const windowsEpochOffset = uint64(116444736000000000)
	filetime := uint64(time.Now().UTC().UnixNano()/100) + windowsEpochOffset
	binary.LittleEndian.PutUint64(value[:], filetime)
	return value
}

// readTSRequest reads exactly one bounded DER SEQUENCE from a stream. It reads
// the tag/length prefix first, then the declared body; it never buffers an
// unbounded TLS record or consumes bytes from a subsequent TSRequest.
func readTSRequest(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil || header[0] != 0x30 {
		return nil, ErrCredSSPMessage
	}
	length := int(header[1])
	prefix := []byte{header[0], header[1]}
	if header[1]&0x80 != 0 {
		count := int(header[1] & 0x7f)
		if count == 0 || count > 3 {
			return nil, ErrCredSSPMessage
		}
		extra := make([]byte, count)
		if _, err := io.ReadFull(r, extra); err != nil || extra[0] == 0 {
			return nil, ErrCredSSPMessage
		}
		prefix = append(prefix, extra...)
		length = 0
		for _, b := range extra {
			length = length<<8 | int(b)
		}
		if length < 128 || count > 1 && length < 256 || count > 2 && length < 65536 {
			return nil, ErrCredSSPMessage
		}
	}
	if length < 1 || length > maxCredSSPMessage-len(prefix) {
		return nil, ErrCredSSPMessage
	}
	message := make([]byte, len(prefix)+length)
	copy(message, prefix)
	if _, err := io.ReadFull(r, message[len(prefix):]); err != nil {
		clear(message)
		return nil, ErrCredSSPMessage
	}
	return message, nil
}

func clearTSRequest(request *TSRequest) {
	if request == nil {
		return
	}
	for _, token := range request.NegoTokens {
		clear(token)
	}
	clear(request.AuthInfo)
	clear(request.PubKeyAuth)
	clear(request.ClientNonce)
}
