package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var ErrCredSSPClient = errors.New("rdp: CredSSP client negotiation failed")

// credsspFailure is ErrCredSSPClient saying where it failed (ADR-0071, the Windows validation): a
// step, and the server's NTSTATUS when its TSRequest carries one — never a value of the exchange.
func credsspFailure(step string, serverCode *uint32) error {
	if serverCode != nil {
		return fmt.Errorf("%w (%s: the server answers NTSTATUS 0x%08X)", ErrCredSSPClient, step, *serverCode)
	}
	return fmt.Errorf("%w (%s)", ErrCredSSPClient, step)
}

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

	// sealAuthInfo replaces the sealing of authInfo. Unexported: only this package's tests set it,
	// to see how Windows answers an authInfo it must refuse or one naming another domain (ADR-0071
	// isolation). Every other caller seals the credentials it was given with the context it proved.
	sealAuthInfo func(security *NTLMSSPClientSecurityContext, challenge NTLMSSPChallenge, credentials []byte) ([]byte, error)
	// directNTLM sends the NTLM messages themselves as negoTokens, without SPNEGO, as FreeRDP does:
	// no mechListMIC, pubKeyAuth at sequence 0. Unexported, for the same isolation: CI run #21 has
	// FreeRDP open a full session on the Windows target that closes after this client's
	// Connect-Initial, and this is what differs most between the two.
	directNTLM bool
}

// CredSSPClientSession represents a completed NLA exchange and owns the
// already verified TLS transport. The NTLM confidentiality keys are erased
// immediately after the one-shot authInfo message is sent.
type CredSSPClientSession struct {
	mu      sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex
	// serverBytes counts what ReadBitmapUpdate reads from the target (ServerBytes, ADR-0090 lot A).
	serverBytes             atomic.Uint64
	transport               *Transport
	version                 uint32
	credentialsDelegated    bool
	mcsConnected            bool
	mcsResponse             MCSConnectResponse
	channelsConnected       bool
	userChannelID           uint16
	clientInfoSent          bool
	licensingAttempted      bool
	licensingUsername       string
	licensingComplete       bool
	mcsSettings             MCSClientSettings
	capabilitiesExchanged   bool
	connectionFinalized     bool
	serverCapabilities      RDPServerCapabilities
	primaryOrdersEnabled    bool
	patBltOpaqueRectEnabled bool
	dstBltEnabled           bool
	scrBltEnabled           bool
	multiDstBltEnabled      bool
	multiPatBltEnabled      bool
	multiScrBltEnabled      bool
	lineToEnabled           bool
	polylineEnabled         bool
	polygonSCEnabled        bool
	ellipseSCEnabled        bool
	multiOpaqueRectEnabled  bool
	primaryOrderState       rdpPrimaryOrderState
	logonNotified           bool
	reactivations           int
}

// BitsPerPixel is the colour depth of the session, as the server chose it in its Demand Active
// (15, 16 or 32, ADR-0086), or 0 before the capability exchange.
func (s *CredSSPClientSession) BitsPerPixel() uint16 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.capabilitiesExchanged {
		return 0
	}
	return s.serverCapabilities.PreferredBitsPerPixel
}

// LogonNotified reports whether the server has said the user's session opened (a Save Session
// Info logon notification, MS-RDPBCGR 2.2.10.1.1). A Windows target that does not open the
// session with the delegated credentials shows its logon screen instead, and never says so
// (ADR-0071, CI runs #39 to #42): the screen alone cannot tell the two apart.
func (s *CredSSPClientSession) LogonNotified() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logonNotified
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
	if cfg.directNTLM {
		initialToken = append([]byte(nil), negotiate...)
		defer clear(initialToken)
	}
	initial, err := MarshalTSRequest(TSRequest{Version: cfg.Version, NegoTokens: [][]byte{initialToken}})
	if err != nil || writeFull(t.Conn, initial) != nil {
		clear(initial)
		return nil, ErrCredSSPClient
	}
	clear(initial)

	serverMessage, err := readTSRequest(t.Conn)
	if err != nil {
		return nil, credsspFailure("reading the server's CHALLENGE", nil)
	}
	serverRequest, err := ParseTSRequest(serverMessage)
	clear(serverMessage)
	defer clearTSRequest(&serverRequest)
	if err != nil || serverRequest.Version < 5 || serverRequest.ErrorCode != nil ||
		len(serverRequest.NegoTokens) != 1 || serverRequest.AuthInfo != nil ||
		serverRequest.PubKeyAuth != nil || serverRequest.ClientNonce != nil {
		return nil, credsspFailure(fmt.Sprintf("the server's CHALLENGE TSRequest: version %d, %d token(s), parse error %v", serverRequest.Version, len(serverRequest.NegoTokens), err != nil), serverRequest.ErrorCode)
	}
	negotiatedVersion := cfg.Version
	if serverRequest.Version < negotiatedVersion {
		negotiatedVersion = serverRequest.Version
	}
	var challengeToken []byte
	micRequested := false
	if cfg.directNTLM {
		challengeToken = serverRequest.NegoTokens[0]
	} else {
		serverSPNEGO, err := ParseSPNEGONegTokenResp(serverRequest.NegoTokens[0])
		defer clear(serverSPNEGO.ResponseToken)
		defer clear(serverSPNEGO.MechanismListMIC)
		micRequested = err == nil && serverSPNEGO.State == spnegoStateRequestMIC
		if err != nil || (serverSPNEGO.State != spnegoStateAcceptIncomplete && !micRequested) || !serverSPNEGO.SupportedMech.Equal(ntlmOID) ||
			len(serverSPNEGO.ResponseToken) == 0 || len(serverSPNEGO.MechanismListMIC) != 0 {
			return nil, credsspFailure(fmt.Sprintf("the server's SPNEGO negTokenResp: state %d, NTLM %v, token %d bytes, mechListMIC %d bytes, parse error %v",
				serverSPNEGO.State, serverSPNEGO.SupportedMech.Equal(ntlmOID), len(serverSPNEGO.ResponseToken), len(serverSPNEGO.MechanismListMIC), err != nil), nil)
		}
		challengeToken = serverSPNEGO.ResponseToken
	}
	challenge, err := ParseNTLMSSPChallenge(challengeToken, ntlmSSPNegotiateFlags)
	defer clear(challenge.TargetName)
	defer clear(challenge.TargetInfo)
	if err != nil {
		return nil, credsspFailure(fmt.Sprintf("the NTLM CHALLENGE: %v", err), nil)
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
	unbound, err := ComputeNTLMv2Response(cfg.Username, cfg.Domain, cfg.Password, challenge.ServerChallenge, clientChallenge, timestamp, challenge.TargetInfo)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer unbound.Purge()
	bindings := NTLMv2ClientBindings{TargetName: targetName, ChannelBindings: channelBinding}
	response, err := BindNTLMv2Response(unbound, challenge.TargetInfo, &bindings)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer response.Purge()
	security, err := NewNTLMSSPClientSecurityContext(response, challenge)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer security.Close()
	ntlmAuthenticate, err := MarshalNTLMSSPAuthenticateWithBindings(negotiate, challengeToken, cfg.Username, cfg.Domain, response, bindings)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clear(ntlmAuthenticate)
	mechTypes, err := spnegoNTLMMechTypes()
	if err != nil {
		return nil, ErrCredSSPClient
	}
	// The MIC goes with AUTHENTICATE whether or not the server asked for it: an NTLM AUTHENTICATE
	// with a MIC needs SPNEGO's mechListMIC (MS-SPNG), and Windows Server closes the connection
	// without it (ADR-0071, measured in CI). Asked (FreeRDP), it keeps the measured exchange of its
	// own; unasked (Windows), it is a signature of this context, and pubKeyAuth follows it.
	var finalToken []byte
	if cfg.directNTLM {
		// No SPNEGO, so no mechListMIC, and nothing in the server's answer but pubKeyAuth.
		finalToken = append([]byte(nil), ntlmAuthenticate...)
		mechTypes = nil
	} else {
		var mechListMIC []byte
		if micRequested {
			mechListMIC, err = security.SignMechListMIC(mechTypes)
		} else {
			mechListMIC, err = security.SignMechListMICInStream(mechTypes)
		}
		if err != nil {
			return nil, credsspFailure("signing the mechListMIC", nil)
		}
		finalToken, err = MarshalSPNEGONTLMResponse(ntlmAuthenticate, mechListMIC)
		if err != nil {
			return nil, ErrCredSSPClient
		}
	}
	defer clear(finalToken)
	// A server that asked for the MIC finishes SPNEGO first, and reads pubKeyAuth in the next
	// message: nothing about the channel is said before the negotiation is proved.
	pendingToken := finalToken
	if micRequested {
		if err := completeSPNEGOMICExchange(t.Conn, negotiatedVersion, finalToken, security, mechTypes); err != nil {
			security.Close()
			return nil, err
		}
		pendingToken = nil
	}
	bindingRequest, err := NewCredSSPClientBindingRequest(negotiatedVersion, pendingToken, binding, security)
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
		return nil, credsspFailure(fmt.Sprintf("reading the server's answer to AUTHENTICATE (MIC requested %v): %v", micRequested, err), nil)
	}
	if err := verifyCredSSPServerCompletion(serverBindingResponse, negotiatedVersion, binding, security, mechTypes); err != nil {
		var code *uint32
		if answer, perr := ParseTSRequest(serverBindingResponse); perr == nil {
			code = answer.ErrorCode
		}
		clear(serverBindingResponse)
		return nil, credsspFailure(fmt.Sprintf("the server's pubKeyAuth (MIC requested %v): %v", micRequested, err), code)
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
	seal := func(security *NTLMSSPClientSecurityContext, _ NTLMSSPChallenge, credentials []byte) ([]byte, error) {
		return security.WrapClientToServer(credentials)
	}
	if cfg.sealAuthInfo != nil {
		seal = cfg.sealAuthInfo
	}
	authInfo, err := seal(security, challenge, credentials)
	if err != nil || len(authInfo) == 0 {
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
		return response, fmt.Errorf("%w: reading MCS Connect-Response TPKT: %v", ErrMCSConnection, readErr)
	}
	response, err = ParseMCSConnectResponse(serverPacket)
	clear(serverPacket)
	cancelStopped := stopCancel()
	if err != nil || ctx.Err() != nil || !cancelStopped {
		s.closeTransportLocked()
		if err != nil {
			return MCSConnectResponse{}, err
		}
		if ctx.Err() != nil {
			return MCSConnectResponse{}, fmt.Errorf("%w: context cancelled during MCS Connect-Response", ErrMCSConnection)
		}
		return MCSConnectResponse{}, fmt.Errorf("%w: MCS response deadline callback raced completion", ErrMCSConnection)
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

// completeSPNEGOMICExchange sends AUTHENTICATE with this client's MIC and checks the server's. The
// server's answer carries nothing else: a pubKeyAuth here is not a proof of anything, this client
// having sent none it could be the answer to.
func completeSPNEGOMICExchange(conn io.ReadWriter, version uint32, token []byte, security *NTLMSSPClientSecurityContext, mechTypes []byte) error {
	request, err := MarshalTSRequest(TSRequest{Version: version, NegoTokens: [][]byte{token}})
	if err != nil {
		return ErrCredSSPClient
	}
	defer clear(request)
	if err := writeFull(conn, request); err != nil {
		return ErrCredSSPClient
	}
	encoded, err := readTSRequest(conn)
	if err != nil {
		return credsspFailure("reading the server's answer to AUTHENTICATE with the MIC", nil)
	}
	defer clear(encoded)
	answer, err := ParseTSRequest(encoded)
	defer clearTSRequest(&answer)
	if err != nil || answer.Version != version || answer.ErrorCode != nil || answer.AuthInfo != nil ||
		answer.PubKeyAuth != nil || answer.ClientNonce != nil {
		return credsspFailure(fmt.Sprintf("the server's answer to the MIC: version %d (sent %d), pubKeyAuth %d bytes, parse error %v",
			answer.Version, version, len(answer.PubKeyAuth), err != nil), answer.ErrorCode)
	}
	if err := verifySPNEGOCompletion(answer.NegoTokens, security, mechTypes, true); err != nil {
		return credsspFailure(fmt.Sprintf("the server's SPNEGO completion of the MIC: %v", err), nil)
	}
	return security.mechListMICExchanged()
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
