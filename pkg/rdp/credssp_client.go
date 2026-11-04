package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var ErrCredSSPClient = errors.New("rdp: CredSSP client negotiation failed")

const defaultCredSSPTimeout = 10 * time.Second

// CredSSPClientConfig contains credentials for the NTLMv2 proof. Password is
// borrowed read-only and is never serialized or modified by this package.
// This increment establishes NLA and TLS public-key binding only; it does not
// construct or send the delegated TSCredentials/authInfo structure.
type CredSSPClientConfig struct {
	Version  uint32
	Username string
	Domain   string
	Password []byte
	Timeout  time.Duration
}

// CredSSPClientSession owns the negotiated NTLMSSP confidentiality context.
// The context is retained for the later authInfo increment and must be closed
// when the RDP connection is abandoned.
type CredSSPClientSession struct {
	security *NTLMSSPClientSecurityContext
	version  uint32
}

func (s *CredSSPClientSession) Close() {
	if s != nil && s.security != nil {
		s.security.Close()
		s.security = nil
	}
}

// EstablishCredSSP performs the strict NTLM-only SPNEGO exchange over the
// already TLS-verified and certificate-pinned transport. It sends no
// TSCredentials: success means only that NTLM negotiation and v5/v6
// pubKeyAuth channel binding completed.
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
	keepSecurity := false
	defer func() {
		if !keepSecurity {
			security.Close()
		}
	}()
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
	keepSecurity = true
	return &CredSSPClientSession{security: security, version: negotiatedVersion}, nil
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
