package rdp

import (
	"context"
	"fmt"
)

// establishCredSSPKerberos is CredSSP with Kerberos (ADR-0100, increment 2; MS-CSSP 3.1.5): the
// AP-REQ in a NegTokenInit offering Kerberos 5 alone; the target's AP-REP, and its mechListMIC when
// it sends one; then, under the Kerberos context, pubKeyAuth, the target's pubKeyAuth, and authInfo.
// Nothing of NTLM is sent: a target that answers with another mechanism, an error or no AP-REP is
// refused, and so is the session.
func (t *Transport) establishCredSSPKerberos(ctx context.Context, cfg CredSSPClientConfig, binding CredSSPPublicKeyBinding) (*CredSSPClientSession, error) {
	kctx, apReq, err := kerberosInitiate(*cfg.Kerberos, cfg.Username, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredSSPClient, err)
	}
	security := kerberosSecurity{ctx: kctx}
	defer security.Close()
	initialToken, err := marshalSPNEGOKerberosInit(apReq)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	initial, err := MarshalTSRequest(TSRequest{Version: cfg.Version, NegoTokens: [][]byte{initialToken}})
	if err != nil || writeFull(t.Conn, initial) != nil {
		return nil, ErrCredSSPClient
	}

	serverMessage, err := readTSRequest(t.Conn)
	if err != nil {
		return nil, credsspFailure("reading the server's AP-REP", nil)
	}
	serverRequest, err := ParseTSRequest(serverMessage)
	clear(serverMessage)
	defer clearTSRequest(&serverRequest)
	if err != nil || serverRequest.Version < 5 || serverRequest.ErrorCode != nil || len(serverRequest.NegoTokens) != 1 ||
		serverRequest.AuthInfo != nil || serverRequest.PubKeyAuth != nil || serverRequest.ClientNonce != nil {
		return nil, credsspFailure(fmt.Sprintf("the server's AP-REP TSRequest: version %d, %d token(s), parse error %v",
			serverRequest.Version, len(serverRequest.NegoTokens), err != nil), serverRequest.ErrorCode)
	}
	negotiatedVersion := min(cfg.Version, serverRequest.Version)
	reply, err := parseSPNEGONegTokenResp(serverRequest.NegoTokens[0], oidKerberos5)
	if err != nil || !reply.SupportedMech.Equal(oidKerberos5) || len(reply.ResponseToken) == 0 ||
		(reply.State != spnegoStateAcceptCompleted && reply.State != spnegoStateAcceptIncomplete && reply.State != spnegoStateRequestMIC) {
		return nil, credsspFailure(fmt.Sprintf("the server's SPNEGO negTokenResp: state %d, Kerberos %v, token %d bytes, parse error %v",
			reply.State, reply.SupportedMech.Equal(oidKerberos5), len(reply.ResponseToken), err), nil)
	}
	if err := kctx.acceptReply(reply.ResponseToken); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredSSPClient, err)
	}
	mechTypes, err := spnegoKerberosMechTypes()
	if err != nil {
		return nil, ErrCredSSPClient
	}
	// The target's mechListMIC, when it sent one, is checked; then the client answers with its own
	// (RFC 4178 §5), as it does when the target asks for one or has not completed.
	var lastToken []byte
	if len(reply.MechanismListMIC) != 0 {
		if err := security.VerifyMechListMIC(mechTypes, reply.MechanismListMIC); err != nil {
			return nil, credsspFailure(fmt.Sprintf("the server's mechListMIC: %v", err), nil)
		}
	}
	if len(reply.MechanismListMIC) != 0 || reply.State != spnegoStateAcceptCompleted {
		mic, err := kctx.getMIC(mechTypes)
		if err != nil {
			return nil, ErrCredSSPClient
		}
		if lastToken, err = marshalSPNEGOMICResponse(mic); err != nil {
			return nil, ErrCredSSPClient
		}
	}

	bindingRequest, err := newCredSSPClientBindingRequest(negotiatedVersion, lastToken, binding, security)
	if err != nil {
		return nil, ErrCredSSPClient
	}
	defer clearTSRequest(&bindingRequest)
	outbound, err := MarshalTSRequest(bindingRequest)
	if err != nil || writeFull(t.Conn, outbound) != nil {
		clear(outbound)
		return nil, ErrCredSSPClient
	}
	clear(outbound)
	serverBindingResponse, err := readTSRequest(t.Conn)
	if err != nil {
		return nil, credsspFailure(fmt.Sprintf("reading the server's pubKeyAuth: %v", err), nil)
	}
	// A completion token beside the target's pubKeyAuth is checked as NTLM's is, its MIC with this
	// context.
	if err := verifyCredSSPServerCompletion(serverBindingResponse, negotiatedVersion, binding, security, mechTypes, oidKerberos5); err != nil {
		var code *uint32
		if answer, perr := ParseTSRequest(serverBindingResponse); perr == nil {
			code = answer.ErrorCode
		}
		clear(serverBindingResponse)
		return nil, credsspFailure(fmt.Sprintf("the server's pubKeyAuth: %v", err), code)
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
	if err != nil || len(authInfo) == 0 {
		return nil, ErrCredSSPClient
	}
	defer clear(authInfo)
	authInfoRequest, err := MarshalTSRequest(TSRequest{Version: negotiatedVersion, AuthInfo: authInfo})
	if err != nil || !tsRequestContainsOnlyVersionAndAuthInfo(authInfoRequest) || writeFull(t.Conn, authInfoRequest) != nil {
		clear(authInfoRequest)
		return nil, ErrCredSSPClient
	}
	clear(authInfoRequest)
	if ctx.Err() != nil {
		return nil, ErrCredSSPClient
	}
	return &CredSSPClientSession{transport: t, version: negotiatedVersion, credentialsDelegated: true}, nil
}
