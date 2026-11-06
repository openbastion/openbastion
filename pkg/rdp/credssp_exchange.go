package rdp

import "errors"

var ErrCredSSPBindingExchange = errors.New("rdp: invalid CredSSP public-key binding exchange")

// NewCredSSPClientBindingRequest creates the final client TSRequest for a
// CredSSP v5/v6 exchange. lastSPNEGOToken must be the final token produced by
// the caller's completed NTLM/SPNEGO negotiation. Per MS-CSSP, that token and
// pubKeyAuth are sent together. The returned request carries the client nonce.
//
// Building the request consumes one outbound GSS_Wrap sequence number. The
// caller must send this request exactly once; if sending fails or is uncertain,
// discard the security context rather than retrying with the same state.
func NewCredSSPClientBindingRequest(
	version uint32,
	lastSPNEGOToken []byte,
	binding CredSSPPublicKeyBinding,
	security *NTLMSSPClientSecurityContext,
) (TSRequest, error) {
	if version < 5 || version > 6 || !binding.valid || security == nil || len(lastSPNEGOToken) > maxCredSSPToken {
		return TSRequest{}, ErrCredSSPBindingExchange
	}

	sealedHash, err := security.WrapClientToServer(binding.ClientToServerHash[:])
	if err != nil {
		return TSRequest{}, ErrCredSSPBindingExchange
	}
	var tokens [][]byte
	if len(lastSPNEGOToken) != 0 {
		tokens = [][]byte{append([]byte(nil), lastSPNEGOToken...)}
	}
	return TSRequest{
		Version:     version,
		NegoTokens:  tokens,
		PubKeyAuth:  sealedHash,
		ClientNonce: append([]byte(nil), binding.ClientNonce[:]...),
	}, nil
}

// VerifyCredSSPServerBindingResponse parses and validates the server's
// pubKeyAuth-only TSRequest, unseals its payload, and verifies the v5/v6
// Server-To-Client Binding Hash. Any failure closes the security context: the
// caller must not continue the CredSSP exchange or send authInfo.
func VerifyCredSSPServerBindingResponse(
	encoded []byte,
	version uint32,
	binding CredSSPPublicKeyBinding,
	security *NTLMSSPClientSecurityContext,
) error {
	return verifyCredSSPServerCompletion(encoded, version, binding, security, nil)
}

// verifyCredSSPServerCompletion also accepts the server's last SPNEGO token beside pubKeyAuth when
// mechTypes says what its MIC covers: that token only completes the negotiation, and a MIC is
// checked whenever present.
func verifyCredSSPServerCompletion(
	encoded []byte,
	version uint32,
	binding CredSSPPublicKeyBinding,
	security *NTLMSSPClientSecurityContext,
	mechTypes []byte,
) error {
	if security == nil || !binding.valid || version < 5 || version > 6 {
		if security != nil {
			security.Close()
		}
		return ErrCredSSPBindingExchange
	}

	request, err := ParseTSRequest(encoded)
	if err != nil || request.Version != version || len(request.PubKeyAuth) == 0 ||
		!tsRequestContainsOnlyServerCompletionFields(encoded, mechTypes != nil) {
		security.Close()
		return ErrCredSSPBindingExchange
	}
	if err := verifySPNEGOCompletion(request.NegoTokens, security, mechTypes, false); err != nil {
		security.Close()
		return ErrCredSSPBindingExchange
	}

	plaintext, err := security.UnwrapServerToClient(request.PubKeyAuth)
	if err != nil {
		security.Close()
		return ErrCredSSPBindingExchange
	}
	defer clear(plaintext)
	if err := binding.VerifyServerToClientHash(plaintext); err != nil {
		security.Close()
		return ErrCredSSPBindingExchange
	}
	return nil
}

// verifySPNEGOCompletion: an exchange the server asked for and did not finish is not finished.
func verifySPNEGOCompletion(tokens [][]byte, security *NTLMSSPClientSecurityContext, mechTypes []byte, micRequired bool) error {
	if len(tokens) == 0 {
		if micRequired {
			return ErrCredSSPBindingExchange
		}
		return nil
	}
	if len(tokens) != 1 {
		return ErrCredSSPBindingExchange
	}
	completion, err := ParseSPNEGONegTokenResp(tokens[0])
	if err != nil || completion.State != spnegoStateAcceptCompleted || len(completion.ResponseToken) != 0 {
		return ErrCredSSPBindingExchange
	}
	if len(completion.MechanismListMIC) == 0 {
		if micRequired {
			return ErrCredSSPBindingExchange
		}
		return nil
	}
	return security.VerifyMechListMIC(mechTypes, completion.MechanismListMIC)
}

// tsRequestContainsOnlyServerCompletionFields enforces the server response shape
// from MS-CSSP §3.1.5: no authInfo, errorCode, or clientNonce, and negoTokens
// only where the caller can check them.
// ParseTSRequest has already validated DER canonicality and field ordering.
func tsRequestContainsOnlyServerCompletionFields(encoded []byte, allowNegoTokens bool) bool {
	outer, rest, err := derRead(encoded)
	if err != nil || outer.tag != 0x30 || len(rest) != 0 {
		return false
	}
	seenVersion, seenPubKeyAuth := false, false
	for fields := outer.value; len(fields) > 0; {
		field, tail, err := derRead(fields)
		if err != nil {
			return false
		}
		switch field.tag {
		case 0xa0:
			if seenVersion {
				return false
			}
			seenVersion = true
		case 0xa1:
			if !allowNegoTokens {
				return false
			}
		case 0xa3:
			if seenPubKeyAuth {
				return false
			}
			seenPubKeyAuth = true
		default:
			return false
		}
		fields = tail
	}
	return seenVersion && seenPubKeyAuth
}
