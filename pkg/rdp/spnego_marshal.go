package rdp

import (
	"encoding/asn1"
)

// MarshalSPNEGONTLMInit wraps the client's NTLMSSP NEGOTIATE message in the
// RFC 4178 InitialContextToken / NegTokenInit form used by CredSSP.
func MarshalSPNEGONTLMInit(mechanismToken []byte) ([]byte, error) {
	if len(mechanismToken) == 0 || len(mechanismToken) > maxSPNEGOToken {
		return nil, ErrSPNEGOToken
	}
	spnego, err := asn1.Marshal(spnegoOID)
	if err != nil {
		return nil, ErrSPNEGOToken
	}
	ntlm, err := asn1.Marshal(ntlmOID)
	if err != nil {
		return nil, ErrSPNEGOToken
	}
	mechTypes := derWrap(0xa0, derWrap(0x30, ntlm))
	mechToken := derWrap(0xa2, derWrap(0x04, mechanismToken))
	negTokenInit := derWrap(0xa0, derWrap(0x30, append(mechTypes, mechToken...)))
	body := append(spnego, negTokenInit...)
	encoded := derWrap(0x60, body)
	if len(encoded) > maxSPNEGOToken {
		return nil, ErrSPNEGOToken
	}
	return encoded, nil
}

// MarshalSPNEGONTLMResponse wraps one NTLMSSP mechanism token in a
// NegTokenResp. It deliberately emits no negState, mechListMIC or mechanism
// switch; this is the final client token for the strict single-mechanism flow.
func MarshalSPNEGONTLMResponse(mechanismToken []byte) ([]byte, error) {
	if len(mechanismToken) == 0 || len(mechanismToken) > maxSPNEGOToken {
		return nil, ErrSPNEGOToken
	}
	encoded := derWrap(0xa1, derWrap(0x30, derWrap(0xa2, derWrap(0x04, mechanismToken))))
	if len(encoded) > maxSPNEGOToken {
		return nil, ErrSPNEGOToken
	}
	return encoded, nil
}
