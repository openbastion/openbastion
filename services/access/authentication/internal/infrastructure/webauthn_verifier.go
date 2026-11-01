package infrastructure

// The WebAuthn adapter of ADR-0065, on github.com/go-webauthn/webauthn: it makes the browser's
// options, and verifies its answers — origin, rpId, user presence, challenge, signature.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// WebAuthnVerifier is an application.WebAuthn.
type WebAuthnVerifier struct{ w *webauthn.WebAuthn }

// NewWebAuthnVerifier checks the relying party: rpID a host name, each origin exact — https, or
// http towards localhost only (what WebAuthn itself allows) — and its host the rpID or under it.
func NewWebAuthnVerifier(rpID string, origins []string) (*WebAuthnVerifier, error) {
	if rpID == "" || strings.ContainsAny(rpID, ":/ ") || strings.HasPrefix(rpID, ".") || strings.HasSuffix(rpID, ".") {
		return nil, errors.New("WEBAUTHN_RP_ID must be a host name, such as bastion.example (no scheme, port or path)")
	}
	if len(origins) == 0 {
		return nil, errors.New("WEBAUTHN_ORIGINS must name the Admin UI's origins, such as https://bastion.example")
	}
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("WEBAUTHN_ORIGINS: %q is not an origin (scheme://host[:port])", o)
		}
		host := u.Hostname()
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && host == "localhost":
		default:
			return nil, fmt.Errorf("WEBAUTHN_ORIGINS: %q must be https (http only for localhost)", o)
		}
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return nil, fmt.Errorf("WEBAUTHN_ORIGINS: %q is not under WEBAUTHN_RP_ID %s: a key would not sign for it", o, rpID)
		}
	}
	w, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "OpenBastion", RPOrigins: origins})
	if err != nil {
		return nil, fmt.Errorf("WebAuthn: %v", err)
	}
	return &WebAuthnVerifier{w: w}, nil
}

// user is an application.WebAuthnUser as go-webauthn reads it.
type user struct {
	u     application.WebAuthnUser
	creds []webauthn.Credential
}

func newUser(u application.WebAuthnUser) (*user, error) {
	out := &user{u: u}
	for _, k := range u.Keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Data, &c); err != nil {
			return nil, errors.New("a stored security key cannot be read")
		}
		out.creds = append(out.creds, c)
	}
	return out, nil
}

func (u *user) WebAuthnID() []byte                         { return u.u.Handle }
func (u *user) WebAuthnName() string                       { return u.u.Name }
func (u *user) WebAuthnDisplayName() string                { return u.u.Display }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func record(c *webauthn.Credential) (domain.WebAuthnCredential, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return domain.WebAuthnCredential{}, err
	}
	return domain.WebAuthnCredential{ID: c.ID, Data: data, SignCount: c.Authenticator.SignCount}, nil
}

func (v *WebAuthnVerifier) BeginLogin(au application.WebAuthnUser) (json.RawMessage, []byte, error) {
	u, err := newUser(au)
	if err != nil {
		return nil, nil, err
	}
	assertion, session, err := v.w.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(assertion, session)
}

func (v *WebAuthnVerifier) FinishLogin(au application.WebAuthnUser, session, response []byte) (domain.WebAuthnCredential, bool, error) {
	u, err := newUser(au)
	if err != nil {
		return domain.WebAuthnCredential{}, false, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(session, &sd); err != nil {
		return domain.WebAuthnCredential{}, false, errors.New("the ceremony cannot be read")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return domain.WebAuthnCredential{}, false, err
	}
	c, err := v.w.ValidateLogin(u, sd, parsed)
	if err != nil {
		return domain.WebAuthnCredential{}, false, err
	}
	k, err := record(c)
	return k, c.Authenticator.CloneWarning, err
}

func (v *WebAuthnVerifier) BeginRegistration(au application.WebAuthnUser) (json.RawMessage, []byte, error) {
	u, err := newUser(au)
	if err != nil {
		return nil, nil, err
	}
	var exclude []protocol.CredentialDescriptor
	for i := range u.creds {
		exclude = append(exclude, u.creds[i].Descriptor())
	}
	creation, session, err := v.w.BeginRegistration(u,
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation), // no device data kept (ADR-0065)
		webauthn.WithExclusions(exclude),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: protocol.VerificationPreferred}))
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(creation, session)
}

func (v *WebAuthnVerifier) FinishRegistration(au application.WebAuthnUser, session, response []byte) (domain.WebAuthnCredential, error) {
	u, err := newUser(au)
	if err != nil {
		return domain.WebAuthnCredential{}, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(session, &sd); err != nil {
		return domain.WebAuthnCredential{}, errors.New("the ceremony cannot be read")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return domain.WebAuthnCredential{}, err
	}
	c, err := v.w.CreateCredential(u, sd, parsed)
	if err != nil {
		return domain.WebAuthnCredential{}, err
	}
	return record(c)
}

func marshalCeremony(options any, session *webauthn.SessionData) (json.RawMessage, []byte, error) {
	o, err := json.Marshal(options)
	if err != nil {
		return nil, nil, err
	}
	s, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return o, s, nil
}
