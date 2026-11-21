package proxycore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/openbastion/openbastion/pkg/screenstream"
	"golang.org/x/crypto/hkdf"
)

// An operator's password, encrypted in the browser for the proxy (ADR-0133): the Gateway relays the
// screen stream by decoding its frames, so a healthy Gateway must only ever hold the ciphertext.
// Each screen session has its own ephemeral P-256 key, published in its HELLO; the browser draws an
// ephemeral key of its own per password, derives an AES-256-GCM key by HKDF-SHA-256 from the ECDH
// secret, salted by the one-use paste token and bound to both public keys, and encrypts the text with
// the session, the token and the protocol as associated data. A ciphertext captured on the way is
// neither readable, nor replayable (the token is taken once), nor movable to another session.
//
// What this does not protect from, said in ADR-0133: a compromised Gateway serves the Admin UI, and
// can read the password before it is encrypted.

// PasteInfo and PasteAAD are the labels of the derivation and of the associated data: changing either
// is a new version of the message, never a silent one.
const (
	pasteHKDFInfo = "openbastion paste v1"
	pasteAADLabel = "openbastion-paste-v1"
)

// ErrPasteRefused is a paste the proxy did not type: no key, no token, a token already taken, a
// ciphertext that does not open. The session goes on; the refusal is audited.
var ErrPasteRefused = errors.New("proxycore: operator paste refused")

// PasteKey is a screen session's ephemeral ECDH key. It lives as long as the relay and is never
// written anywhere.
type PasteKey struct {
	private *ecdh.PrivateKey
}

// NewPasteKey draws a screen session's key.
func NewPasteKey() (*PasteKey, error) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PasteKey{private: private}, nil
}

// Public is the key the HELLO carries: an uncompressed P-256 point.
func (k *PasteKey) Public() []byte {
	return k.private.PublicKey().Bytes()
}

// pasteAAD binds a ciphertext to its session, its token and its protocol.
func pasteAAD(sessionID string, token [screenstream.PasteTokenSize]byte, protocol string) []byte {
	aad := make([]byte, 0, len(pasteAADLabel)+1+len(sessionID)+1+len(token)+len(protocol))
	aad = append(aad, pasteAADLabel...)
	aad = append(aad, 0)
	aad = append(aad, sessionID...)
	aad = append(aad, 0)
	aad = append(aad, token[:]...)
	return append(aad, protocol...)
}

// pasteAEAD is the AES-256-GCM of one paste: HKDF-SHA-256 of the ECDH secret, salted by the token,
// with the label and both public keys as info.
func pasteAEAD(shared []byte, token [screenstream.PasteTokenSize]byte, clientKey, proxyKey []byte) (cipher.AEAD, error) {
	info := append(append([]byte(pasteHKDFInfo), clientKey...), proxyKey...)
	// golang.org/x/crypto/hkdf: crypto/hkdf needs Go 1.24, and this module declares 1.22.
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, token[:], info), key); err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Open decrypts a paste for this session. The plaintext is the caller's to zero.
func (k *PasteKey) Open(sessionID, protocol string, in screenstream.PasteInput) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: the session takes no paste", ErrPasteRefused)
	}
	clientKey, err := ecdh.P256().NewPublicKey(in.ClientKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: the client's key", ErrPasteRefused)
	}
	shared, err := k.private.ECDH(clientKey)
	if err != nil {
		return nil, fmt.Errorf("%w: the key agreement", ErrPasteRefused)
	}
	defer clear(shared)
	aead, err := pasteAEAD(shared, in.Token, in.ClientKey[:], k.Public())
	if err != nil {
		return nil, fmt.Errorf("%w: the key derivation", ErrPasteRefused)
	}
	plain, err := aead.Open(nil, in.Nonce[:], in.Ciphertext, pasteAAD(sessionID, in.Token, protocol))
	if err != nil {
		return nil, fmt.Errorf("%w: the ciphertext does not open", ErrPasteRefused)
	}
	return plain, nil
}

// SealPaste is what the browser does (WebCrypto), written in Go for the tests and for any other
// client of the screen contract: an ephemeral key, the same derivation, a random nonce.
func SealPaste(proxyKey []byte, sessionID, protocol string, token [screenstream.PasteTokenSize]byte, text []byte) (screenstream.PasteInput, error) {
	var in screenstream.PasteInput
	proxy, err := ecdh.P256().NewPublicKey(proxyKey)
	if err != nil {
		return in, err
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return in, err
	}
	shared, err := ephemeral.ECDH(proxy)
	if err != nil {
		return in, err
	}
	defer clear(shared)
	copy(in.ClientKey[:], ephemeral.PublicKey().Bytes())
	in.Token = token
	aead, err := pasteAEAD(shared, token, in.ClientKey[:], proxyKey)
	if err != nil {
		return in, err
	}
	if _, err := rand.Read(in.Nonce[:]); err != nil {
		return in, err
	}
	in.Ciphertext = aead.Seal(nil, in.Nonce[:], text, pasteAAD(sessionID, token, protocol))
	return in, nil
}

// PasteAuthorizer holds the paste tokens the Session Broker issued after the operator's second
// factor (ADR-0133 §2): one per paste, for one session, for a short while. TakePaste consumes it and
// returns the account the session is on.
type PasteAuthorizer interface {
	TakePaste(sessionID string, token [screenstream.PasteTokenSize]byte) (accountID string, ok bool)
}

// PasteRefusalAuditor writes a refused paste: nothing typed, the reason, never the text.
type PasteRefusalAuditor interface {
	AuditPasteRefused(ctx context.Context, sessionID, protocol, reason string) error
}

// PasteAuditing is a registry that audits the pastes it authorizes: the same auditor as a Vault
// secret's, the start and the result of the typing.
type PasteAuditing interface {
	PasteAuditor() SecretInputAuditor
}

// screenPaste is a screen session's side of ADR-0133: its key, the tokens' holder, and what types.
type screenPaste struct {
	key      *PasteKey
	pastes   PasteAuthorizer
	auditor  SecretInputAuditor
	typer    SecretTyper
	recorder SecretInputRecorder
	session  string
	protocol string
}

// newScreenPaste is nil unless the registry holds paste tokens and an auditor, and a key is drawn.
func newScreenPaste(registry SecretInputRegistrar, meta SessionMetadata, typer SecretTyper, recorder SecretInputRecorder) *screenPaste {
	pastes, ok := registry.(PasteAuthorizer)
	auditing, ok2 := registry.(PasteAuditing)
	if !ok || !ok2 || auditing.PasteAuditor() == nil {
		return nil
	}
	key, err := NewPasteKey()
	if err != nil {
		return nil
	}
	return &screenPaste{key: key, pastes: pastes, auditor: auditing.PasteAuditor(), typer: typer, recorder: recorder,
		session: meta.SessionID, protocol: screenProtocolName(meta.ScreenProtocol)}
}

// handle types one paste, or refuses it. The token is taken before anything is decrypted: a
// ciphertext that does not open burns it, and the operator goes through the second factor again.
func (p *screenPaste) handle(ctx context.Context, in screenstream.PasteInput) {
	accountID, ok := p.pastes.TakePaste(p.session, in.Token)
	if !ok {
		p.refuse(ctx, "no paste token, or one already taken or expired")
		return
	}
	plain, err := p.key.Open(p.session, p.protocol, in)
	if err != nil {
		p.refuse(ctx, "the ciphertext does not open")
		return
	}
	// InjectSecret checks the bounds (128 characters, one line, no control character), audits,
	// records the salted fingerprint, types, audits the result, and zeroes the text.
	if err := InjectSecret(ctx, p.session, p.protocol, SecretInputOperator, accountID, plain, p.auditor, p.recorder, p.typer); err != nil {
		if errors.Is(err, ErrSecretInjectionInvalid) {
			p.refuse(ctx, "a text out of the bounds of a password")
		}
		return
	}
}

func (p *screenPaste) refuse(ctx context.Context, reason string) {
	if auditor, ok := p.auditor.(PasteRefusalAuditor); ok {
		_ = auditor.AuditPasteRefused(ctx, p.session, p.protocol, reason)
	}
}
