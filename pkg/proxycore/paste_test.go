package proxycore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// ADR-0133: a password sealed for a screen session opens there, for that token and protocol only.
func TestPaste_ItOpensOnlyWhereItWasSealedFor(t *testing.T) {
	key, err := NewPasteKey()
	if err != nil {
		t.Fatal(err)
	}
	if pub := key.Public(); len(pub) != screenstream.PasteKeySize || pub[0] != 0x04 {
		t.Fatalf("the public key: %d bytes", len(pub))
	}
	var token [screenstream.PasteTokenSize]byte
	token[0] = 7
	sealed, err := SealPaste(key.Public(), "sess-1", "rdp", token, []byte("Correct-Horse-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, []byte("Correct-Horse")) {
		t.Fatal("the text in clear in the message")
	}
	plain, err := key.Open("sess-1", "rdp", sealed)
	if err != nil || string(plain) != "Correct-Horse-1" {
		t.Fatalf("opened %q, %v", plain, err)
	}
	other, _ := NewPasteKey()
	var otherToken [screenstream.PasteTokenSize]byte
	otherToken[0] = 8
	for name, try := range map[string]func() ([]byte, error){
		"another session":     func() ([]byte, error) { return key.Open("sess-2", "rdp", sealed) },
		"another protocol":    func() ([]byte, error) { return key.Open("sess-1", "vnc", sealed) },
		"another session key": func() ([]byte, error) { return other.Open("sess-1", "rdp", sealed) },
		"another token":       func() ([]byte, error) { s := sealed; s.Token = otherToken; return key.Open("sess-1", "rdp", s) },
		"a ciphertext flipped": func() ([]byte, error) {
			s := sealed
			s.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
			s.Ciphertext[0] ^= 1
			return key.Open("sess-1", "rdp", s)
		},
		"another client key": func() ([]byte, error) {
			s := sealed
			s.ClientKey[10] ^= 1
			return key.Open("sess-1", "rdp", s)
		},
		"no session key": func() ([]byte, error) { var nothing *PasteKey; return nothing.Open("sess-1", "rdp", sealed) },
	} {
		if got, err := try(); !errors.Is(err, ErrPasteRefused) || got != nil {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// pasteSink is a screen client of the test: it keeps what the relay sends, and hands the relay the
// inputs the test writes, once it has read the HELLO.
type pasteSink struct {
	fakeScreenSink
	hello  chan screenstream.Message
	inputs chan []byte
}

func (s *pasteSink) Send(ctx context.Context, m screenstream.Message) error {
	if m.Type == screenstream.TypeHello {
		s.hello <- m
	}
	return s.fakeScreenSink.Send(ctx, m)
}

func (s *pasteSink) ReceiveInput(ctx context.Context) ([]byte, error) {
	select {
	case data := <-s.inputs:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// pasteRegistry is the proxy's registry as the relay sees it: it registers the typer, holds the paste
// tokens and the auditor.
type pasteRegistry struct {
	fakeSecretInputRegistrar
	mu      sync.Mutex
	tokens  map[[screenstream.PasteTokenSize]byte]string
	auditor *pasteAudit
}

func (r *pasteRegistry) TakePaste(sessionID string, token [screenstream.PasteTokenSize]byte) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account, ok := r.tokens[token]
	delete(r.tokens, token)
	return account, ok && sessionID == "screen-1"
}

func (r *pasteRegistry) PasteAuditor() SecretInputAuditor { return r.auditor }

type pasteAudit struct {
	mu      sync.Mutex
	started []SecretInputEvidence
	results []bool
	refused []string
}

func (a *pasteAudit) AuditSecretInput(_ context.Context, e SecretInputEvidence) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.started = append(a.started, e)
	return nil
}
func (a *pasteAudit) AuditSecretInputResult(_ context.Context, _ SecretInputEvidence, ok bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.results = append(a.results, ok)
	return nil
}
func (a *pasteAudit) AuditPasteRefused(_ context.Context, sessionID, protocol, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refused = append(a.refused, reason)
	return nil
}

// typingSession types into a list, under the exclusive input the common path asks for.
type typingSession struct {
	*fakeScreenSession
	mu    sync.Mutex
	typed []string
}

func (s *typingSession) WithExclusiveInput(_ context.Context, operation func() error) error {
	return operation()
}
func (s *typingSession) TypeSecret(_ context.Context, secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.typed = append(s.typed, string(secret))
	return nil
}

type pasteRecorder struct {
	*fakeFrameRecorder
	mu       sync.Mutex
	evidence []SecretInputEvidence
}

func (r *pasteRecorder) RecordSecretInput(_ context.Context, e SecretInputEvidence) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evidence = append(r.evidence, e)
	return nil
}

// ADR-0133, on the real relay: the HELLO carries the session's key; a password sealed for it with a
// token the Broker issued is typed, its salted fingerprint recorded and audited, never its text; the
// same message again, a token of no one, and a ciphertext for another session are refused and audited,
// and the session goes on.
func TestRelayScreen_AnOperatorsPasswordEncryptedForTheProxy(t *testing.T) {
	frames := make(chan screenstream.Message)
	session := &typingSession{fakeScreenSession: &fakeScreenSession{frames: frames}}
	codec := &fakeScreenCodec{secretSession: session}
	recorder := &pasteRecorder{fakeFrameRecorder: &fakeFrameRecorder{}}
	var token, stranger, burnt, long [screenstream.PasteTokenSize]byte
	token[0], stranger[0], burnt[0], long[0] = 1, 2, 3, 4
	audit := &pasteAudit{}
	registry := &pasteRegistry{tokens: map[[screenstream.PasteTokenSize]byte]string{token: "acc-desk", burnt: "acc-desk", long: "acc-desk"}, auditor: audit}
	sink := &pasteSink{hello: make(chan screenstream.Message, 1), inputs: make(chan []byte)}
	cred := newScreenTestCredential()
	cred.TargetHost, cred.TargetUser = "desk:5900", "operator"
	done := make(chan error, 1)
	go func() {
		done <- relayScreen(context.Background(), context.Background(), screenMeta(), cred, codec, recorder, sink, ScreenInputLimits{}, time.Second, nil, registry)
	}()
	hello := <-sink.hello
	if len(hello.PasteKey) != screenstream.PasteKeySize {
		t.Fatalf("the HELLO carries no key: %d bytes", len(hello.PasteKey))
	}
	send := func(in screenstream.PasteInput) {
		raw, err := screenstream.EncodePasteInput(in)
		if err != nil {
			t.Fatal(err)
		}
		sink.inputs <- raw
	}
	sealed, err := SealPaste(hello.PasteKey, "screen-1", "vnc", token, []byte("Correct-Horse-1"))
	if err != nil {
		t.Fatal(err)
	}
	send(sealed)
	send(sealed)                                                                        // the same message again: its token is taken
	strangers, _ := SealPaste(hello.PasteKey, "screen-1", "vnc", stranger, []byte("x")) // a token no one issued
	send(strangers)
	elsewhere, _ := SealPaste(hello.PasteKey, "screen-2", "vnc", burnt, []byte("y"))
	send(elsewhere) // a token of this session, a ciphertext for another: burnt, refused
	tooLong, _ := SealPaste(hello.PasteKey, "screen-1", "vnc", long, []byte(strings.Repeat("a", 129)))
	send(tooLong) // 129 characters: not a password (ADR-0097 §6), refused before anything is typed
	// Inputs are read apart from the relay's loop: the last one is handled once its refusal is written.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		audit.mu.Lock()
		n := len(audit.refused)
		audit.mu.Unlock()
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d refusal(s) written", n)
		}
	}
	frames <- validScreenFrame(1)
	close(frames)
	if err := <-done; err != nil {
		t.Fatalf("relay: %v", err)
	}
	if len(session.typed) != 1 || session.typed[0] != "Correct-Horse-1" {
		t.Fatalf("typed %q", session.typed)
	}
	if len(recorder.evidence) != 1 || len(audit.started) != 1 || len(audit.results) != 1 || !audit.results[0] {
		t.Fatalf("recorded %d, audited %d / %v", len(recorder.evidence), len(audit.started), audit.results)
	}
	e := recorder.evidence[0]
	salt, _ := hex.DecodeString(e.Salt)
	if e.Source != SecretInputOperator || e.AccountID != "acc-desk" || e.Length != 15 || e.SHA256 != SaltedSecretFingerprint(salt, []byte("Correct-Horse-1")) {
		t.Fatalf("evidence %+v", e)
	}
	if len(audit.refused) != 4 || audit.refused[3] != "a text out of the bounds of a password" {
		t.Fatalf("refusals %q", audit.refused)
	}
	if _, left := registry.tokens[burnt]; left {
		t.Fatal("a token whose ciphertext did not open was not burnt")
	}
	for _, m := range sink.snapshot() {
		if bytes.Contains(m.PNG, []byte("Correct-Horse")) || strings.Contains(m.Text, "Correct-Horse") {
			t.Fatal("the text left the proxy")
		}
	}
}

// A session that takes no paste (no registry able to) has no key in its HELLO, and an InputPaste
// sent to it anyway breaks the contract.
func TestRelayScreen_APasteTheSessionDoesNotTakeEndsIt(t *testing.T) {
	frames := make(chan screenstream.Message)
	session := &typingSession{fakeScreenSession: &fakeScreenSession{frames: frames}}
	sink := &pasteSink{hello: make(chan screenstream.Message, 1), inputs: make(chan []byte)}
	done := make(chan error, 1)
	go func() {
		done <- relayScreen(context.Background(), context.Background(), screenMeta(), newScreenTestCredential(), &fakeScreenCodec{secretSession: session},
			&pasteRecorder{fakeFrameRecorder: &fakeFrameRecorder{}}, sink, ScreenInputLimits{}, time.Second, nil, &fakeSecretInputRegistrar{})
	}()
	hello := <-sink.hello
	if hello.PasteKey != nil {
		t.Fatal("a key without a registry that takes pastes")
	}
	var in screenstream.PasteInput
	in.ClientKey[0] = 0x04
	in.Ciphertext = make([]byte, 20)
	raw, _ := screenstream.EncodePasteInput(in)
	sink.inputs <- raw
	if err := <-done; !errors.Is(err, ErrScreenInputInvalid) {
		t.Fatalf("relay: %v", err)
	}
}
