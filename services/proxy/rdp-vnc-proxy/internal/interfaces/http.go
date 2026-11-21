package interfaces

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

const screenSubprotocol = "openbastion.screen.v1"

type secretInjectionOutcomeUnknownResponse struct {
	Status      string `json:"status"`
	InjectionID string `json:"injection_id"`
}

type HTTPServer struct {
	pending  *infrastructure.PendingScreenSessions
	listener *proxycore.Listener
	codec    proxycore.ScreenCodec
	// rdpCodec is set only when RDP is on (ADR-0088, RDP_ENABLED): nil, RDP is refused.
	rdpCodec       proxycore.ScreenCodec
	recorder       *infrastructure.VideoRecorderClient
	gate           proxycore.ScreenRecorderGate
	secretInputs   *infrastructure.SecretInputRegistry
	secretFetcher  *proxycore.CredentialFetcher
	secretAuditor  proxycore.SecretInputAuditor
	endpoint       string
	allowedOrigins []string
}

func NewHTTPServer(p *infrastructure.PendingScreenSessions, l *proxycore.Listener, codec proxycore.ScreenCodec, recorder *infrastructure.VideoRecorderClient, endpoint string, origins []string) *HTTPServer {
	return &HTTPServer{pending: p, listener: l, codec: codec, recorder: recorder, gate: recorder, endpoint: endpoint, allowedOrigins: append([]string(nil), origins...)}
}

// WithRDP opens the RDP route with its codec (ADR-0088). Without it, establish-session refuses rdp.
func (s *HTTPServer) WithRDP(codec proxycore.ScreenCodec) *HTTPServer {
	s.rdpCodec = codec
	return s
}

// WithSecretInputs enables the Session Broker's mTLS-only Vault injection path.
func (s *HTTPServer) WithSecretInputs(registry *infrastructure.SecretInputRegistry, fetcher *proxycore.CredentialFetcher, auditor proxycore.SecretInputAuditor) *HTTPServer {
	s.secretInputs, s.secretFetcher, s.secretAuditor = registry, fetcher, auditor
	return s
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/internal/v1/establish-session", s.establish)
	mux.HandleFunc("/internal/v1/revoke-session", s.revoke)
	mux.HandleFunc("/internal/v1/inject-vault-secret", s.injectVaultSecret)
	mux.HandleFunc("/internal/v1/authorize-paste", s.authorizePaste)
	mux.HandleFunc("/internal/v1/screen", s.screen)
	return mux
}

type establishRequest struct {
	SessionID       string `json:"session_id"`
	VaultScopeToken string `json:"vault_scope_token"`
	Protocol        string `json:"protocol"`
	TTLSeconds      int    `json:"ttl_seconds"`
	BreakGlass      bool   `json:"break_glass"`
	// The clipboard directions the Broker granted (ADR-0096 §1); absent means refused.
	ClipboardToTarget   bool `json:"clipboard_to_target"`
	ClipboardFromTarget bool `json:"clipboard_from_target"`
	// The screen the Broker resolved (ADR-0132): RDP only, absent means the deployment's.
	ScreenChannel string `json:"screen_channel"`
	ColorDepth    int    `json:"color_depth"`
}
type establishResponse struct {
	ProxyEndpoint    string `json:"proxy_endpoint"`
	ConnectionTicket string `json:"connection_ticket"`
}

func (s *HTTPServer) establish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req establishRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" || req.VaultScopeToken == "" || req.TTLSeconds < 1 || req.TTLSeconds > 86400 || req.BreakGlass {
		http.Error(w, "invalid screen session request", http.StatusBadRequest)
		return
	}
	var protocol screenstream.Protocol
	switch {
	case req.Protocol == "vnc":
		protocol = screenstream.ProtocolVNC
	case req.Protocol == "rdp" && s.rdpCodec != nil:
		protocol = screenstream.ProtocolRDP
	default:
		// RDP is opened by the installation's operator (ADR-0088), not by default.
		http.Error(w, "screen protocol is unavailable", http.StatusConflict)
		return
	}
	// Only RDP has a clipboard channel (ADR-0096). A right for another protocol is a Broker
	// that got something wrong: refused, like a break-glass request for a screen.
	if protocol != screenstream.ProtocolRDP && (req.ClipboardToTarget || req.ClipboardFromTarget) {
		http.Error(w, "invalid screen session request", http.StatusBadRequest)
		return
	}
	// The screen choice is RDP's alone (ADR-0132), and only the values the Broker can resolve.
	if !validScreenChoice(protocol, req.ScreenChannel, req.ColorDepth) {
		http.Error(w, "invalid screen session request", http.StatusBadRequest)
		return
	}
	if s.listener == nil || s.listener.Live == nil || s.pending == nil || s.gate == nil {
		http.Error(w, "screen service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.listener.Live.Revoked(req.SessionID) {
		http.Error(w, "session revoked", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.gate.Ready(ctx); err != nil {
		_ = s.listener.Terminator.EmitRecordingUnavailable(r.Context(), req.SessionID)
		http.Error(w, "recording unavailable", http.StatusServiceUnavailable)
		return
	}
	expires := time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
	ticket, err := s.pending.Register(infrastructure.PendingScreenSession{SessionID: req.SessionID, ScopeToken: req.VaultScopeToken, Protocol: protocol, ExpiresAt: expires, ClipboardToTarget: req.ClipboardToTarget, ClipboardFromTarget: req.ClipboardFromTarget, ScreenChannel: req.ScreenChannel, ColorDepth: req.ColorDepth})
	if err != nil {
		http.Error(w, "ticket generation unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.listener.Live.Revoked(req.SessionID) {
		s.pending.RevokeSession(req.SessionID)
		http.Error(w, "session revoked", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(establishResponse{ProxyEndpoint: s.endpoint, ConnectionTicket: ticket})
}

type revokeRequest struct {
	SessionID  string `json:"session_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}
type revokeResponse struct {
	TicketsRevoked int `json:"tickets_revoked"`
	ConnectionsCut int `json:"connections_cut"`
}

func (s *HTTPServer) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || req.SessionID == "" || req.TTLSeconds < 1 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if s.listener == nil || s.listener.Live == nil {
		http.Error(w, "revocation unavailable", http.StatusServiceUnavailable)
		return
	}
	memory := time.Duration(req.TTLSeconds) * time.Second
	if memory > 7*24*time.Hour {
		memory = 7 * 24 * time.Hour
	}
	revocation := s.listener.Live.Revoke(req.SessionID, time.Now().Add(memory))
	tickets := s.pending.RevokeSession(req.SessionID)
	cut := revocation.Cut()
	if still := revocation.Wait(5 * time.Second); still > 0 {
		http.Error(w, "session is still closing", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(revokeResponse{TicketsRevoked: tickets, ConnectionsCut: cut})
}

// authorizePasteRequest is the Session Broker's grant of one operator paste (ADR-0133 §2), after
// the operator's second factor: the session, its account, the one-use token (64 hex), its lifetime.
type authorizePasteRequest struct {
	SessionID  string `json:"session_id"`
	AccountID  string `json:"account_id"`
	PasteToken string `json:"paste_token"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// authorizePaste is called only by the Session Broker over mTLS. No text crosses it: the text comes
// encrypted for this proxy over the screen stream, with this token.
func (s *HTTPServer) authorizePaste(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req authorizePasteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	var token [screenstream.PasteTokenSize]byte
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid paste grant", http.StatusBadRequest)
		return
	}
	raw, hexErr := hex.DecodeString(req.PasteToken)
	if hexErr != nil || len(raw) != screenstream.PasteTokenSize || req.TTLSeconds < 1 || req.TTLSeconds > int(infrastructure.MaxPasteTTL/time.Second) {
		http.Error(w, "invalid paste grant", http.StatusBadRequest)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid paste grant", http.StatusBadRequest)
		return
	}
	copy(token[:], raw)
	if s.secretInputs == nil || s.secretInputs.PasteAuditor() == nil {
		http.Error(w, "operator paste unavailable", http.StatusServiceUnavailable)
		return
	}
	switch err := s.secretInputs.AuthorizePaste(req.SessionID, req.AccountID, token, time.Duration(req.TTLSeconds)*time.Second); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, infrastructure.ErrSecretSessionInactive):
		http.Error(w, "session input is not active", http.StatusNotFound)
	default:
		http.Error(w, "invalid paste grant", http.StatusBadRequest)
	}
}

type injectVaultSecretRequest struct {
	SessionID  string `json:"session_id"`
	AccountID  string `json:"account_id"`
	ScopeToken string `json:"vault_scope_token"`
}

// injectVaultSecret is called only by Session Broker over mTLS. The scope is
// exchanged by this proxy directly with Vault; neither Gateway nor Broker sees bytes.
func (s *HTTPServer) injectVaultSecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req injectVaultSecretRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.SessionID == "" || len(req.SessionID) > 256 || req.AccountID == "" || len(req.AccountID) > 128 || req.ScopeToken == "" || len(req.ScopeToken) > 8192 {
		http.Error(w, "invalid secret injection request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid secret injection request", http.StatusBadRequest)
		return
	}
	if s.secretInputs == nil || s.secretFetcher == nil || s.secretAuditor == nil {
		http.Error(w, "secret injection unavailable", http.StatusServiceUnavailable)
		return
	}
	err := s.secretInputs.InjectVaultScope(r.Context(), req.SessionID, req.AccountID, req.ScopeToken, s.secretFetcher, s.secretAuditor)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, proxycore.ErrSecretInjectionOutcomeUnknown):
		var outcome *proxycore.SecretInjectionOutcomeUnknownError
		if !errors.As(err, &outcome) || outcome.InjectionID == "" {
			http.Error(w, "secret injection outcome unknown", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(secretInjectionOutcomeUnknownResponse{Status: "outcome_unknown", InjectionID: outcome.InjectionID})
	case errors.Is(err, infrastructure.ErrSecretSessionInactive):
		http.Error(w, "session input is not active", http.StatusNotFound)
	case errors.Is(err, infrastructure.ErrSecretSessionAmbiguous):
		http.Error(w, "session has multiple active input streams", http.StatusConflict)
	case errors.Is(err, proxycore.ErrSecretInjectionInvalid):
		http.Error(w, "secret injection refused", http.StatusConflict)
	default:
		log.Printf("rdp-vnc-proxy: Vault injection refused for session %s: %v", req.SessionID, err)
		http.Error(w, "secret injection unavailable", http.StatusServiceUnavailable)
	}
}

func (s *HTTPServer) screen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pending == nil || s.listener == nil || s.codec == nil || s.recorder == nil {
		http.Error(w, "screen service unavailable", http.StatusServiceUnavailable)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{screenSubprotocol}, OriginPatterns: s.allowedOrigins})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "session ended")
	conn.SetReadLimit(screenstream.MaxInputBytes)
	// A read cancelled by its context closes the WebSocket, and the session's context ends before
	// the END that says why: the input reads under this one, which outlives the relay.
	inputCtx, stopInput := context.WithCancel(context.Background())
	defer stopInput()
	sink := &websocketScreenSink{conn: conn, inputCtx: inputCtx}
	writeTicketEnd := func() {
		endCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = sink.Send(endCtx, screenstream.Message{Type: screenstream.TypeEnd, Sequence: 1, Timestamp: time.Now().UTC(), EndCode: screenstream.EndCodeTicketInvalid, Text: "ticket_invalid"})
	}
	authorization := r.Header.Get("Authorization")
	ticket, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || ticket == "" {
		writeTicketEnd()
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid connection ticket")
		return
	}
	pending, err := s.pending.Consume(ticket, time.Now().UTC())
	if err != nil {
		writeTicketEnd()
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid connection ticket")
		return
	}
	// The Listener applies ExpiresAt to the relay alone. A deadline here would also end the context
	// the audit of the expiry and the purge of the credential run on.
	ctx := r.Context()
	meta := screenMetadata(pending)
	conn.SetReadLimit(screenReadLimit(meta))
	// The codec is the ticket's protocol's, which the Broker took from the session: never the
	// browser's choice.
	codec := s.codec
	if pending.Protocol == screenstream.ProtocolRDP {
		codec = s.rdpCodec
	}
	if codec == nil {
		writeTicketEnd()
		_ = conn.Close(websocket.StatusPolicyViolation, "screen protocol is unavailable")
		return
	}
	if pending.Protocol == screenstream.ProtocolRDP {
		var err error
		if codec, err = sessionScreen(codec, pending); err != nil {
			log.Printf("rdp-vnc-proxy: session %s not opened: %v", pending.SessionID, err)
			writeTicketEnd()
			_ = conn.Close(websocket.StatusPolicyViolation, "screen protocol is unavailable")
			return
		}
	}
	if err := s.listener.ServeScreen(ctx, meta, codec, s.recorder, s.gate, sink); err != nil {
		log.Printf("rdp-vnc-proxy: graphical session ended: %v", err)
	}
}

// validScreenChoice: an RDP session's channel and depth are ones the Broker resolves to (ADR-0132)
// or empty; any other protocol carries none.
func validScreenChoice(protocol screenstream.Protocol, channel string, colorDepth int) bool {
	if protocol != screenstream.ProtocolRDP {
		return channel == "" && colorDepth == 0
	}
	return (channel == "" || channel == "graphics" || channel == "bitmap") &&
		(colorDepth == 0 || colorDepth == 16 || colorDepth == 32)
}

// screenChoosingCodec is a codec that opens a session with its own screen (engine.RDPCodec).
type screenChoosingCodec interface {
	WithScreen(channel string, colorDepth int) (proxycore.ScreenCodec, bool, error)
}

// sessionScreen is the codec of the ticket's session, with the screen the Broker resolved
// (ADR-0132), and the line that says which. A choice the codec cannot apply is refused: the session
// is not opened on another screen than the one on the record.
func sessionScreen(codec proxycore.ScreenCodec, p infrastructure.PendingScreenSession) (proxycore.ScreenCodec, error) {
	if p.ScreenChannel == "" && p.ColorDepth == 0 {
		return codec, nil
	}
	choosing, ok := codec.(screenChoosingCodec)
	if !ok {
		return nil, fmt.Errorf("the codec cannot apply the screen choice (channel %q, %d bpp)", p.ScreenChannel, p.ColorDepth)
	}
	session, downgraded, err := choosing.WithScreen(p.ScreenChannel, p.ColorDepth)
	if err != nil {
		return nil, err
	}
	channel := p.ScreenChannel
	if downgraded {
		// SCREEN_RDPGFX=false is the deployment's ceiling (ADR-0132 §4).
		log.Printf("rdp-vnc-proxy: session %s: graphics chosen, the graphics pipeline is off on this proxy (SCREEN_RDPGFX): bitmap", p.SessionID)
		channel = "bitmap"
	}
	log.Printf("rdp-vnc-proxy: session %s screen: channel %q, %d bpp asked", p.SessionID, channel, p.ColorDepth)
	return session, nil
}

type websocketScreenSink struct {
	conn     *websocket.Conn
	inputCtx context.Context
}

func (s *websocketScreenSink) Send(ctx context.Context, m screenstream.Message) error {
	data, err := screenstream.Encode(m)
	if err != nil {
		return err
	}
	return s.conn.Write(ctx, websocket.MessageBinary, data)
}
func (s *websocketScreenSink) ReceiveInput(context.Context) ([]byte, error) {
	typ, data, err := s.conn.Read(s.inputCtx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary || (len(data) != screenstream.InputMessageSize && !screenstream.IsClipboardInput(data)) {
		return nil, fmt.Errorf("invalid screen input message")
	}
	return data, nil
}

// screenMetadata is what a consumed ticket tells the Listener: the session, its scope, its
// protocol and end, and the clipboard directions the Broker granted (ADR-0096 §1). Nothing in it
// comes from the browser.
func screenMetadata(p infrastructure.PendingScreenSession) proxycore.SessionMetadata {
	return proxycore.SessionMetadata{
		SessionID: p.SessionID, ScopeToken: p.ScopeToken, ScreenProtocol: p.Protocol, ExpiresAt: p.ExpiresAt,
		ClipboardToTarget: p.ClipboardToTarget, ClipboardFromTarget: p.ClipboardFromTarget,
	}
}

// screenReadLimit is the longest message a session's client may send: a clipboard text when the
// session may paste (ADR-0096 §6), 64 bytes otherwise, as before.
func screenReadLimit(meta proxycore.SessionMetadata) int64 {
	if meta.ClipboardToTarget {
		return screenstream.MaxClipboardInputBytes
	}
	return screenstream.MaxInputBytes
}
