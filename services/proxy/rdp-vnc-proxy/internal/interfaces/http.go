package interfaces

import (
	"context"
	"encoding/json"
	"fmt"
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

type HTTPServer struct {
	pending  *infrastructure.PendingScreenSessions
	listener *proxycore.Listener
	codec    proxycore.ScreenCodec
	// rdpCodec is set only when RDP is on (ADR-0088, RDP_ENABLED): nil, RDP is refused.
	rdpCodec       proxycore.ScreenCodec
	recorder       *infrastructure.VideoRecorderClient
	gate           proxycore.ScreenRecorderGate
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

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/internal/v1/establish-session", s.establish)
	mux.HandleFunc("/internal/v1/revoke-session", s.revoke)
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
	ticket, err := s.pending.Register(infrastructure.PendingScreenSession{SessionID: req.SessionID, ScopeToken: req.VaultScopeToken, Protocol: protocol, ExpiresAt: expires, ClipboardToTarget: req.ClipboardToTarget, ClipboardFromTarget: req.ClipboardFromTarget})
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
	if err := s.listener.ServeScreen(ctx, meta, codec, s.recorder, s.gate, sink); err != nil {
		log.Printf("rdp-vnc-proxy: graphical session ended: %v", err)
	}
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
	if typ != websocket.MessageBinary || len(data) != screenstream.InputMessageSize {
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
