package interfaces

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// The heads of ADR-0116 §4, for the Session Broker only (CallerRules): it attests each revision of a
// session's row, and reads the head back to compare a row with it.

type attestRequest struct {
	SessionID      string `json:"session_id"`
	Revision       uint64 `json:"revision"`
	MetadataSHA256 string `json:"metadata_sha256"`
	KeyID          string `json:"key_id"`
}

type headResponse struct {
	SessionID      string `json:"session_id"`
	Revision       uint64 `json:"revision"`
	MetadataSHA256 string `json:"metadata_sha256"`
	KeyID          string `json:"key_id"`
	EventID        string `json:"event_id"`
}

func toHeadResponse(h domain.MetadataHead) headResponse {
	return headResponse{SessionID: h.SessionID, Revision: h.Revision, MetadataSHA256: hex.EncodeToString(h.Digest), KeyID: h.KeyID, EventID: h.EventID}
}

// POST /audit/v1/session-metadata/attestations: 200 with the head (written, or already there); 409
// with the head and the reason when the revision does not follow it.
func (s *HTTPServer) handleAttestSessionMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req attestRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid attestation: not a JSON attestation", http.StatusBadRequest)
		return
	}
	digest, err := hex.DecodeString(req.MetadataSHA256)
	if err != nil {
		http.Error(w, "invalid attestation: metadata_sha256 is not hexadecimal", http.StatusBadRequest)
		return
	}
	emitter, _ := mtls.CallerFrom(r.Context())
	head, err := s.svc.AttestSessionMetadata(r.Context(), emitter, req.SessionID, req.Revision, digest, req.KeyID)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toHeadResponse(head))
	case errors.Is(err, domain.ErrMetadataFork), errors.Is(err, domain.ErrMetadataRollback), errors.Is(err, domain.ErrMetadataGap):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "head": toHeadResponse(head)})
	case errors.Is(err, domain.ErrInvalidEvent):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		log.Printf("audit-service: session metadata attestation not written: %v", err)
		http.Error(w, "the attestation could not be written", http.StatusServiceUnavailable)
	}
}

// GET /audit/v1/session-metadata/head?session_id=: 200 with the head checked against its signed
// event; 404 without one; 500 if it does not recompute (the projection was altered).
func (s *HTTPServer) handleSessionMetadataHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	head, err := s.svc.SessionMetadataHead(r.Context(), r.URL.Query().Get("session_id"))
	switch {
	case err == nil && head == nil:
		http.Error(w, "no attested head for this session", http.StatusNotFound)
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toHeadResponse(*head))
	case errors.Is(err, domain.ErrInvalidEvent):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, domain.ErrMetadataHeadTampered):
		log.Printf("audit-service: ADR-0116: the head of a session does not match its signed event")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	case errors.Is(err, application.ErrMetadataHeadsUnavailable):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		log.Printf("audit-service: session metadata head unavailable: %v", err)
		http.Error(w, "the head could not be read", http.StatusServiceUnavailable)
	}
}
