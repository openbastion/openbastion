package application

// Re-sealing under the current key what an earlier key still protects (ADR-0055).

import (
	"context"
	"fmt"
	"log"
)

// RewrapBatch is how many versions one sweep re-seals at most.
const RewrapBatch = 50

// KeyHistory is what an Encryptor that holds earlier keys says of them (infrastructure.Keyring).
type KeyHistory interface {
	PreviousKeyIDs() []string
}

// Rewrapped is what one call to RewrapDue did.
type Rewrapped struct {
	Resealed int    // versions now under the current key
	Skipped  int    // versions an earlier key the Vault holds does not open: they stay as they are
	Next     string // where the next call starts; "" when this page was the last
	Found    int    // versions on this page, re-sealed or not
}

// RewrapDue re-seals under the current key a page of up to RewrapBatch versions — current,
// pending or superseded — still sealed under an earlier key the Vault holds, starting after
// the version id after (ADR-0055). Each one is written to the audit before it changes
// (vault.secret_rewrapped, a system action): without the audit, nothing is re-sealed. A version
// written meanwhile under another key — a rotation that got there first — is left as it is
// (compare-and-swap); one the earlier key does not open is skipped and counted, never a reason
// to stop the others. An Encryptor without earlier keys has nothing to do.
func (s *VaultService) RewrapDue(ctx context.Context, after string) (Rewrapped, error) {
	var r Rewrapped
	history, ok := s.kms.(KeyHistory)
	if !ok || len(history.PreviousKeyIDs()) == 0 {
		return r, nil
	}
	if s.audit == nil {
		return r, ErrRotationOff
	}
	due, err := s.secrets.SealedUnder(ctx, history.PreviousKeyIDs(), after, RewrapBatch)
	if err != nil {
		return r, err
	}
	r.Found = len(due)
	if len(due) == RewrapBatch {
		r.Next = due[len(due)-1].ID
	}
	for _, v := range due {
		plain, err := s.kms.Open(v.EncryptionKeyID, v.EncryptedMaterial)
		if err != nil {
			r.Skipped++
			log.Printf("password-vault: version %s of account %s does not open under %s: left as it is (%v)", v.ID, v.PrivilegedAccountID, v.EncryptionKeyID, err)
			continue
		}
		sealed, err := s.kms.Seal(plain)
		clear(plain)
		if err != nil {
			return r, err
		}
		if err := s.audit.EmitEvent(ctx, "", "vault.secret_rewrapped", "account", v.PrivilegedAccountID, true); err != nil {
			return r, fmt.Errorf("%w (nothing more is re-sealed): %w", ErrAuditUnavailable, err)
		}
		swapped, err := s.secrets.ResealIf(ctx, v.ID, v.EncryptionKeyID, sealed, s.kms.KeyID())
		if err != nil {
			return r, err
		}
		if !swapped {
			log.Printf("password-vault: version %s of account %s changed while it was re-sealed: left as it is", v.ID, v.PrivilegedAccountID)
			continue
		}
		r.Resealed++
	}
	return r, nil
}
