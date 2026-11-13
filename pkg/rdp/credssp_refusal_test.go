package rdp

import (
	"errors"
	"testing"
)

// A target refusing the account's credentials is told apart from every other CredSSP failure: the
// statuses by which Windows refuses a name or password, and only those (ADR-0071 §12).
func TestCredSSPFailure_SaysWhenTheCredentialsAreRefused(t *testing.T) {
	for _, status := range []uint32{0xC000006D, 0xC000006A, 0xC0000064, 0xC0000071, 0xC0000072, 0xC0000193, 0xC0000224, 0xC0000234} {
		code := status
		err := credsspFailure("pubKeyAuth", &code)
		if !errors.Is(err, ErrCredSSPClient) || !errors.Is(err, ErrTargetCredentialsRefused) {
			t.Errorf("0x%08X: %v", status, err)
		}
	}
	for _, code := range []*uint32{nil, ptr(0xC0000022), ptr(0x80090302), ptr(0)} {
		err := credsspFailure("pubKeyAuth", code)
		if !errors.Is(err, ErrCredSSPClient) || errors.Is(err, ErrTargetCredentialsRefused) {
			t.Errorf("%v: %v, want a plain CredSSP failure", code, err)
		}
	}
}

func ptr(v uint32) *uint32 { return &v }
