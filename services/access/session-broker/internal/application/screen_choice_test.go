package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// The operator's screen choice is resolved against the account's profile before any Vault scope
// (ADR-0132): what the profile allows reaches the proxy and the audit, what it does not is refused
// with nothing started.
func TestConnect_ScreenChoiceAgainstTheAccountProfile(t *testing.T) {
	bitmapOnly16 := &domain.ScreenProfile{Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{16, 32}, DefaultColorDepth: 16}
	cases := []struct {
		name      string
		protocol  string
		profile   *domain.ScreenProfile
		screenErr error
		choice    domain.ScreenChoice
		want      domain.ScreenChoice
		wantErr   error
	}{
		{name: "no profile, no choice: the current behaviour", protocol: "rdp", want: domain.ScreenChoice{Channel: "graphics", ColorDepth: 32}},
		{name: "no profile, bitmap chosen", protocol: "rdp", choice: domain.ScreenChoice{Channel: "bitmap"}, want: domain.ScreenChoice{Channel: "bitmap", ColorDepth: 32}},
		{name: "the account's defaults", protocol: "rdp", profile: bitmapOnly16, want: domain.ScreenChoice{Channel: "bitmap", ColorDepth: 16}},
		{name: "a depth the profile allows", protocol: "rdp", profile: bitmapOnly16, choice: domain.ScreenChoice{ColorDepth: 32}, want: domain.ScreenChoice{Channel: "bitmap", ColorDepth: 32}},
		{name: "a channel the profile forbids", protocol: "rdp", profile: bitmapOnly16, choice: domain.ScreenChoice{Channel: "graphics"}, wantErr: domain.ErrForbidden},
		{name: "a channel that does not exist", protocol: "rdp", choice: domain.ScreenChoice{Channel: "h264"}, wantErr: domain.ErrInvalidScreenChoice},
		{name: "a depth that does not exist", protocol: "rdp", choice: domain.ScreenChoice{ColorDepth: 24}, wantErr: domain.ErrInvalidScreenChoice},
		{name: "the Vault does not answer: no fallback to everything allowed", protocol: "rdp", screenErr: errors.New("vault down"), wantErr: domain.ErrUnavailable},
		{name: "a VNC session takes no choice", protocol: "vnc", choice: domain.ScreenChoice{Channel: "bitmap"}, wantErr: domain.ErrInvalidScreenChoice},
		{name: "a VNC session without a choice carries none", protocol: "vnc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vault, proxy, audit := &fakeVaultAuthorizer{}, &fakeProxyClient{}, &fakeAudit{}
			accounts := &fakeAccountLookup{protocol: tc.protocol, screenProfile: tc.profile, screenErr: tc.screenErr}
			broker := newTestBroker(&fakeAuthz{allowed: true}, vault, audit, accounts, proxy).WithRDP(true)
			sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", tc.protocol, "justification", "", 60)
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			_, _, _, _, err = broker.ConnectDetails(context.Background(), sess.ID, sess.RequestedBy, tc.choice)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ConnectDetails = %v, want %v", err, tc.wantErr)
				}
				if vault.calls != 0 || proxy.calls != 0 {
					t.Fatalf("refused, yet %d Vault scope(s) and %d proxy call(s)", vault.calls, proxy.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConnectDetails: %v", err)
			}
			if proxy.lastScreen != tc.want {
				t.Fatalf("the proxy was given %+v, want %+v", proxy.lastScreen, tc.want)
			}
			got := audit.details["session.connect"]
			if tc.want == (domain.ScreenChoice{}) {
				if got != nil {
					t.Fatalf("session.connect details %v, want none", got)
				}
				return
			}
			if got["screen_channel"] != tc.want.Channel || got["color_depth"] == "" {
				t.Fatalf("session.connect details %v, want the screen %+v on the record", got, tc.want)
			}
		})
	}
}
