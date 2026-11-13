package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/vnc"
)

// The clipboard of an RDP session, in the engine (ADR-0096, increment 3b): opened only with
// SCREEN_CLIPBOARD and a right, the texts copied on the target handed to the relay, the operator's
// offered to the target.

type clipboardDesktop struct {
	fakeRDPDesktop
	copied  chan string
	offered []string
}

func (d *clipboardDesktop) copiedTexts() <-chan string { return d.copied }
func (d *clipboardDesktop) offerClipboardText(_ context.Context, text string) error {
	d.offered = append(d.offered, text)
	return nil
}

func TestRDPCodec_TheClipboardOpensOnlyWithTheSwitchAndARight(t *testing.T) {
	for name, c := range map[string]struct {
		on       bool
		to, from bool
		want     rdpClipboardRights
		viaOpen  bool
	}{
		"switch off":         {false, true, true, rdpClipboardRights{}, false},
		"switch on, both":    {true, true, true, rdpClipboardRights{true, true}, false},
		"switch on, to only": {true, true, false, rdpClipboardRights{toTarget: true}, false},
		"switch on, Open":    {true, true, true, rdpClipboardRights{}, true},
	} {
		var got *rdpClipboardRights
		codec := &RDPCodec{TLSRoots: x509.NewCertPool(), Clipboard: c.on,
			openSessionWith: func(_ context.Context, _ *proxycore.Credential, rights rdpClipboardRights) (rdpScreenSession, error) {
				got = &rights
				return &fakeRDPDesktop{width: 2, height: 1}, nil
			}}
		var session proxycore.ScreenSession
		var err error
		if c.viaOpen {
			session, err = codec.Open(context.Background(), rdpTestCredential(t))
		} else {
			session, err = codec.OpenWithClipboard(context.Background(), rdpTestCredential(t), c.to, c.from)
		}
		if err != nil || got == nil || *got != c.want {
			t.Fatalf("%s: opened with %+v (%v), want %+v", name, got, err, c.want)
		}
		_ = session.Close()
	}
}

func TestRDPSession_HandsOnTheClipboard(t *testing.T) {
	desktop := &clipboardDesktop{fakeRDPDesktop: fakeRDPDesktop{width: 2, height: 1}, copied: make(chan string, 1)}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), Clipboard: true,
		openSessionWith: func(context.Context, *proxycore.Credential, rdpClipboardRights) (rdpScreenSession, error) {
			return desktop, nil
		}}
	opened, err := codec.OpenWithClipboard(context.Background(), rdpTestCredential(t), true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	session := opened.(proxycore.ClipboardSession)
	desktop.copied <- "copied"
	if text := <-session.ClipboardTexts(); text != "copied" {
		t.Fatalf("relay got %q", text)
	}
	if err := session.OfferClipboardText("pasted"); err != nil || len(desktop.offered) != 1 || desktop.offered[0] != "pasted" {
		t.Fatalf("offered %q, %v", desktop.offered, err)
	}
	// A target whose clipboard cannot open: no texts, and an offer refused.
	plain, err := (&RDPCodec{TLSRoots: x509.NewCertPool(),
		openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
			return &fakeRDPDesktop{width: 2, height: 1}, nil
		}}).
		Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	clip := plain.(proxycore.ClipboardSession)
	if clip.ClipboardTexts() != nil || !errors.Is(clip.OfferClipboardText("x"), rdp.ErrRDPClipboard) {
		t.Fatal("a session without a clipboard offered one")
	}
}

// A text past the waiting bound is dropped, counted, and never holds up the reader.
func TestRDPTarget_ACopiedTextPastTheBoundIsDropped(t *testing.T) {
	target := &rdpTargetSession{copied: make(chan string, rdpCopiedTextsWaiting)}
	for i := 0; i < rdpCopiedTextsWaiting+2; i++ {
		if err := target.clipboardCopied("t"); err != nil {
			t.Fatal(err)
		}
	}
	if len(target.copied) != rdpCopiedTextsWaiting || target.copiedDropped != 2 {
		t.Fatalf("%d waiting, %d dropped", len(target.copied), target.copiedDropped)
	}
}

// A target refusing the account's credentials ends the opening as target_auth_failed, RDP as VNC
// (ADR-0071 §12); other failures keep their codes.
func TestScreenCodecs_ACredentialRefusalHasItsOwnCode(t *testing.T) {
	refused := fmt.Errorf("%w: %w (NTSTATUS 0xC000006D)", rdp.ErrCredSSPClient, rdp.ErrTargetCredentialsRefused)
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return nil, refused }}
	_, err := codec.Open(context.Background(), rdpTestCredential(t))
	var failure *proxycore.ScreenFailure
	if !errors.As(err, &failure) || failure.Code != "target_auth_failed" {
		t.Fatalf("RDP: %v", err)
	}
	other := &RDPCodec{TLSRoots: x509.NewCertPool(), openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) {
		return nil, fmt.Errorf("%w (NTSTATUS 0xC0000022)", rdp.ErrCredSSPClient)
	}}
	if _, err := other.Open(context.Background(), rdpTestCredential(t)); !errors.As(err, &failure) || failure.Code != "target_unreachable" {
		t.Fatalf("RDP, another status: %v", err)
	}
	if got := vncEndCode(fmt.Errorf("handshake: %w", vnc.ErrAuthentication)); got != "target_auth_failed" {
		t.Fatalf("VNC: %s", got)
	}
}
