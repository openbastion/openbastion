package hostkey_test

// ADR-0054: under an authority line, "@revoked" lines refuse a host key even when it is certified.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/hostkey"
)

func TestRevoked_ACertifiedButRevokedKeyIsRefused_TheOthersStillPass(t *testing.T) {
	ca, stolen, other := signer(t), signer(t), signer(t)
	line := "@cert-authority target.example " + line(ca.PublicKey()) + "\n@revoked target.example " + line(stolen.PublicKey())
	tr := trust(t, line)
	if tr.Revoked() != 1 {
		t.Fatalf("%d revoked keys read, want 1", tr.Revoked())
	}
	err := check(tr, certify(t, ca, stolen.PublicKey()))
	if !errors.Is(err, hostkey.ErrMismatch) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a valid certificate of a revoked key: %v, want a refusal that says revoked", err)
	}
	if err := check(tr, certify(t, ca, other.PublicKey())); err != nil {
		t.Fatalf("a certificate of a key that is not revoked: %v", err)
	}
}

func TestRevoked_NormalizedTheSameWayEveryTime(t *testing.T) {
	ca, a, b := signer(t), signer(t), signer(t)
	head := "@cert-authority Target.Example " + line(ca.PublicKey())
	one, fp1, err := hostkey.Normalize(head + "\n@revoked * " + line(b.PublicKey()) + "\r\n\n@revoked target.example " + line(a.PublicKey()) + " stolen 2026-10-31\n@revoked * " + line(a.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	two, fp2, err := hostkey.Normalize(head + "\n@revoked * " + line(a.PublicKey()) + "\n@revoked * " + line(b.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if one != two || strings.Count(one, "\n") != 2 || fp1 != fp2 || fp1 != ssh.FingerprintSHA256(ca.PublicKey()) {
		t.Fatalf("the same revocations, written two ways, normalize differently or lose the authority's fingerprint:\n%s\n---\n%s", one, two)
	}
	if again, _, _ := hostkey.Normalize(one); again != one {
		t.Fatal("a normalized line does not normalize to itself")
	}
}

func TestRevoked_WhatCannotMeanARevocationIsRefused(t *testing.T) {
	ca, host := signer(t), signer(t)
	auth := "@cert-authority target.example " + line(ca.PublicKey())
	rev := "@revoked * " + line(host.PublicKey())
	many := auth
	for i := 0; i <= hostkey.MaxRevoked; i++ {
		many += "\n@revoked * " + line(signer(t).PublicKey())
	}
	for name, bad := range map[string]string{
		"under a pinned key":                             line(host.PublicKey()) + "\n" + rev,
		"before the authority":                           rev + "\n" + auth,
		"for another name":                               auth + "\n@revoked other.example " + line(host.PublicKey()),
		"of the authority itself":                        auth + "\n@revoked * " + line(ca.PublicKey()),
		"of a certificate":                               auth + "\n@revoked * " + line(certify(t, ca, host.PublicKey())),
		"a key that does not read":                       auth + "\n@revoked * ssh-ed25519 not-a-key",
		"another marker":                                 auth + "\n@cert-authority other.example " + line(host.PublicKey()),
		"a plain key line":                               auth + "\n" + line(host.PublicKey()),
		fmt.Sprint(hostkey.MaxRevoked+1, " revocations"): many,
	} {
		if _, _, err := hostkey.Normalize(bad); !errors.Is(err, hostkey.ErrBadLine) {
			t.Fatalf("%s: %v, want ErrBadLine", name, err)
		}
	}
}

func TestRevoked_TheListIsWrittenInOneOrder_WhateverTheMapSays(t *testing.T) {
	ca := signer(t)
	in := "@cert-authority target.example " + line(ca.PublicKey())
	for i := 0; i < 10; i++ {
		in += "\n@revoked * " + line(signer(t).PublicKey())
	}
	first, _, err := hostkey.Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if again, _, _ := hostkey.Normalize(in); again != first {
			t.Fatal("the same revocations normalized twice came out in two orders")
		}
	}
	lines := strings.Split(first, "\n")[1:]
	for i := 1; i < len(lines); i++ {
		if lines[i-1] > lines[i] {
			t.Fatalf("the revocations are not sorted:\n%s", first)
		}
	}
}
