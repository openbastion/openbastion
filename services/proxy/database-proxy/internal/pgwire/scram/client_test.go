package scram

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestClientCompletesKnownExchange(t *testing.T) {
	client := newClientWithNonce("user", []byte("pencil"), "rOprNGfwEbeRWgbNEkqO")
	first, err := client.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if first != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("client first = %q", first)
	}

	serverFirst := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	final, err := client.Continue(serverFirst)
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if final != "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF,p=2Co9/7Q6ALsppyR+n1iwWmzVJJJ1zzcgLokVX3Qm5cs=" {
		t.Fatalf("client final = %q", final)
	}
	if err := client.VerifyServerFinal("v=8hijqPrqPCmSN/gl2kogo4dBQD8q6AB/l4k9skRkz1s="); err != nil {
		t.Fatalf("VerifyServerFinal: %v", err)
	}
}

func TestClientRejectsServerNonceNotBoundToClientNonce(t *testing.T) {
	client := newClientWithNonce("user", []byte("pencil"), "client-nonce")
	if _, err := client.Start(); err != nil {
		t.Fatal(err)
	}
	_, err := client.Continue("r=attacker-nonce,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096")
	if err == nil {
		t.Fatal("server nonce not bound to client nonce was accepted")
	}
}

func TestClientRejectsExcessiveIterationsBeforeExpensiveWork(t *testing.T) {
	client := newClientWithNonce("user", []byte("pencil"), "client-nonce")
	_, _ = client.Start()
	_, err := client.Continue("r=client-nonce-server,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=1000001")
	if err == nil {
		t.Fatal("excessive SCRAM iteration count was accepted")
	}
}

func TestClientRejectsUnsupportedMandatoryExtension(t *testing.T) {
	client := newClientWithNonce("user", []byte("pencil"), "client-nonce")
	_, _ = client.Start()
	_, err := client.Continue("m=unsupported,r=client-nonce-server,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096")
	if err == nil {
		t.Fatal("unsupported mandatory extension was accepted")
	}
}

func TestClientRejectsWrongServerSignature(t *testing.T) {
	client := newClientWithNonce("user", []byte("pencil"), "rOprNGfwEbeRWgbNEkqO")
	_, _ = client.Start()
	_, err := client.Continue("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyServerFinal("v=" + base64.StdEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("wrong server signature was accepted")
	}
}

func TestClientRejectsPasswordInServerErrorAndDoesNotEchoIt(t *testing.T) {
	secret := "do-not-echo-this-password"
	client := newClientWithNonce("user", []byte(secret), "client-nonce")
	_, _ = client.Start()
	_, err := client.Continue("e=invalid-proof")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v; it must fail without echoing the password", err)
	}
}

func TestPBKDF2SHA256KnownVector(t *testing.T) {
	got := base64.StdEncoding.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	const want = "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="
	if got != want {
		t.Fatalf("PBKDF2-SHA-256 = %q, want %q", got, want)
	}
}

func TestClientEscapesSASLUsername(t *testing.T) {
	client := newClientWithNonce("a,b=c", []byte("pencil"), "nonce")
	got, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	if got != "n,,n=a=2Cb=3Dc,r=nonce" {
		t.Fatalf("client first = %q", got)
	}
}

func TestClientRefusesPasswordThatNeedsSASLPrep(t *testing.T) {
	client := newClientWithNonce("user", []byte("pássword"), "nonce")
	if _, err := client.Start(); err == nil {
		t.Fatal("non-ASCII password was accepted without SASLprep")
	}
}
