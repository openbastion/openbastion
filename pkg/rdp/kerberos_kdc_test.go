package rdp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Kerberos of ADR-0100, increment 1, against a real KDC: MIT krb5 in Docker
// (test/integration/testdata/kerberos/mit-kdc). The client obtains its tickets over TCP (AS, then
// TGS for TERMSRV/<target>), and an acceptor holding the service's key, as Windows would, verifies
// the AP-REQ (ticket and authenticator), answers it, and wrap tokens go both ways. A wrong
// password and an unknown service are refused. KERBEROS_INTEROP=1 runs it; Docker is needed.

const (
	kdcRealm   = "OPENBASTION.TEST"
	kdcService = "TERMSRV/target.openbastion.test"
)

func startMITKDC(t *testing.T, userPassword, servicePassword string) string {
	t.Helper()
	if os.Getenv("KERBEROS_INTEROP") == "" {
		t.Skip("KERBEROS_INTEROP not set: this test builds and starts a real KDC in Docker")
	}
	_, here, _, _ := runtime.Caller(0)
	context := filepath.Join(filepath.Dir(here), "..", "..", "test", "integration", "testdata", "kerberos", "mit-kdc")
	const image = "openbastion-test-mit-kdc:latest"
	if out, err := exec.Command("docker", "build", "-q", "-t", image, context).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	name := fmt.Sprintf("ob-kdc-%d", os.Getpid())
	args := []string{"run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::88",
		"-e", "KDC_REALM=" + kdcRealm, "-e", "KDC_USER=operator", "-e", "KDC_USER_PASSWORD=" + userPassword,
		"-e", "KDC_SERVICE=" + kdcService, "-e", "KDC_SERVICE_PASSWORD=" + servicePassword, image}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(logs), "kdc ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the KDC did not start:\n%s", logs)
		}
	}
	port, err := exec.Command("docker", "port", name, "88/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // krb5kdc listens just after the log line
	return strings.TrimSpace(strings.Split(string(port), "\n")[0])
}

func TestKerberos_AgainstAnMITKDC(t *testing.T) {
	userPassword, servicePassword := "Op-kerberos-1", "Svc-kerberos-2"
	kdc := startMITKDC(t, userPassword, servicePassword)
	cfg := KerberosConfig{Realm: kdcRealm, KDCs: []string{kdc}, ServicePrincipal: kdcService, Timeout: 10 * time.Second}
	ctx, token, err := kerberosInitiate(cfg, "operator", []byte(userPassword))
	if err != nil {
		t.Fatalf("the tickets from the KDC: %v", err)
	}
	// The target's side: its key, from its password, as its keytab would hold it.
	kt := keytab.New()
	for _, etype := range []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96} {
		if err := kt.AddEntry(kdcService, kdcRealm, servicePassword, time.Now(), 1, etype); err != nil {
			t.Fatal(err)
		}
	}
	id, message, err := gssUnframe(token)
	if err != nil || id != gssTokenAPReq {
		t.Fatalf("the initial token: %v", err)
	}
	acceptor := &testAcceptor{t: t}
	apReq := acceptor.readAPReqWith(message, kt)
	t.Logf("ticket for %s from %s, session key of type %d, subkey of type %d",
		apReq.Ticket.SName.PrincipalNameString(), apReq.Ticket.Realm, acceptor.sessionKey.KeyType, acceptor.initiator.KeyType)
	if err := ctx.acceptReply(acceptor.apRep(true, acceptor.auth.CTime, acceptor.auth.Cusec)); err != nil {
		t.Fatal(err)
	}
	sealed, err := ctx.wrap([]byte("pubKeyAuth"))
	if err != nil || string(acceptor.unwrap(sealed)) != "pubKeyAuth" {
		t.Fatalf("the initiator's wrap: %v", err)
	}
	if got, err := ctx.unwrap(acceptor.wrap([]byte("the target's"), 0, 28)); err != nil || string(got) != "the target's" {
		t.Fatalf("the acceptor's wrap: %q, %v", got, err)
	}
	// A wrong password: the AS exchange is refused; an unknown service: the TGS exchange.
	// A wrong password, an unknown user: refused credentials, as NTLM's are (target_auth_failed).
	if _, _, err := kerberosInitiate(cfg, "operator", []byte("wrong")); !errors.Is(err, ErrTargetCredentialsRefused) || !strings.Contains(err.Error(), "AS exchange") {
		t.Errorf("a wrong password: %v", err)
	}
	if _, _, err := kerberosInitiate(cfg, "nobody", []byte(userPassword)); !errors.Is(err, ErrTargetCredentialsRefused) {
		t.Errorf("an unknown user: %v", err)
	}
	other := cfg
	other.ServicePrincipal = "TERMSRV/unknown.openbastion.test"
	if _, _, err := kerberosInitiate(other, "operator", []byte(userPassword)); !errors.Is(err, ErrRDPKerberos) || !strings.Contains(err.Error(), "TGS exchange") {
		t.Errorf("an unknown service: %v", err)
	}
}

// readAPReqWith reads the AP-REQ as a target holding kt: the ticket decrypted with the service's key,
// the authenticator with the session key in it, both checked by the library's acceptor.
func (a *testAcceptor) readAPReqWith(message []byte, kt *keytab.Keytab) messages.APReq {
	a.t.Helper()
	var apReq messages.APReq
	if err := apReq.Unmarshal(message); err != nil {
		a.t.Fatal(err)
	}
	ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
	if err != nil || !ok {
		a.t.Fatalf("the target refuses the AP-REQ: %v", err)
	}
	a.sessionKey = apReq.Ticket.DecryptedEncPart.Key
	a.auth = apReq.Authenticator
	a.initiator = a.auth.SubKey
	a.recvSeq = uint64(a.auth.SeqNumber)
	return apReq
}
