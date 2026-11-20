package rdp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	xasn1 "github.com/go-krb5/x/encoding/asn1"
)

// Kerberos of ADR-0100, increment 1, without a KDC: the AP-REQ read by an acceptor written apart in
// this test, its AP-REP read back, and wrap tokens both ways, rotated or not; then what a target may
// not send. The tickets from a real KDC are TestKerberos_AgainstAnMITKDC's.

func testKey(t *testing.T, etype int32) types.EncryptionKey {
	t.Helper()
	et, err := crypto.GetEtype(etype)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, et.GetKeyByteSize())
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return types.EncryptionKey{KeyType: etype, KeyValue: key}
}

// testAcceptor is the target's side, written from RFC 4120 and 4121 apart from the client.
type testAcceptor struct {
	t          *testing.T
	sessionKey types.EncryptionKey
	subkey     *types.EncryptionKey // the acceptor's, when it sends one
	initiator  types.EncryptionKey  // the initiator's subkey, from the authenticator
	auth       types.Authenticator
	sendSeq    uint64
	recvSeq    uint64
}

func (a *testAcceptor) readAPReq(token []byte) messages.APReq {
	a.t.Helper()
	id, message, err := gssUnframe(token)
	if err != nil || id != gssTokenAPReq {
		a.t.Fatalf("the initial token: id 0x%04x, %v", id, err)
	}
	var apReq messages.APReq
	if err := apReq.Unmarshal(message); err != nil {
		a.t.Fatal(err)
	}
	if err := apReq.DecryptAuthenticator(a.sessionKey); err != nil {
		a.t.Fatalf("the authenticator: %v", err)
	}
	a.auth = apReq.Authenticator
	a.initiator = a.auth.SubKey
	a.recvSeq = uint64(a.auth.SeqNumber)
	return apReq
}

func (a *testAcceptor) apRep(withSubkey bool, ctime time.Time, cusec int) []byte {
	a.t.Helper()
	part := messages.EncAPRepPart{CTime: ctime, Cusec: cusec, SequenceNumber: 77}
	if withSubkey {
		key := testKey(a.t, a.sessionKey.KeyType)
		a.subkey, part.Subkey = &key, key
	}
	a.sendSeq = 77
	der, err := xasn1.Marshal(part)
	if err != nil {
		a.t.Fatal(err)
	}
	der = asn1tools.AddASNAppTag(der, asn1apptag.EncAPRepPart)
	enc, err := crypto.GetEncryptedData(der, a.sessionKey, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		a.t.Fatal(err)
	}
	rep, err := xasn1.Marshal(messages.APRep{PVNO: 5, MsgType: 15, EncPart: enc})
	if err != nil {
		a.t.Fatal(err)
	}
	return gssFrame(gssTokenAPRep, asn1tools.AddASNAppTag(rep, asn1apptag.APREP))
}

func (a *testAcceptor) key() (types.EncryptionKey, byte) {
	if a.subkey != nil {
		return *a.subkey, gssWrapAcceptorSubkey
	}
	return a.initiator, 0
}

// wrap is the acceptor's wrap token: sent by the acceptor, sealed, with ec filler bytes and rotated
// right by rrc bytes.
func (a *testAcceptor) wrap(plain []byte, ec, rrc int) []byte {
	a.t.Helper()
	key, keyFlag := a.key()
	header := make([]byte, 16)
	binary.BigEndian.PutUint16(header[0:2], 0x0504)
	header[2], header[3] = gssWrapSentByAcceptor|gssWrapSealed|keyFlag, 0xff
	binary.BigEndian.PutUint16(header[4:6], uint16(ec))
	binary.BigEndian.PutUint64(header[8:16], a.sendSeq)
	et, _ := crypto.GetEtype(key.KeyType)
	inner := append(append(append([]byte(nil), plain...), bytes.Repeat([]byte{0xff}, ec)...), header...)
	_, sealed, err := et.EncryptMessage(key.KeyValue, inner, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		a.t.Fatal(err)
	}
	if rrc > 0 {
		rrc %= len(sealed)
		sealed = append(sealed[len(sealed)-rrc:], sealed[:len(sealed)-rrc]...)
	}
	binary.BigEndian.PutUint16(header[6:8], uint16(rrc))
	a.sendSeq++
	return append(header, sealed...)
}

// unwrap opens the initiator's wrap token.
func (a *testAcceptor) unwrap(token []byte) []byte {
	a.t.Helper()
	key, keyFlag := a.key()
	header := token[:16]
	if binary.BigEndian.Uint16(header[0:2]) != 0x0504 || header[2] != gssWrapSealed|keyFlag || header[3] != 0xff ||
		binary.BigEndian.Uint64(header[8:16]) != a.recvSeq {
		a.t.Fatalf("the initiator's header % x", header)
	}
	et, _ := crypto.GetEtype(key.KeyType)
	plain, err := et.DecryptMessage(key.KeyValue, token[16:], keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		a.t.Fatalf("the initiator's token: %v", err)
	}
	if !bytes.Equal(plain[len(plain)-16:], header) {
		a.t.Fatal("the header inside")
	}
	a.recvSeq++
	return plain[:len(plain)-16]
}

func testTicket() messages.Ticket {
	return messages.Ticket{TktVNO: 5, Realm: "OPENBASTION.TEST", SName: types.NewPrincipalName(2, "TERMSRV/target.openbastion.test"),
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("ticket encrypted for the target")}}
}

func established(t *testing.T, etype int32, acceptorSubkey bool) (*kerberosContext, *testAcceptor) {
	t.Helper()
	acceptor := &testAcceptor{t: t, sessionKey: testKey(t, etype)}
	ctx, token, err := newKerberosContext("OPENBASTION.TEST", "operator", testTicket(), acceptor.sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	apReq := acceptor.readAPReq(token)
	if !types.IsFlagSet(&apReq.APOptions, flags.APOptionMutualRequired) {
		t.Fatal("mutual authentication not asked")
	}
	if err := ctx.acceptReply(acceptor.apRep(acceptorSubkey, acceptor.auth.CTime, acceptor.auth.Cusec)); err != nil {
		t.Fatal(err)
	}
	return ctx, acceptor
}

func TestKerberos_TheAPReqAsTheAcceptorReadsIt(t *testing.T) {
	acceptor := &testAcceptor{t: t, sessionKey: testKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)}
	_, token, err := newKerberosContext("OPENBASTION.TEST", "operator", testTicket(), acceptor.sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	// The GSS-API frame: application 0, the Kerberos 5 OID, token ID 01 00.
	if token[0] != 0x60 || !bytes.Contains(token[:20], []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01, 0x00}) {
		t.Fatalf("the frame % x", token[:20])
	}
	acceptor.readAPReq(token)
	auth := acceptor.auth
	// The GSS-API checksum (RFC 4121 §4.1.1): type 0x8003, Lgth 16, no channel binding, the flags
	// mutual, sequence, confidentiality and integrity; no delegation.
	if auth.Cksum.CksumType != chksumtype.GSSAPI || len(auth.Cksum.Checksum) != 24 ||
		binary.LittleEndian.Uint32(auth.Cksum.Checksum[0:4]) != 16 || !bytes.Equal(auth.Cksum.Checksum[4:20], make([]byte, 16)) ||
		binary.LittleEndian.Uint32(auth.Cksum.Checksum[20:24]) != 2|8|16|32 {
		t.Fatalf("the GSS-API checksum % x", auth.Cksum.Checksum)
	}
	if auth.SubKey.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 || len(auth.SubKey.KeyValue) != 32 || auth.CName.PrincipalNameString() != "operator" || auth.CRealm != "OPENBASTION.TEST" {
		t.Fatalf("the authenticator: %+v", auth)
	}
}

func TestKerberos_WrapTokensBothWays(t *testing.T) {
	for _, c := range []struct {
		name           string
		etype          int32
		acceptorSubkey bool
		ec, rrc        int
	}{
		{"AES256, the acceptor's subkey", etypeID.AES256_CTS_HMAC_SHA1_96, true, 0, 0},
		{"AES128, the initiator's subkey", etypeID.AES128_CTS_HMAC_SHA1_96, false, 0, 0},
		{"rotated by 28, as Windows may", etypeID.AES256_CTS_HMAC_SHA1_96, true, 0, 28},
		{"with filler", etypeID.AES256_CTS_HMAC_SHA1_96, true, 5, 0},
		{"rotated past the length", etypeID.AES256_CTS_HMAC_SHA1_96, false, 0, 1000},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, acceptor := established(t, c.etype, c.acceptorSubkey)
			for i, message := range []string{"pubKeyAuth", "authInfo, the credentials", ""} {
				sealed, err := ctx.wrap([]byte(message))
				if err != nil {
					t.Fatal(err)
				}
				if got := acceptor.unwrap(sealed); string(got) != message {
					t.Fatalf("message %d: the acceptor read %q", i, got)
				}
				back := acceptor.wrap([]byte("from the target "+message), c.ec, c.rrc)
				got, err := ctx.unwrap(back)
				if err != nil || string(got) != "from the target "+message {
					t.Fatalf("message %d back: %q, %v", i, got, err)
				}
			}
		})
	}
}

func TestKerberos_RefusesWhatATargetMayNotSend(t *testing.T) {
	// The reply.
	newCtx := func() (*kerberosContext, *testAcceptor) {
		acceptor := &testAcceptor{t: t, sessionKey: testKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)}
		ctx, token, err := newKerberosContext("OPENBASTION.TEST", "operator", testTicket(), acceptor.sessionKey)
		if err != nil {
			t.Fatal(err)
		}
		acceptor.readAPReq(token)
		return ctx, acceptor
	}
	ctx, acceptor := newCtx()
	kerr := messages.NewKRBError(types.NewPrincipalName(2, "TERMSRV/target"), "OPENBASTION.TEST", 41, "")
	krbErr, err := kerr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string][]byte{
		"a KRB-ERROR":         gssFrame(gssTokenError, krbErr),
		"an AP-REQ back":      gssFrame(gssTokenAPReq, []byte{0}),
		"another time":        acceptor.apRep(false, acceptor.auth.CTime.Add(time.Second), acceptor.auth.Cusec),
		"another microsecond": acceptor.apRep(false, acceptor.auth.CTime, acceptor.auth.Cusec+1),
		"not GSS-API":         {0x30, 0x00},
		"empty":               nil,
		"too long":            make([]byte, maxKerberosToken+1),
	} {
		if err := ctx.acceptReply(token); !errors.Is(err, ErrRDPKerberos) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ctx.acceptReply(gssFrame(gssTokenError, krbErr)); err == nil || !strings.Contains(err.Error(), "KRB-ERROR 41") {
		t.Errorf("the KRB-ERROR's code: %v", err)
	}
	// An AP-REP under another key; one with an RC4 subkey.
	ctx, acceptor = newCtx()
	right := acceptor.sessionKey
	acceptor.sessionKey = testKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err := ctx.acceptReply(acceptor.apRep(false, acceptor.auth.CTime, acceptor.auth.Cusec)); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("another key: %v", err)
	}
	acceptor.sessionKey = right
	part := messages.EncAPRepPart{CTime: acceptor.auth.CTime, Cusec: acceptor.auth.Cusec, Subkey: types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: make([]byte, 16)}}
	der, _ := xasn1.Marshal(part)
	enc, _ := crypto.GetEncryptedData(asn1tools.AddASNAppTag(der, asn1apptag.EncAPRepPart), right, keyusage.AP_REP_ENCPART, 0)
	rep, _ := xasn1.Marshal(messages.APRep{PVNO: 5, MsgType: 15, EncPart: enc})
	if err := ctx.acceptReply(gssFrame(gssTokenAPRep, asn1tools.AddASNAppTag(rep, asn1apptag.APREP))); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("an RC4 subkey: %v", err)
	}
	// No wrap before the reply; no second reply.
	if _, err := ctx.wrap([]byte("x")); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("a wrap before the reply: %v", err)
	}
	ctx, acceptor = established(t, etypeID.AES256_CTS_HMAC_SHA1_96, true)
	again := *acceptor // a second reply, made apart: the acceptor keeps its subkey
	if err := ctx.acceptReply(again.apRep(true, acceptor.auth.CTime, acceptor.auth.Cusec)); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("a second reply: %v", err)
	}
	// Wrap tokens: replayed, out of order, tampered, without the acceptor's flag.
	first := acceptor.wrap([]byte("one"), 0, 0)
	second := acceptor.wrap([]byte("two"), 0, 0)
	if _, err := ctx.unwrap(second); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("out of order: %v", err)
	}
	if _, err := ctx.unwrap(first); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.unwrap(first); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("replayed: %v", err)
	}
	tampered := append([]byte(nil), second...)
	tampered[len(tampered)-1] ^= 1
	if _, err := ctx.unwrap(tampered); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("tampered: %v", err)
	}
	ownFlag := append([]byte(nil), second...)
	ownFlag[2] &^= gssWrapSentByAcceptor
	if _, err := ctx.unwrap(ownFlag); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("not sent by the acceptor: %v", err)
	}
	header := append([]byte(nil), second...)
	header[3] = 0
	if _, err := ctx.unwrap(header); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("a filler byte other than FF: %v", err)
	}
	if _, err := ctx.unwrap(second); err != nil {
		t.Fatalf("the right token after the refusals: %v", err)
	}
	if _, err := ctx.unwrap(make([]byte, 15)); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("a short token: %v", err)
	}
}

func TestKerberos_TheConfigurationIsExplicit(t *testing.T) {
	good := KerberosConfig{Realm: "OPENBASTION.TEST", KDCs: []string{"kdc.openbastion.test:88"}, ServicePrincipal: "TERMSRV/target.openbastion.test"}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]KerberosConfig{
		"a lower-case realm":       {Realm: "openbastion.test", KDCs: good.KDCs, ServicePrincipal: good.ServicePrincipal},
		"no realm":                 {KDCs: good.KDCs, ServicePrincipal: good.ServicePrincipal},
		"no KDC":                   {Realm: good.Realm, ServicePrincipal: good.ServicePrincipal},
		"a KDC without a port":     {Realm: good.Realm, KDCs: []string{"kdc.openbastion.test"}, ServicePrincipal: good.ServicePrincipal},
		"five KDCs":                {Realm: good.Realm, KDCs: []string{"a:88", "b:88", "c:88", "d:88", "e:88"}, ServicePrincipal: good.ServicePrincipal},
		"another service":          {Realm: good.Realm, KDCs: good.KDCs, ServicePrincipal: "HTTP/target"},
		"a principal with a realm": {Realm: good.Realm, KDCs: good.KDCs, ServicePrincipal: "TERMSRV/target@OTHER.TEST"},
		"a negative timeout":       {Realm: good.Realm, KDCs: good.KDCs, ServicePrincipal: good.ServicePrincipal, Timeout: -1},
	} {
		if err := c.validate(); !errors.Is(err, ErrRDPKerberos) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The library's configuration: this realm and its KDCs only, no DNS, TCP, AES.
	cfg := good.libraryConfig()
	if cfg.LibDefaults.DNSLookupKDC || cfg.LibDefaults.DNSLookupRealm || cfg.LibDefaults.DNSCanonicalizeHostname ||
		cfg.LibDefaults.UDPPreferenceLimit != 1 || len(cfg.Realms) != 1 || cfg.Realms[0].KDC[0] != "kdc.openbastion.test:88" {
		t.Fatalf("the library's configuration: %+v", cfg.LibDefaults)
	}
	for _, id := range cfg.LibDefaults.PermittedEnctypeIDs {
		if !kerberosEtypes[id] {
			t.Fatalf("encryption type %d permitted", id)
		}
	}
	// A user is checked before any exchange: the tickets are never asked for.
	asked := false
	saved := kerberosTickets
	kerberosTickets = func(KerberosConfig, string, []byte) (messages.Ticket, types.EncryptionKey, error) {
		asked = true
		return messages.Ticket{}, types.EncryptionKey{}, nil
	}
	defer func() { kerberosTickets = saved }()
	for _, user := range []string{"", "op@OTHER.TEST", "op/admin"} {
		if _, _, err := kerberosInitiate(good, user, []byte("x")); !errors.Is(err, ErrRDPKerberos) {
			t.Errorf("user %q: %v", user, err)
		}
	}
	if _, _, err := kerberosInitiate(good, "operator", nil); !errors.Is(err, ErrRDPKerberos) || asked {
		t.Errorf("no password: %v, asked %v", err, asked)
	}
	// A session key of RC4, given by the KDC, is refused.
	kerberosTickets = func(KerberosConfig, string, []byte) (messages.Ticket, types.EncryptionKey, error) {
		return testTicket(), types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: make([]byte, 16)}, nil
	}
	if _, _, err := kerberosInitiate(good, "operator", []byte("x")); !errors.Is(err, ErrRDPKerberos) {
		t.Errorf("an RC4 session key: %v", err)
	}
}

func FuzzKerberosAcceptReplyAndUnwrap(f *testing.F) {
	f.Add(gssFrame(gssTokenAPRep, []byte{0x6f, 0x00}))
	f.Add([]byte{0x05, 0x04, 0x07, 0xff, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 77, 1, 2, 3})
	f.Fuzz(func(t *testing.T, token []byte) {
		key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
		ctx := &kerberosContext{sessionKey: key, subkey: key}
		if err := ctx.acceptReply(token); err != nil && !errors.Is(err, ErrRDPKerberos) {
			t.Fatalf("an error outside ErrRDPKerberos: %v", err)
		}
		open := &kerberosContext{sessionKey: key, subkey: key, established: true, recvSeq: 77}
		if _, err := open.unwrap(token); err != nil && !errors.Is(err, ErrRDPKerberos) {
			t.Fatalf("an error outside ErrRDPKerberos: %v", err)
		}
	})
}

func TestKerberos_TheKDCsErrorCode(t *testing.T) {
	for text, want := range map[string]int32{
		"[Root cause: KDC_Error] KDC_Error: AS Exchange Error: kerberos error response from KDC: KRB Error: (24) KDC_ERR_PREAUTH_FAILED": 24,
		"KRB Error: (6) KDC_ERR_C_PRINCIPAL_UNKNOWN": 6,
	} {
		if code, ok := kdcErrorCode(errors.New(text)); !ok || code != want {
			t.Errorf("%q: %d, %v", text, code, ok)
		}
	}
	for _, text := range []string{"no code here", "KRB Error: (24", "KRB Error: (abc)", "KRB Error: (123456)"} {
		if _, ok := kdcErrorCode(errors.New(text)); ok {
			t.Errorf("%q gave a code", text)
		}
	}
	kerr := messages.NewKRBError(types.NewPrincipalName(1, "x"), "R", 18, "")
	if code, ok := kdcErrorCode(fmt.Errorf("wrapped: %w", kerr)); !ok || code != 18 {
		t.Errorf("a wrapped KRBError: %d, %v", code, ok)
	}
}
