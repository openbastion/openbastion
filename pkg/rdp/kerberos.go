package rdp

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Kerberos for CredSSP (ADR-0100), increment 1: the tickets, the GSS-API context and its wrap
// tokens. github.com/go-krb5/krb5 v0.1.0 (the owner's choice, 13 November 2026) obtains the tickets
// (AS and TGS) and does the RFC 3961/3962 cryptography; the GSS-API framing (RFC 1964 §1.1, RFC
// 4121 §4.1), the authenticator's checksum, the AP-REP check and the wrap tokens (RFC 4121 §4.2.6.2)
// are this package's, under its bounds, as NTLM is.
//
// The KDCs and the realm come from the privileged account, held by the Vault with it, never from the
// operator: the configuration is explicit, the KDC reached over TCP only, with no DNS discovery and
// no hostname canonicalization. Only AES (RFC 3962) is accepted: RC4 and DES are refused. The
// password serves the AS-REQ alone; the library holds it as a string, which this package cannot
// clear (ADR-0115's limit on Go strings), and drops it with the client once the tickets are had.

// ErrRDPKerberos reports a Kerberos exchange, ticket or token outside what this client accepts.
var ErrRDPKerberos = errors.New("rdp: Kerberos refused")

// KerberosConfig is where and for what a Kerberos context is made: the realm, its KDCs (host:port),
// and the service principal of the target, TERMSRV/<host>.
type KerberosConfig struct {
	Realm            string
	KDCs             []string
	ServicePrincipal string
	Timeout          time.Duration
}

const (
	maxKerberosKDCs = 4
	// maxKerberosToken bounds a GSS-API token or a wrap token read from the target.
	maxKerberosToken = 64 << 10

	gssTokenAPReq  = uint16(0x0100)
	gssTokenAPRep  = uint16(0x0200)
	gssTokenError  = uint16(0x0300)
	gssWrapTokenID = uint16(0x0504)

	gssWrapSentByAcceptor = byte(0x01)
	gssWrapSealed         = byte(0x02)
	gssWrapAcceptorSubkey = byte(0x04)
	gssWrapHeaderSize     = 16

	// The context flags asked for (RFC 4121 §4.1.1.1): mutual authentication, sequencing,
	// confidentiality and integrity. Delegation is never asked: the secret stays with the proxy.
	gssFlags = uint32(2 | 8 | 16 | 32)
)

// oidKerberos5 is the Kerberos 5 GSS-API mechanism, 1.2.840.113554.1.2.2.
var oidKerberos5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// kerberosCredentialsRefused are the KDC's errors that refuse the account's credentials (RFC 4120
// §7.5.9): a wrong password (PREAUTH_FAILED), an unknown, revoked or expired account.
var kerberosCredentialsRefused = map[int32]bool{
	errorcode.KDC_ERR_PREAUTH_FAILED: true, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN: true,
	errorcode.KDC_ERR_CLIENT_REVOKED: true, errorcode.KDC_ERR_KEY_EXPIRED: true,
}

// kdcErrorCode is the KDC's error code in the library's error. The library flattens a KRB-ERROR into
// its text ("KRB Error: (24) ..."): the code is read there, the only place left. A message of
// another shape gives no code, and the refusal stays a plain Kerberos one.
func kdcErrorCode(err error) (int32, bool) {
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		return krbErr.ErrorCode, true
	}
	text := err.Error()
	i := strings.Index(text, "KRB Error: (")
	if i < 0 {
		return 0, false
	}
	rest := text[i+len("KRB Error: ("):]
	j := strings.IndexByte(rest, ')')
	if j <= 0 || j > 4 {
		return 0, false
	}
	code, convErr := strconv.Atoi(rest[:j])
	if convErr != nil {
		return 0, false
	}
	return int32(code), true
}

// kerberosEtypes are the encryption types accepted, AES only (RFC 3962).
var kerberosEtypes = map[int32]bool{etypeID.AES256_CTS_HMAC_SHA1_96: true, etypeID.AES128_CTS_HMAC_SHA1_96: true}

func kerberosRefused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRDPKerberos}, args...)...)
}

// validate checks the configuration before anything is sent.
func (c KerberosConfig) validate() error {
	if c.Realm == "" || len(c.Realm) > 255 || strings.ToUpper(c.Realm) != c.Realm || strings.ContainsAny(c.Realm, " \t\r\n/@") {
		return kerberosRefused("realm %q", c.Realm)
	}
	if len(c.KDCs) == 0 || len(c.KDCs) > maxKerberosKDCs {
		return kerberosRefused("%d KDC(s)", len(c.KDCs))
	}
	for _, kdc := range c.KDCs {
		host, port, err := net.SplitHostPort(kdc)
		if err != nil || host == "" || port == "" {
			return kerberosRefused("KDC %q is not host:port", kdc)
		}
	}
	parts := strings.Split(c.ServicePrincipal, "/")
	if len(parts) != 2 || parts[0] != "TERMSRV" || parts[1] == "" || strings.ContainsAny(parts[1], " @\t\r\n") {
		return kerberosRefused("service principal %q is not TERMSRV/<host>", c.ServicePrincipal)
	}
	if c.Timeout < 0 {
		return kerberosRefused("a negative timeout")
	}
	return nil
}

// libraryConfig is the library's configuration for one realm, built from c alone: no krb5.conf, no
// DNS, TCP, AES.
func (c KerberosConfig) libraryConfig() *config.Config {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = c.Realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.DNSCanonicalizeHostname = false
	cfg.LibDefaults.RDNS = false
	cfg.LibDefaults.UDPPreferenceLimit = 1 // every request over TCP
	aes := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}
	cfg.LibDefaults.DefaultTktEnctypeIDs = aes
	cfg.LibDefaults.DefaultTGSEnctypeIDs = aes
	cfg.LibDefaults.PermittedEnctypeIDs = aes
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	cfg.LibDefaults.DefaultTGSEnctypes = cfg.LibDefaults.DefaultTktEnctypes
	cfg.LibDefaults.PermittedEnctypes = cfg.LibDefaults.DefaultTktEnctypes
	cfg.Realms = []config.Realm{{Realm: c.Realm, KDC: append([]string(nil), c.KDCs...)}}
	return cfg
}

// kerberosContext is the GSS-API context of one CredSSP exchange, as initiator.
type kerberosContext struct {
	sessionKey     types.EncryptionKey
	subkey         types.EncryptionKey // the initiator's, from the authenticator
	acceptorSubkey *types.EncryptionKey
	ctime          time.Time
	cusec          int
	sendSeq        uint64
	recvSeq        uint64
	established    bool
}

// kerberosTickets obtains a service ticket for cfg.ServicePrincipal, as user of cfg.Realm with
// password: the AS exchange, then the TGS exchange, with the library.
var kerberosTickets = func(cfg KerberosConfig, user string, password []byte) (messages.Ticket, types.EncryptionKey, error) {
	cl := client.NewWithPassword(user, cfg.Realm, string(password), cfg.libraryConfig(), client.DisablePAFXFAST(true))
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		// The KDC refusing the account's credentials is said as NTLM's refusal is
		// (ErrTargetCredentialsRefused, target_auth_failed): the secret in the Vault is to be checked.
		if code, ok := kdcErrorCode(err); ok && kerberosCredentialsRefused[code] {
			return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("%w: %w: the AS exchange: KDC error %d",
				ErrRDPKerberos, ErrTargetCredentialsRefused, code)
		}
		return messages.Ticket{}, types.EncryptionKey{}, kerberosRefused("the AS exchange: %v", err)
	}
	ticket, key, err := cl.GetServiceTicket(cfg.ServicePrincipal)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, kerberosRefused("the TGS exchange: %v", err)
	}
	return ticket, key, nil
}

// kerberosInitiate obtains the tickets and returns the context and the initial context token: an
// AP-REQ asking for mutual authentication, with a subkey and a sequence number, framed for GSS-API.
func kerberosInitiate(cfg KerberosConfig, user string, password []byte) (*kerberosContext, []byte, error) {
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	// The user is a name in cfg.Realm alone: a DOMAIN\user or user@realm would ask the KDC for
	// another principal than the account names.
	if user == "" || strings.ContainsAny(user, "@/\\ \t\r\n") || len(password) == 0 {
		return nil, nil, kerberosRefused("an empty or malformed user")
	}
	ticket, sessionKey, err := kerberosTickets(cfg, user, password)
	if err != nil {
		return nil, nil, err
	}
	if !kerberosEtypes[sessionKey.KeyType] {
		return nil, nil, kerberosRefused("a session key of encryption type %d", sessionKey.KeyType)
	}
	return newKerberosContext(cfg.Realm, user, ticket, sessionKey)
}

// newKerberosContext builds the AP-REQ for ticket and its session key.
func newKerberosContext(realm, user string, ticket messages.Ticket, sessionKey types.EncryptionKey) (*kerberosContext, []byte, error) {
	auth, err := types.NewAuthenticator(realm, types.NewPrincipalName(1, user))
	if err != nil {
		return nil, nil, kerberosRefused("an authenticator: %v", err)
	}
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, nil, kerberosRefused("encryption type %d: %v", sessionKey.KeyType, err)
	}
	if err := auth.GenerateSeqNumberAndSubKey(sessionKey.KeyType, et.GetKeyByteSize()); err != nil {
		return nil, nil, kerberosRefused("a subkey: %v", err)
	}
	// The GSS-API checksum (RFC 4121 §4.1.1): Lgth 16, a zero channel binding, the flags.
	checksum := make([]byte, 24)
	binary.LittleEndian.PutUint32(checksum[0:4], 16)
	binary.LittleEndian.PutUint32(checksum[20:24], gssFlags)
	auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
	apReq, err := messages.NewAPReq(ticket, sessionKey, auth)
	if err != nil {
		return nil, nil, kerberosRefused("the AP-REQ: %v", err)
	}
	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)
	der, err := apReq.Marshal()
	if err != nil {
		return nil, nil, kerberosRefused("the AP-REQ: %v", err)
	}
	ctx := &kerberosContext{sessionKey: sessionKey, subkey: auth.SubKey, ctime: auth.CTime, cusec: auth.Cusec, sendSeq: uint64(auth.SeqNumber)}
	return ctx, gssFrame(gssTokenAPReq, der), nil
}

// gssFrame frames a Kerberos message as a GSS-API token (RFC 1964 §1.1, RFC 2743 §3.1): the
// application tag 0, the mechanism OID, the two-byte token ID, the message.
func gssFrame(tokenID uint16, message []byte) []byte {
	oid, _ := asn1.Marshal(oidKerberos5)
	inner := append(append(oid, byte(tokenID>>8), byte(tokenID)), message...)
	raw, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: inner})
	return raw
}

// gssUnframe reads a GSS-API token of the Kerberos 5 mechanism: its token ID and message.
func gssUnframe(token []byte) (uint16, []byte, error) {
	if len(token) == 0 || len(token) > maxKerberosToken {
		return 0, nil, kerberosRefused("a token of %d bytes", len(token))
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(token, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassApplication || outer.Tag != 0 || !outer.IsCompound {
		return 0, nil, kerberosRefused("not a GSS-API token")
	}
	var oid asn1.ObjectIdentifier
	body, err := asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil || !oid.Equal(oidKerberos5) || len(body) < 2 {
		return 0, nil, kerberosRefused("a token of another mechanism")
	}
	return binary.BigEndian.Uint16(body[0:2]), body[2:], nil
}

// acceptReply reads the target's answer to the AP-REQ (RFC 4121 §4.1): an AP-REP whose encrypted
// part, under the session key, repeats the authenticator's time, and may carry the acceptor's
// subkey and sequence number. A KRB-ERROR is refused with its code.
func (k *kerberosContext) acceptReply(token []byte) error {
	if k == nil || k.established {
		return kerberosRefused("a reply to no AP-REQ, or a second one")
	}
	tokenID, message, err := gssUnframe(token)
	if err != nil {
		return err
	}
	switch tokenID {
	case gssTokenError:
		var krbErr messages.KRBError
		if krbErr.Unmarshal(message) != nil {
			return kerberosRefused("a malformed KRB-ERROR")
		}
		return kerberosRefused("the target answered KRB-ERROR %d", krbErr.ErrorCode)
	case gssTokenAPRep:
	default:
		return kerberosRefused("token ID 0x%04x", tokenID)
	}
	var apRep messages.APRep
	if err := apRep.Unmarshal(message); err != nil {
		return kerberosRefused("a malformed AP-REP")
	}
	plain, err := kerberosDecrypt(k.sessionKey, apRep.EncPart.Cipher, keyusage.AP_REP_ENCPART, 0)
	if err != nil || apRep.EncPart.EType != k.sessionKey.KeyType {
		return kerberosRefused("the AP-REP does not decrypt under the session key")
	}
	var part messages.EncAPRepPart
	if err := part.Unmarshal(plain); err != nil {
		return kerberosRefused("a malformed AP-REP part")
	}
	if !part.CTime.Equal(k.ctime.Truncate(time.Second)) || part.Cusec != k.cusec {
		return kerberosRefused("the AP-REP does not repeat the authenticator's time")
	}
	if len(part.Subkey.KeyValue) > 0 {
		if !kerberosEtypes[part.Subkey.KeyType] {
			return kerberosRefused("an acceptor subkey of encryption type %d", part.Subkey.KeyType)
		}
		subkey := part.Subkey
		k.acceptorSubkey = &subkey
	}
	k.recvSeq = uint64(part.SequenceNumber)
	k.established = true
	return nil
}

// wrapKey is the key of the wrap tokens (RFC 4121 §2): the acceptor's subkey when it sent one,
// else the initiator's.
func (k *kerberosContext) wrapKey() (types.EncryptionKey, byte) {
	if k.acceptorSubkey != nil {
		return *k.acceptorSubkey, gssWrapAcceptorSubkey
	}
	return k.subkey, 0
}

// wrap seals plain into a wrap token (RFC 4121 §4.2.6.2): the header, then plain and a copy of the
// header encrypted together, with no rotation and no filler (AES needs none).
func (k *kerberosContext) wrap(plain []byte) ([]byte, error) {
	if k == nil || !k.established {
		return nil, kerberosRefused("a wrap before the context is established")
	}
	key, keyFlag := k.wrapKey()
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, kerberosRefused("encryption type %d", key.KeyType)
	}
	header := make([]byte, gssWrapHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], gssWrapTokenID)
	header[2] = gssWrapSealed | keyFlag
	header[3] = 0xff
	// EC (header[4:6]) and RRC (header[6:8]) are 0.
	binary.BigEndian.PutUint64(header[8:16], k.sendSeq)
	_, sealed, err := et.EncryptMessage(key.KeyValue, append(append([]byte(nil), plain...), header...), keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, kerberosRefused("sealing: %v", err)
	}
	k.sendSeq++
	return append(header, sealed...), nil
}

// unwrap opens a wrap token from the target (RFC 4121 §4.2.6.2): sent by the acceptor, sealed,
// under the key the context agreed on, with the sequence number expected next. A rotation (RRC) is
// undone; the header inside must be the one outside, its RRC 0.
func (k *kerberosContext) unwrap(token []byte) ([]byte, error) {
	if k == nil || !k.established {
		return nil, kerberosRefused("an unwrap before the context is established")
	}
	if len(token) < gssWrapHeaderSize || len(token) > maxKerberosToken {
		return nil, kerberosRefused("a wrap token of %d bytes", len(token))
	}
	header := token[:gssWrapHeaderSize]
	key, keyFlag := k.wrapKey()
	if binary.BigEndian.Uint16(header[0:2]) != gssWrapTokenID || header[2] != gssWrapSentByAcceptor|gssWrapSealed|keyFlag || header[3] != 0xff {
		return nil, kerberosRefused("a wrap token's header % x", header[:4])
	}
	ec, rrc := int(binary.BigEndian.Uint16(header[4:6])), int(binary.BigEndian.Uint16(header[6:8]))
	if seq := binary.BigEndian.Uint64(header[8:16]); seq != k.recvSeq {
		return nil, kerberosRefused("sequence number %d, %d expected", seq, k.recvSeq)
	}
	body := append([]byte(nil), token[gssWrapHeaderSize:]...)
	if len(body) == 0 {
		return nil, kerberosRefused("an empty wrap token")
	}
	// Undo the right rotation by RRC bytes (RFC 4121 §4.2.5).
	if rrc %= len(body); rrc > 0 {
		body = append(body[rrc:], body[:rrc]...)
	}
	plain, err := kerberosDecrypt(key, body, keyusage.GSSAPI_ACCEPTOR_SEAL, gssWrapHeaderSize)
	if err != nil {
		return nil, kerberosRefused("the wrap token does not decrypt")
	}
	if len(plain) < ec+gssWrapHeaderSize {
		return nil, kerberosRefused("a wrap token shorter than its filler and header")
	}
	inner := plain[len(plain)-gssWrapHeaderSize:]
	expected := append([]byte(nil), header...)
	expected[6], expected[7] = 0, 0
	if !bytes.Equal(inner, expected) {
		return nil, kerberosRefused("the header inside is not the header outside")
	}
	k.recvSeq++
	return plain[:len(plain)-gssWrapHeaderSize-ec], nil
}

// kerberosDecrypt decrypts ciphertext with key for usage, after checking it holds at least the
// confounder, the HMAC and minimum plaintext bytes: the library's DecryptMessage panics on a shorter
// one (found by FuzzKerberosAcceptReplyAndUnwrap). A panic left in the library is turned into a
// refusal all the same: what the target sends never takes the proxy down.
func kerberosDecrypt(key types.EncryptionKey, ciphertext []byte, usage uint32, minimum int) (plain []byte, err error) {
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil || !kerberosEtypes[key.KeyType] {
		return nil, kerberosRefused("encryption type %d", key.KeyType)
	}
	if len(ciphertext) < et.GetConfounderByteSize()+et.GetHMACBitLength()/8+minimum {
		return nil, kerberosRefused("a ciphertext of %d bytes", len(ciphertext))
	}
	defer func() {
		if recover() != nil {
			plain, err = nil, kerberosRefused("a ciphertext the library could not read")
		}
	}()
	plain, err = et.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, kerberosRefused("the ciphertext does not decrypt")
	}
	return plain, nil
}

const (
	gssMICTokenID    = uint16(0x0404)
	gssMICHeaderSize = 16
)

// micHeader is the header of a MIC token (RFC 4121 §4.2.6.1): its ID, flags, five filler bytes and
// the sequence number.
func micHeader(flags byte, seq uint64) []byte {
	header := make([]byte, gssMICHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], gssMICTokenID)
	header[2] = flags
	for i := 3; i < 8; i++ {
		header[i] = 0xff
	}
	binary.BigEndian.PutUint64(header[8:16], seq)
	return header
}

// getMIC signs data (RFC 4121 §4.2.6.1): the checksum of data then the header, under the wrap key,
// at the next sequence number of this direction, which wrap tokens share.
func (k *kerberosContext) getMIC(data []byte) ([]byte, error) {
	if k == nil || !k.established {
		return nil, kerberosRefused("a MIC before the context is established")
	}
	key, keyFlag := k.wrapKey()
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, kerberosRefused("encryption type %d", key.KeyType)
	}
	header := micHeader(keyFlag, k.sendSeq)
	sum, err := et.GetChecksumHash(key.KeyValue, append(append([]byte(nil), data...), header...), keyusage.GSSAPI_INITIATOR_SIGN)
	if err != nil {
		return nil, kerberosRefused("signing: %v", err)
	}
	k.sendSeq++
	return append(header, sum...), nil
}

// verifyMIC checks the target's MIC token over data: sent by the acceptor, under the agreed key, at
// the sequence number expected next.
func (k *kerberosContext) verifyMIC(data, token []byte) error {
	if k == nil || !k.established {
		return kerberosRefused("a MIC before the context is established")
	}
	key, keyFlag := k.wrapKey()
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return kerberosRefused("encryption type %d", key.KeyType)
	}
	if len(token) != gssMICHeaderSize+et.GetHMACBitLength()/8 {
		return kerberosRefused("a MIC token of %d bytes", len(token))
	}
	header := token[:gssMICHeaderSize]
	if !bytes.Equal(header, micHeader(gssWrapSentByAcceptor|keyFlag, k.recvSeq)) {
		return kerberosRefused("a MIC token's header % x, sequence %d expected", header, k.recvSeq)
	}
	if !et.VerifyChecksum(key.KeyValue, append(append([]byte(nil), data...), header...), token[gssMICHeaderSize:], keyusage.GSSAPI_ACCEPTOR_SIGN) {
		return kerberosRefused("a MIC that does not verify")
	}
	k.recvSeq++
	return nil
}

// close forgets the keys.
func (k *kerberosContext) close() {
	if k == nil {
		return
	}
	clear(k.sessionKey.KeyValue)
	clear(k.subkey.KeyValue)
	if k.acceptorSubkey != nil {
		clear(k.acceptorSubkey.KeyValue)
	}
	k.established = false
}

// kerberosSecurity is the Kerberos context as CredSSP uses a security context: pubKeyAuth and
// authInfo wrapped, the target's wrap tokens opened, SPNEGO's mechListMIC checked.
type kerberosSecurity struct{ ctx *kerberosContext }

func (s kerberosSecurity) WrapClientToServer(plain []byte) ([]byte, error) { return s.ctx.wrap(plain) }
func (s kerberosSecurity) UnwrapServerToClient(token []byte) ([]byte, error) {
	return s.ctx.unwrap(token)
}
func (s kerberosSecurity) VerifyMechListMIC(mechTypes, mic []byte) error {
	return s.ctx.verifyMIC(mechTypes, mic)
}
func (s kerberosSecurity) Close() { s.ctx.close() }
