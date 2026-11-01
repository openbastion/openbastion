package integration_test

// ADR-0065 across real processes, with a software authenticator written here, apart from the
// verifier (its own CBOR, its own signatures): a strict role enrolls a security key with an
// administrator's code and logs in only with it; what phishing would send — another origin,
// another relying party — is refused, as are a wrong signature, a key of no one, a counter that
// goes back, a replayed challenge, and TOTP for a strict role.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

// cbor encodes the few CBOR items an attestation needs: unsigned and negative integers, byte and
// text strings, and maps (canonical: keys sorted by their encoding).
func cbor(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 256:
			return []byte{major<<5 | 24, byte(n)}
		case n < 65536:
			return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
		default:
			b := []byte{major<<5 | 26, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(b[1:], uint32(n))
			return b
		}
	}
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return head(0, uint64(x))
		}
		return head(1, uint64(-1-x))
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case string:
		return append(head(3, uint64(len(x))), x...)
	case map[any]any:
		var items [][2][]byte
		for k, val := range x {
			items = append(items, [2][]byte{cbor(k), cbor(val)})
		}
		sort.Slice(items, func(i, j int) bool {
			a, b := items[i][0], items[j][0]
			if len(a) != len(b) {
				return len(a) < len(b)
			}
			return bytes.Compare(a, b) < 0
		})
		out := head(5, uint64(len(items)))
		for _, it := range items {
			out = append(append(out, it[0]...), it[1]...)
		}
		return out
	}
	panic(fmt.Sprintf("cbor: %T", v))
}

// softKey is a security key: an ES256 key pair, its credential ID and its counter.
type softKey struct {
	priv    *ecdsa.PrivateKey
	id      []byte
	counter uint32
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{priv: priv, id: id}
}

func rpHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

func clientData(kind, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// create answers navigator.credentials.create for options, as the browser at origin would.
func (k *softKey) create(t *testing.T, options any, origin string) map[string]any {
	t.Helper()
	pk := options.(map[string]any)["publicKey"].(map[string]any)
	challenge := pk["challenge"].(string)
	rpID := pk["rp"].(map[string]any)["id"].(string)
	x, y := k.priv.PublicKey.X.FillBytes(make([]byte, 32)), k.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	cose := cbor(map[any]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}) // EC2, ES256, P-256
	auth := append(append([]byte{}, rpHash(rpID)...), 0x41)     // UP, AT
	auth = append(auth, 0, 0, 0, 0)                             // counter 0
	auth = append(auth, make([]byte, 16)...)                    // AAGUID: none
	auth = append(auth, byte(len(k.id)>>8), byte(len(k.id)))
	auth = append(append(auth, k.id...), cose...)
	att := cbor(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": auth})
	return map[string]any{"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64.EncodeToString(clientData("webauthn.create", challenge, origin)), "attestationObject": b64.EncodeToString(att)},
		"clientExtensionResults": map[string]any{}}
}

// get answers navigator.credentials.get for options, as the browser at origin would, the key's
// counter moving by step; rpID and sign let a test play what an attacker would send.
func (k *softKey) get(t *testing.T, options any, origin, rpID string, step int, userHandle string, sign bool) map[string]any {
	t.Helper()
	pk := options.(map[string]any)["publicKey"].(map[string]any)
	challenge := pk["challenge"].(string)
	if rpID == "" {
		rpID = pk["rpId"].(string)
	}
	k.counter = uint32(int(k.counter) + step)
	auth := append(append([]byte{}, rpHash(rpID)...), 0x01) // UP
	auth = binary.BigEndian.AppendUint32(auth, k.counter)
	cd := clientData("webauthn.get", challenge, origin)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !sign {
		sig[len(sig)-1] ^= 0xff
	}
	return map[string]any{"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(auth),
			"signature": b64.EncodeToString(sig), "userHandle": userHandle},
		"clientExtensionResults": map[string]any{}}
}

func TestWebAuthnFlow_AStrictRoleLogsInOnlyWithItsKey_AndWhatPhishingWouldSendIsRefused(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-65")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-65")
	const origin, rpID = "http://localhost:5173", "localhost"
	mfaKey := testKMSKeyHex(t)
	base := []string{"SKIP_DEMO_SEED=1", "MFA_SECRET_KEY_HEX=" + mfaKey, "MFA_REQUIRED_ROLES=dba"}
	webauthnEnv := append(append([]string{}, base...), "MFA_PHISHING_RESISTANT_ROLES=platform-admin", "WEBAUTHN_RP_ID="+rpID, "WEBAUTHN_ORIGINS="+origin)

	t.Run("WebAuthn's configuration is all or nothing, and an origin must be under the relying party", func(t *testing.T) {
		for name, env := range map[string][]string{
			"strict roles without WebAuthn": append(append([]string{}, base...), "MFA_PHISHING_RESISTANT_ROLES=platform-admin"),
			"a relying party, no origin":    append(append([]string{}, base...), "WEBAUTHN_RP_ID="+rpID),
			"an origin elsewhere":           append(append([]string{}, base...), "WEBAUTHN_RP_ID=bastion.example", "WEBAUTHN_ORIGINS=https://bastion-example.evil"),
			"http that is not localhost":    append(append([]string{}, base...), "WEBAUTHN_RP_ID=bastion.example", "WEBAUTHN_ORIGINS=http://bastion.example"),
			"a relying party with a scheme": append(append([]string{}, base...), "WEBAUTHN_RP_ID=https://bastion.example", "WEBAUTHN_ORIGINS=https://bastion.example"),
		} {
			out := runUntilExit(t, root, authnBin, append([]string{"PORT=19663", "AUDIT_URL=" + auditSinkURL()}, env...)...)
			if !strings.Contains(out, "WEBAUTHN") && !strings.Contains(out, "WebAuthn") {
				t.Fatalf("%s: the refusal does not name WebAuthn:\n%s", name, out)
			}
		}
	})

	authn := startService(t, root, authnBin, "19661", webauthnEnv...)
	gateway := startService(t, root, gatewayBin, "19662", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	run := fmt.Sprint(time.Now().UnixNano())
	admin, dba := "root-"+run, "dba-"+run
	for user, role := range map[string]string{admin: "platform-admin", dba: "dba"} {
		if s, out := postJSONTo(t, authn.baseURL+"/auth/v1/users", map[string]any{"username": user, "displayName": user, "password": "pw-" + user, "roles": []string{role}}); s != http.StatusCreated {
			t.Fatalf("create %s: %d %v", user, s, out)
		}
	}
	login := func(user string) map[string]any {
		t.Helper()
		s, out := postJSONTo(t, gateway.baseURL+"/auth/login", map[string]string{"username": user, "password": "pw-" + user})
		if s != http.StatusUnauthorized || out["challenge"] == nil {
			t.Fatalf("login %s: %d %v, want a challenge", user, s, out)
		}
		return out
	}
	verify := func(ch string, credential map[string]any) (int, map[string]any) {
		return postJSONTo(t, gateway.baseURL+"/auth/mfa/webauthn/verify", map[string]any{"challenge": ch, "credential": credential})
	}
	key := newSoftKey(t)

	t.Run("a strict role enrolls a key, with an administrator's code — TOTP is refused", func(t *testing.T) {
		out := login(admin)
		if out["mfa"] != "enrollment_required" || fmt.Sprint(out["factors"]) != "[webauthn]" {
			t.Fatalf("a strict role with nothing: %v", out)
		}
		ch := out["challenge"].(string)
		_, issued := postJSONTo(t, authn.baseURL+"/auth/v1/mfa/enrollment-codes", map[string]string{"source": "local", "loginName": admin})
		ec := issued["enrollmentCode"].(string)
		if s, _ := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll", map[string]string{"challenge": ch, "enrollmentCode": ec, "factor": "totp"}); s != http.StatusUnauthorized {
			t.Fatalf("TOTP for a strict role: %d", s)
		}
		s, e := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll", map[string]string{"challenge": ch, "enrollmentCode": ec, "factor": "webauthn"})
		if s != http.StatusOK || e["webauthn"] == nil || e["secret"] != nil {
			t.Fatalf("a key's enrollment: %d %v", s, e)
		}
		s, done := postJSONTo(t, gateway.baseURL+"/auth/mfa/webauthn/enroll/confirm", map[string]any{"challenge": ch, "credential": key.create(t, e["webauthn"], origin)})
		if s != http.StatusOK || done["accessToken"] == nil {
			t.Fatalf("confirm the key: %d %v", s, done)
		}
		username, roles := whoIs(t, authn.baseURL, done["accessToken"].(string))
		if username != admin || fmt.Sprint(roles) != "[platform-admin]" {
			t.Fatalf("token: %s %v", username, roles)
		}
	})

	t.Run("what phishing would send is refused, and so is TOTP; the key at its origin logs in", func(t *testing.T) {
		out := login(admin)
		if out["mfa"] != "required" || fmt.Sprint(out["factors"]) != "[webauthn]" || out["webauthn"] == nil {
			t.Fatalf("a strict role with a key: %v", out)
		}
		ch, opts := out["challenge"].(string), out["webauthn"]
		if s, _ := postJSONTo(t, gateway.baseURL+"/auth/mfa/verify", map[string]string{"challenge": ch, "code": "123456"}); s != http.StatusUnauthorized {
			t.Fatalf("a TOTP code for a strict role: %d", s)
		}
		for name, cred := range map[string]map[string]any{
			"another origin (a phishing site)":  key.get(t, opts, "http://localhost:6666", "", 1, "", true),
			"another relying party":             key.get(t, opts, origin, "evil.example", 1, "", true),
			"a signature that is not the key's": key.get(t, opts, origin, "", 1, "", false),
		} {
			if s, out := verify(ch, cred); s != http.StatusUnauthorized || out["accessToken"] != nil {
				t.Fatalf("%s: %d %v", name, s, out)
			}
		}
		// Four failures on this challenge: the fifth try, the right one, still has its chance.
		if s, done := verify(ch, key.get(t, opts, origin, "", 1, "", true)); s != http.StatusOK || done["accessToken"] == nil {
			t.Fatalf("the key at its origin: %d %v", s, done)
		}
		if s, _ := verify(ch, key.get(t, opts, origin, "", 1, "", true)); s != http.StatusUnauthorized {
			t.Fatalf("a spent challenge: %d", s)
		}
	})

	t.Run("a key of no one, and a counter that goes back, are refused", func(t *testing.T) {
		out := login(admin)
		if s, _ := verify(out["challenge"].(string), newSoftKey(t).get(t, out["webauthn"], origin, "", 1, "", true)); s != http.StatusUnauthorized {
			t.Fatalf("a key of no one: %d", s)
		}
		out = login(admin)
		if s, _ := verify(out["challenge"].(string), key.get(t, out["webauthn"], origin, "", -2, "", true)); s != http.StatusUnauthorized {
			t.Fatalf("a counter that went back: %d", s)
		}
		out = login(admin)
		if s, _ := verify(out["challenge"].(string), key.get(t, out["webauthn"], origin, "", 5, "", true)); s != http.StatusOK {
			t.Fatalf("the key, its counter forward again: %d", s)
		}
	})

	t.Run("the Gateway forwards the browser's answer only as an object", func(t *testing.T) {
		out := login(admin)
		for _, bad := range []any{"a string", 42, []string{"a"}, nil} {
			if s, _ := postJSONTo(t, gateway.baseURL+"/auth/mfa/webauthn/verify", map[string]any{"challenge": out["challenge"], "credential": bad}); s != http.StatusBadRequest {
				t.Fatalf("credential %v: %d, want 400", bad, s)
			}
		}
	})

	t.Run("a role that is not strict may enroll either factor", func(t *testing.T) {
		if out := login(dba); out["mfa"] != "enrollment_required" || fmt.Sprint(out["factors"]) != "[totp webauthn]" {
			t.Fatalf("a non-strict role: %v", out)
		}
	})

	t.Run("a reset forgets the key; the logins and the key are in the audit; no answer in any log", func(t *testing.T) {
		resp, err := http.Post(authn.baseURL+"/auth/v1/mfa/reset", "application/json", strings.NewReader(fmt.Sprintf(`{"username": %q}`, admin)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if out := login(admin); out["mfa"] != "enrollment_required" {
			t.Fatalf("after a reset: %v", out)
		}
		var actions []string
		for _, e := range sunk(admin) {
			actions = append(actions, e.Action)
		}
		got := strings.Join(actions, " ")
		for _, want := range []string{"auth.mfa_webauthn_registered", "auth.login_webauthn", "auth.login_refused", "auth.mfa_reset"} {
			if !strings.Contains(got, want) {
				t.Fatalf("the audit of %s lacks %s: %s", admin, want, got)
			}
		}
		if strings.Contains(got, "auth.login_mfa") || strings.Contains(got, "auth.login ") {
			t.Fatalf("a strict role logged in otherwise than by its key: %s", got)
		}
		if strings.Contains(authn.out.String(), b64.EncodeToString(key.id)) || strings.Contains(authn.out.String(), "authenticatorData") {
			t.Fatal("a key or an answer is in the service's log")
		}
		if !strings.Contains(authn.out.String(), "only a security key (WebAuthn) counts for the roles platform-admin") {
			t.Fatalf("the start does not say the strict roles:\n%s", authn.out.String())
		}
	})
}
