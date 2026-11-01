package integration_test

// ADR-0062 across real processes and a real PostgreSQL: an account that holds a declared role gets
// no token for its password alone; it enrolls only with an administrator's code; a code is used
// once; the secret survives a restart sealed, and is useless under another key.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// totpCode is RFC 6238 (SHA-1, 30 s, 6 digits) for the base32 secret at t: what an authenticator
// application shows.
func totpCode(t *testing.T, b32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	s := m.Sum(nil)
	o := s[19] & 0xf
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(s[o:o+4])&0x7fffffff)%1000000)
}

// postJSONTo posts body to url and returns the status and the decoded answer.
func postJSONTo(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestPostgresFlow_ADeclaredRoleNeedsASecondFactor_EnrolledWithAnAdministratorsCode(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-62")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-62")
	signing, mfaKey := testKMSKeyHex(t), testKMSKeyHex(t)
	base := []string{"DATABASE_URL=" + dsn, "TOKEN_SIGNING_KEY_HEX=" + signing, "SKIP_DEMO_SEED=1"}
	withMFA := func(key string) []string {
		return append(append([]string{}, base...), "MFA_REQUIRED_ROLES=platform-admin,vault-admin", "MFA_SECRET_KEY_HEX="+key)
	}

	t.Run("the roles and the key go together, and neither is ever written", func(t *testing.T) {
		for name, env := range map[string][]string{
			"roles without a key":     append(append([]string{}, base...), "MFA_REQUIRED_ROLES=platform-admin"),
			"a key without roles":     append(append([]string{}, base...), "MFA_SECRET_KEY_HEX="+mfaKey),
			"a key that is too short": append(append([]string{}, base...), "MFA_REQUIRED_ROLES=platform-admin", "MFA_SECRET_KEY_HEX=abcd"),
			"a role that is no name":  append(append([]string{}, base...), "MFA_REQUIRED_ROLES=Platform Admin", "MFA_SECRET_KEY_HEX="+mfaKey),
		} {
			out := runUntilExit(t, root, authnBin, append([]string{"PORT=19633"}, env...)...)
			if !strings.Contains(out, "MFA_") {
				t.Fatalf("%s: the refusal does not name the variable:\n%s", name, out)
			}
			if strings.Contains(out, mfaKey) {
				t.Fatalf("%s: the key is in the output", name)
			}
		}
	})

	authn := startService(t, root, authnBin, "19631", withMFA(mfaKey)...)
	gateway := startService(t, root, gatewayBin, "19632", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	run := fmt.Sprint(time.Now().UnixNano())
	admin, dba := "root-"+run, "dba-"+run
	for user, role := range map[string]string{admin: "platform-admin", dba: "dba"} {
		if s, out := postJSONTo(t, authn.baseURL+"/auth/v1/users", map[string]any{"username": user, "displayName": user, "password": "pw-" + user, "roles": []string{role}}); s != http.StatusCreated {
			t.Fatalf("create %s: %d %v", user, s, out)
		}
	}
	login := func(user string) (int, map[string]any) {
		return postJSONTo(t, gateway.baseURL+"/auth/login", map[string]string{"username": user, "password": "pw-" + user})
	}
	var secrets []string // everything that must never be in a log
	var secret string

	t.Run("the declared role gets a challenge, not a token; the other role is untouched", func(t *testing.T) {
		s, out := login(admin)
		if s != http.StatusUnauthorized || out["mfa"] != "enrollment_required" || out["challenge"] == nil || out["accessToken"] != nil {
			t.Fatalf("%s: %d %v", admin, s, out)
		}
		if s, out := login(dba); s != http.StatusOK || out["accessToken"] == nil {
			t.Fatalf("%s: %d %v", dba, s, out)
		}
	})

	t.Run("enrollment needs the administrator's code, then a first code, and ends the login", func(t *testing.T) {
		_, out := login(admin)
		ch := out["challenge"].(string)
		secrets = append(secrets, ch)
		if s, _ := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll", map[string]string{"challenge": ch, "enrollmentCode": "not-issued"}); s != http.StatusUnauthorized {
			t.Fatalf("enroll with no code issued: %d", s)
		}
		s, issued := postJSONTo(t, authn.baseURL+"/auth/v1/mfa/enrollment-codes", map[string]string{"source": "local", "loginName": admin})
		if s != http.StatusOK || issued["enrollmentCode"] == nil {
			t.Fatalf("issue a code: %d %v", s, issued)
		}
		ec := issued["enrollmentCode"].(string)
		secrets = append(secrets, ec)
		s, e := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll", map[string]string{"challenge": ch, "enrollmentCode": ec})
		if s != http.StatusOK || e["secret"] == nil || !strings.HasPrefix(fmt.Sprint(e["otpauthUri"]), "otpauth://totp/") {
			t.Fatalf("enroll: %d %v", s, e)
		}
		secret = e["secret"].(string)
		secrets = append(secrets, secret)
		c := totpCode(t, secret, time.Now())
		s, done := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll/confirm", map[string]string{"challenge": ch, "code": c})
		if s != http.StatusOK || done["accessToken"] == nil {
			t.Fatalf("confirm: %d %v", s, done)
		}
		username, roles := whoIs(t, authn.baseURL, done["accessToken"].(string))
		if username != admin || fmt.Sprint(roles) != "[platform-admin]" {
			t.Fatalf("token: %s %v", username, roles)
		}
		// In the database: the secret sealed, the code burned, the challenge gone — and no value of any.
		var sealed []byte
		if err := db.QueryRow(`SELECT totp_secret_enc FROM users WHERE username = $1`, admin).Scan(&sealed); err != nil || len(sealed) == 0 {
			t.Fatalf("totp_secret_enc: %v", err)
		}
		raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if bytes.Contains(sealed, raw) || bytes.Contains(sealed, []byte(secret)) {
			t.Fatal("the TOTP secret is readable in the database")
		}
		var codes, challenges int
		_ = db.QueryRow(`SELECT count(*) FROM mfa_enrollment_codes WHERE login_name = $1`, admin).Scan(&codes)
		_ = db.QueryRow(`SELECT count(*) FROM mfa_challenges WHERE challenge_hash = $1`, []byte(ch)).Scan(&challenges)
		if codes != 0 || challenges != 0 {
			t.Fatalf("after the confirmation: %d enrollment code(s), %d challenge(s) stored by value", codes, challenges)
		}
	})

	var used string
	t.Run("after a restart the sealed secret still verifies; a code is used once", func(t *testing.T) {
		stopService(t, authn)
		authn = startService(t, root, authnBin, "19631", withMFA(mfaKey)...)
		_, out := login(admin)
		if out["mfa"] != "required" {
			t.Fatalf("an enrolled account: %v", out)
		}
		used = totpCode(t, secret, time.Now().Add(30*time.Second)) // the next step: the confirmation spent this one
		s, done := postJSONTo(t, gateway.baseURL+"/auth/mfa/verify", map[string]string{"challenge": out["challenge"].(string), "code": used})
		if s != http.StatusOK || done["accessToken"] == nil {
			t.Fatalf("verify after a restart: %d %v", s, done)
		}
		_, out = login(admin)
		if s, _ := postJSONTo(t, gateway.baseURL+"/auth/mfa/verify", map[string]string{"challenge": out["challenge"].(string), "code": used}); s != http.StatusUnauthorized {
			t.Fatalf("a replayed code: %d, want 401", s)
		}
	})

	t.Run("under another key the secret does not open: 503, never a token", func(t *testing.T) {
		stopService(t, authn)
		other := startService(t, root, authnBin, "19634", withMFA(testKMSKeyHex(t))...)
		gw := startService(t, root, gatewayBin, "19635", "AUTHENTICATION_URL="+other.baseURL, "CLIENT_LOGIN_BURST=100")
		_, out := postJSONTo(t, gw.baseURL+"/auth/login", map[string]string{"username": admin, "password": "pw-" + admin})
		s, done := postJSONTo(t, gw.baseURL+"/auth/mfa/verify", map[string]string{"challenge": fmt.Sprint(out["challenge"]), "code": totpCode(t, secret, time.Now())})
		if s != http.StatusServiceUnavailable || done["accessToken"] != nil {
			t.Fatalf("another key: %d %v", s, done)
		}
		stopService(t, other)
	})
	// Started here, not in a subtest: a process started by a subtest ends with it.
	authn = startService(t, root, authnBin, "19631", withMFA(mfaKey)...)

	t.Run("each second-factor step takes from the per-address login budget", func(t *testing.T) {
		tight := startService(t, root, gatewayBin, "19636", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=2")
		var codes []int
		for _, path := range []string{"/auth/mfa/verify", "/auth/mfa/enroll", "/auth/mfa/enroll/confirm"} {
			s, _ := postJSONTo(t, tight.baseURL+path, map[string]string{"challenge": "not-a-challenge", "code": "000000", "enrollmentCode": "x"})
			codes = append(codes, s)
		}
		if fmt.Sprint(codes) != "[401 401 429]" {
			t.Fatalf("three steps with a budget of two: %v", codes)
		}
	})

	t.Run("a reset asks for a new enrollment", func(t *testing.T) {
		resp, err := http.Post(authn.baseURL+"/auth/v1/mfa/reset", "application/json", strings.NewReader(fmt.Sprintf(`{"username": %q}`, admin)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("reset: %d", resp.StatusCode)
		}
		if _, out := login(admin); out["mfa"] != "enrollment_required" {
			t.Fatalf("after a reset: %v", out)
		}
	})

	t.Run("no secret, code or challenge is in any log", func(t *testing.T) {
		for name, out := range map[string]string{"authentication": authn.out.String(), "gateway": gateway.out.String()} {
			for _, v := range append(secrets, used, mfaKey) {
				if v != "" && strings.Contains(out, v) {
					t.Fatalf("the %s log holds a value it must not", name)
				}
			}
		}
		if !strings.Contains(authn.out.String(), "second factor (TOTP) required for the roles platform-admin, vault-admin") {
			t.Fatalf("the start does not say the second factor is on:\n%s", authn.out.String())
		}
	})
}
