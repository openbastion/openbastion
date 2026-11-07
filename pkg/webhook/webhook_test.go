package webhook_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/webhook"
)

const secret = "0123456789abcdef0123456789abcdef"

func TestNew_AcceptsOnlyAURLItCanTrust_AndNeverRepeatsIt(t *testing.T) {
	for _, ok := range []string{"https://hooks.example/T/B/x", "http://127.0.0.1:9/x", "http://localhost:9/x", "http://[::1]:9/x"} {
		if _, err := webhook.New(ok); err != nil {
			t.Fatalf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://hooks.example/s3cr3t", "ftp://hooks.example/s3cr3t", "https://user:s3cr3t@hooks.example/",
		"https:///s3cr3t", "://s3cr3t", "hooks.example/s3cr3t", "http://10.0.0.1/s3cr3t"} {
		_, err := webhook.New(bad)
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Fatalf("%q: the error repeats the URL: %v", bad, err)
		}
	}
}

func TestEndpoint_WhereIsSchemeAndHostOnly(t *testing.T) {
	e, _ := webhook.New("https://hooks.example:8443/services/T/B/s3cr3t?token=x")
	if e.Where() != "https://hooks.example:8443" {
		t.Fatalf("Where() = %q", e.Where())
	}
}

func TestEndpoint_AShortSecretIsRefused_WithoutBeingRepeated(t *testing.T) {
	e, _ := webhook.New("https://hooks.example/x")
	short := strings.Repeat("k", webhook.MinSecretBytes-1)
	if _, err := e.WithSecret(short); err == nil || strings.Contains(err.Error(), short) {
		t.Fatalf("err = %v", err)
	}
	if e.Signed() {
		t.Fatal("a refused secret signs")
	}
	if _, err := e.WithSecret(secret); err != nil || !e.Signed() {
		t.Fatalf("a %d-byte secret: %v", len(secret), err)
	}
}

func TestPost_SignsTheExactBody_StampedWhenSent(t *testing.T) {
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, body = r.Header.Clone(), mustRead(r)
		w.WriteHeader(202)
	}))
	defer srv.Close()
	e, _ := webhook.New(srv.URL)
	_, _ = e.WithSecret(secret)
	e.WithClock(func() time.Time { return time.Unix(1700000000, 0) })
	status, err := e.Post(context.Background(), "ua-test", []byte(`{"a":1}`))
	if err != nil || status != 202 {
		t.Fatalf("status %d, err %v", status, err)
	}
	if got.Get(webhook.TimestampHeader) != "1700000000" || got.Get("User-Agent") != "ua-test" || got.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", got)
	}
	// The reference value, computed here with crypto/hmac rather than by the code under test.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(`1700000000.{"a":1}`))
	want := "v1=" + hex.EncodeToString(mac.Sum(nil))
	if sig := got.Get(webhook.SignatureHeader); sig != want || string(body) != `{"a":1}` {
		t.Fatalf("signature %q over %q, want %q", sig, body, want)
	}
	if webhook.Signature([]byte(secret), "1700000000", body) != want {
		t.Fatal("Signature does not compute what a receiver computes")
	}
}

func TestPost_WithoutASecretNothingIsSigned(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	e, _ := webhook.New(srv.URL)
	if _, err := e.Post(context.Background(), "ua", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if got.Get(webhook.SignatureHeader) != "" || got.Get(webhook.TimestampHeader) != "" {
		t.Fatalf("an unsigned endpoint signed: %v", got)
	}
}

func TestPost_ARedirectIsAnAnswer_NotFollowed(t *testing.T) {
	followed := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	e, _ := webhook.New(srv.URL)
	status, err := e.Post(context.Background(), "ua", []byte("{}"))
	if err != nil || status != http.StatusTemporaryRedirect || followed {
		t.Fatalf("status %d, err %v, followed %v", status, err, followed)
	}
}

func TestPost_ATransportErrorDoesNotCarryTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/services/T/B/s3cr3t-path"
	srv.Close()
	e, _ := webhook.New(url)
	_, err := e.Post(context.Background(), "ua", []byte("{}"))
	if err == nil || strings.Contains(err.Error(), "s3cr3t-path") {
		t.Fatalf("err = %v", err)
	}
}

func TestPost_ASilentEndpointIsCutAtTheTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	e, _ := webhook.New(srv.URL)
	e.WithTimeout(50 * time.Millisecond)
	start := time.Now()
	if _, err := e.Post(context.Background(), "ua", []byte("{}")); err == nil {
		t.Fatal("a silent endpoint answered")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Post waited %s", d)
	}
}

func TestSafeText_KeepsAnIdentifier_AndDisarmsTheRest(t *testing.T) {
	if got := webhook.SafeText("acc_db-01.prod:x"); got != "acc_db-01.prod:x" {
		t.Fatalf("an identifier was changed: %q", got)
	}
	if got := webhook.SafeText("a<@U1>\n*b*"); got != "a??U1???b?" {
		t.Fatalf("SafeText = %q", got)
	}
	if got := webhook.SafeText(strings.Repeat("x", 100)); len(got) != 64 {
		t.Fatalf("not bounded: %d", len(got))
	}
}

func mustRead(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	return b
}

func TestParseFormat_NamesThreeShapes_AndRefusesTheRest(t *testing.T) {
	for in, want := range map[string]webhook.Format{"": webhook.FormatGeneric, "generic": webhook.FormatGeneric, "slack": webhook.FormatSlack, "teams": webhook.FormatTeams} {
		if got, err := webhook.ParseFormat(in); err != nil || got != want {
			t.Fatalf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"Slack", "TEAMS", " slack", "mattermost", "generic\n"} {
		if _, err := webhook.ParseFormat(in); err == nil {
			t.Fatalf("ParseFormat(%q) was accepted: a typing mistake must not leave a channel that cannot read its messages", in)
		}
	}
}

// The generic shape is a contract with receivers already in place: not one byte changes.
func TestFormatBody_GenericIsTheCallersBodyUntouched(t *testing.T) {
	generic := []byte(`{"event":"e", "text":"t"}`)
	got, err := webhook.FormatGeneric.Body(generic, "other words")
	if err != nil || !bytes.Equal(got, generic) {
		t.Fatalf("%s, %v", got, err)
	}
}

func TestFormatBody_SlackIsThePhraseAlone(t *testing.T) {
	got, err := webhook.FormatSlack.Body([]byte(`{"requestedBy":"raw<!channel>"}`), "the phrase")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"text":"the phrase"}` {
		t.Fatalf("%s", got)
	}
}

func TestFormatBody_TeamsIsAnAdaptiveCardWithoutAnyAction(t *testing.T) {
	got, err := webhook.FormatTeams.Body([]byte(`{"requestedBy":"raw<at>x</at>"}`), "the phrase")
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":"the phrase","wrap":true}]}}]}`
	if string(got) != want {
		t.Fatalf("%s", got)
	}
	if bytes.Contains(got, []byte("raw")) || bytes.Contains(got, []byte("actions")) {
		t.Fatalf("the card carries more than the phrase: %s", got)
	}
}

// What the phrase is made of is the caller's, but the JSON around it is this package's.
func TestFormatBody_AnythingInThePhraseStaysInsideTheJSONString(t *testing.T) {
	hostile := "\",\"attachments\":[],\"x\":\"\n <script>"
	for _, f := range []webhook.Format{webhook.FormatSlack, webhook.FormatTeams} {
		got, err := f.Body(nil, hostile)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(got, &m); err != nil {
			t.Fatalf("%s: %v: %s", f, err, got)
		}
		if f == webhook.FormatSlack && (m["text"] != hostile || len(m) != 1) {
			t.Fatalf("slack: %v", m)
		}
		if f == webhook.FormatTeams && (m["type"] != "message" || len(m["attachments"].([]any)) != 1) {
			t.Fatalf("teams: the phrase changed the envelope: %v", m)
		}
	}
}

func TestFormatBody_AnUnknownFormatIsAnError(t *testing.T) {
	if _, err := webhook.Format("telex").Body([]byte(`{}`), "x"); err == nil {
		t.Fatal("an unknown format produced a body")
	}
	if _, err := webhook.FormatSlack.Body(nil, ""); err == nil {
		t.Fatal("an empty phrase produced a message that says nothing")
	}
}

// A real channel, when its URL is given (ADR-0074): never written in the repository, and the
// URL is a secret, so a failure says the status and nothing of the URL.
func TestRealChannel_AcceptsTheFormat(t *testing.T) {
	for _, c := range []struct {
		env    string
		format webhook.Format
	}{{"NOTIFY_INTEROP_SLACK_URL", webhook.FormatSlack}, {"NOTIFY_INTEROP_TEAMS_URL", webhook.FormatTeams}} {
		t.Run(c.env, func(t *testing.T) {
			raw := os.Getenv(c.env)
			if raw == "" {
				t.Skip(c.env + " not set")
			}
			endpoint, err := webhook.New(raw)
			if err != nil {
				t.Fatalf("the URL cannot be used: %v", err)
			}
			body, err := c.format.Body(nil, "OpenBastion: test message of ADR-0074, nothing to do. A neutralized mention reads: "+webhook.SafeText("<!here>"))
			if err != nil {
				t.Fatal(err)
			}
			status, err := endpoint.Post(context.Background(), "OpenBastion-Interop-Test", body)
			if err != nil {
				t.Fatalf("delivery failed: %T", err)
			}
			if status < 200 || status > 299 {
				t.Fatalf("status %d", status)
			}
		})
	}
}

// A Workflows URL is authorized by its query (sp, sv, sig): one byte changed is a 401. And a request
// must carry no other scheme beside it: Microsoft refuses both at once.
func TestPost_SendsAWorkflowsURLUntouched_AndNoAuthorizationHeader(t *testing.T) {
	const path = "/powerautomate/automations/direct/workflows/abc123/triggers/manual/paths/invoke"
	const query = "api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=a-_b%2Bc%3D"
	var gotURI, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI, gotAuth = r.RequestURI, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	endpoint, err := webhook.New(srv.URL + path + "?" + query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.WithSecret(secret); err != nil {
		t.Fatal(err)
	}
	status, err := endpoint.Post(context.Background(), "test", []byte(`{}`))
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("%d, %v", status, err)
	}
	if gotURI != path+"?"+query {
		t.Fatalf("the URL changed on the way: %s", gotURI)
	}
	if gotAuth != "" {
		t.Fatalf("an Authorization header was sent: %s", gotAuth)
	}
}
