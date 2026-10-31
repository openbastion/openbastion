// Package webhook is the one implementation of an outgoing, signed webhook in OpenBastion: the
// break-glass notification of the Session Broker (ADR-0012, ADR-0013) and the alerts of the
// Audit Service (ADR-0045). It checks the URL, signs the exact bytes sent, does not follow a
// redirect, and never writes the URL — which is a secret — anywhere.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	// DefaultTimeout bounds one delivery, connection and answer included.
	DefaultTimeout = 5 * time.Second

	// MinSecretBytes is the shortest key a delivery is signed with (ADR-0013): an HMAC key
	// shorter than its output is a weaker key than the one it stands in for.
	MinSecretBytes = 32

	// The two headers of a signed delivery (ADR-0013). The signature is
	// "v1=" + hex(HMAC-SHA256(secret, timestamp + "." + body)); a receiver recomputes it on the
	// bytes it received, compares in constant time, and refuses a timestamp that is too far
	// from its own clock.
	TimestampHeader = "X-OpenBastion-Timestamp"
	SignatureHeader = "X-OpenBastion-Signature"
)

// Endpoint is one URL that deliveries are POSTed to.
type Endpoint struct {
	url     string
	where   string
	client  *http.Client
	timeout time.Duration
	secret  []byte // never written anywhere
	now     func() time.Time
}

// New checks rawURL and returns an endpoint for it. https is required, except towards a
// loopback address (development and tests); a URL that carries credentials, has no host, has
// another scheme or cannot be read is an error — whose text never repeats the URL, because the
// caller writes it into the log.
func New(rawURL string) (*Endpoint, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("not a valid URL")
	}
	if u.Hostname() == "" {
		return nil, errors.New("the URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("the URL must not carry credentials (user:password@)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, errors.New("http is only allowed towards a loopback address; use https")
		}
	default:
		return nil, errors.New("the URL scheme must be https")
	}
	return &Endpoint{
		url:     u.String(),
		where:   u.Scheme + "://" + u.Host,
		timeout: DefaultTimeout,
		now:     time.Now,
		client: &http.Client{
			// A redirect is an answer, not an instruction: a hostile or hijacked endpoint must
			// not be able to send the service, from inside the network, to another address.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// WithSecret makes every delivery signed. A secret shorter than MinSecretBytes is refused, with
// an error that does not repeat it. The secret is used exactly as given — a trailing newline
// from a file is part of the key, and the receiver's key must have it too.
func (e *Endpoint) WithSecret(secret string) (*Endpoint, error) {
	if len(secret) < MinSecretBytes {
		return nil, fmt.Errorf("the secret must be at least %d bytes long (for example `openssl rand -hex 32`)", MinSecretBytes)
	}
	e.secret = []byte(secret)
	return e, nil
}

// Signed says whether deliveries carry a signature.
func (e *Endpoint) Signed() bool { return len(e.secret) > 0 }

// WithTimeout changes the bound of one delivery; for tests.
func (e *Endpoint) WithTimeout(d time.Duration) *Endpoint {
	e.timeout = d
	return e
}

// WithClock replaces the clock that stamps a signed delivery; for tests.
func (e *Endpoint) WithClock(now func() time.Time) *Endpoint {
	e.now = now
	return e
}

// Where is the only part of the URL that may be written down: scheme and host.
func (e *Endpoint) Where() string { return e.where }

// Signature is the value of SignatureHeader for body sent at timestamp ts.
func Signature(secret []byte, ts string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Post sends body once and returns the status of the answer. The error, when there is one, is
// the cause alone: net/http puts the whole URL — the secret — in front of it, and that part is
// removed.
func (e *Endpoint) Post(ctx context.Context, userAgent string, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("the request could not be built")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if e.Signed() {
		// Stamped at the moment of sending, not of the event: the receiver's tolerance is about
		// how fresh the delivery is.
		ts := strconv.FormatInt(e.now().Unix(), 10)
		req.Header.Set(TimestampHeader, ts)
		req.Header.Set(SignatureHeader, Signature(e.secret, ts, body))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// SafeText makes an identifier fit to be read inside a sentence by a chat service: letters,
// digits and . _ : - survive, anything else — the characters that make a mention, a link or a
// line break — becomes "?", and it stops at 64 characters. Identifiers come from people (an
// account id is chosen at onboarding): they are not trusted to be the plain word they normally
// are.
func SafeText(s string) string {
	const max = 64
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if len(out) == max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == ':', r == '-':
			out = append(out, r)
		default:
			out = append(out, '?')
		}
	}
	return string(out)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
