// Package transit is OpenBastion's client to the Transit secrets engine of OpenBao (or of
// HashiCorp Vault, which has the same API) — the key-management service that keeps the master
// keys of the Password Vault and of the Command Recorder (ADR-0049). It wraps and unwraps data
// keys under a named key that never leaves the Transit server, each bound to associated data.
//
// Standard library only. The token is read from a file and is never written anywhere: not in an
// error, not in a log.
package transit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Timeout bounds one call to Transit, connection and answer included.
const Timeout = 5 * time.Second

var (
	namePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	mountPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}(/[A-Za-z0-9_-]{1,64}){0,3}$`)
)

// Config names a Transit key and how to reach it.
type Config struct {
	Addr      string // https://openbao.example:8200 (http only towards a loopback address)
	Mount     string // "transit" when empty
	Key       string // the key's name in the mount
	TokenFile string // a file holding the token, readable by its owner only
	CAFile    string // optional: the authority that signs the server's certificate
}

// Client wraps and unwraps with one Transit key.
type Client struct {
	base, mount, key string
	tokenMu          sync.RWMutex
	token            string // the token in use; replaced by ReloadToken once a new one is checked (ADR-0056)
	tokenFile        string
	http             *http.Client
	renewFloor       time.Duration // the shortest wait before a renewal is tried again (ADR-0053)
}

// FromEnv reads TRANSIT_ADDR, TRANSIT_KEY and TRANSIT_TOKEN_FILE, which go together, and
// TRANSIT_MOUNT and TRANSIT_CA_FILE. None set: (nil, false, nil) — Transit is not configured.
// Some but not all, or any value that cannot be used: an error that names the variable and never
// repeats the token.
func FromEnv(getenv func(string) string) (*Client, bool, error) {
	cfg := Config{Addr: getenv("TRANSIT_ADDR"), Mount: getenv("TRANSIT_MOUNT"), Key: getenv("TRANSIT_KEY"),
		TokenFile: getenv("TRANSIT_TOKEN_FILE"), CAFile: getenv("TRANSIT_CA_FILE")}
	if cfg.Addr == "" && cfg.Key == "" && cfg.TokenFile == "" && cfg.Mount == "" && cfg.CAFile == "" {
		return nil, false, nil
	}
	var missing []string
	for name, v := range map[string]string{"TRANSIT_ADDR": cfg.Addr, "TRANSIT_KEY": cfg.Key, "TRANSIT_TOKEN_FILE": cfg.TokenFile} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, true, fmt.Errorf("TRANSIT_ADDR, TRANSIT_KEY and TRANSIT_TOKEN_FILE go together; missing: %s", strings.Join(sorted(missing), ", "))
	}
	c, err := New(cfg)
	return c, true, err
}

// New checks cfg and returns a client; it does not call the server (see Probe).
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Addr)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, errors.New("TRANSIT_ADDR must be a URL such as https://openbao.example:8200, without credentials, path or query")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, errors.New("TRANSIT_ADDR: http is only allowed towards a loopback address; use https")
		}
	default:
		return nil, errors.New("TRANSIT_ADDR: the scheme must be https")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "transit"
	}
	if !mountPattern.MatchString(mount) {
		return nil, errors.New("TRANSIT_MOUNT must be a mount path of letters, digits, '-', '_' and '/'")
	}
	if !namePattern.MatchString(cfg.Key) {
		return nil, errors.New("TRANSIT_KEY must be a key name of 1 to 128 letters, digits, '-' and '_'")
	}
	token, err := readToken(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("TRANSIT_CA_FILE cannot be read: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("TRANSIT_CA_FILE holds no PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		base: u.Scheme + "://" + u.Host, mount: mount, key: cfg.Key, token: token, tokenFile: cfg.TokenFile, renewFloor: DefaultRenewFloor,
		http: &http.Client{
			Timeout: Timeout,
			// The token goes to this server and nowhere else: no redirect, no egress proxy.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig},
		},
	}, nil
}

// readToken reads the token from a file only its owner can read: a token others can read is a
// token others can use.
func readToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("TRANSIT_TOKEN_FILE cannot be read: %v", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("TRANSIT_TOKEN_FILE must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("TRANSIT_TOKEN_FILE is readable by its group or by others (mode %#o): make it 0600 or 0400", info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("TRANSIT_TOKEN_FILE cannot be read: %v", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("TRANSIT_TOKEN_FILE must hold one token on one line")
	}
	return token, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// KeyID names the key in what OpenBastion stores next to each wrapped key: stable across
// addresses of the server, and across rotations of the key inside Transit.
func (c *Client) KeyID() string { return "transit:" + c.mount + "/" + c.key }

// Where is what a log may say of the server: scheme and host.
func (c *Client) Where() string { return c.base }

// Encrypt wraps plaintext under the key, bound to aad, which must not be empty.
func (c *Client) Encrypt(ctx context.Context, plaintext, aad []byte) (string, error) {
	if len(aad) == 0 {
		return "", errors.New("transit: associated data is required")
	}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := c.call(ctx, "encrypt", map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext), "associated_data": base64.StdEncoding.EncodeToString(aad),
	}, &out); err != nil {
		return "", err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return "", errors.New("transit encrypt: the answer holds no ciphertext")
	}
	return out.Data.Ciphertext, nil
}

// Decrypt unwraps ciphertext, which must have been wrapped with the same aad.
func (c *Client) Decrypt(ctx context.Context, ciphertext string, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("transit: associated data is required")
	}
	if !strings.HasPrefix(ciphertext, "vault:v") {
		return nil, errors.New("transit decrypt: not a Transit ciphertext")
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := c.call(ctx, "decrypt", map[string]string{
		"ciphertext": ciphertext, "associated_data": base64.StdEncoding.EncodeToString(aad),
	}, &out); err != nil {
		return nil, err
	}
	p, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, errors.New("transit decrypt: the answer holds no plaintext")
	}
	return p, nil
}

// Probe wraps and unwraps a test value: the key exists, the token may use it both ways.
func (c *Client) Probe(ctx context.Context) error {
	want := []byte("openbastion transit probe")
	aad := []byte("openbastion.transit.probe")
	ct, err := c.Encrypt(ctx, want, aad)
	if err != nil {
		return err
	}
	got, err := c.Decrypt(ctx, ct, aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("transit probe: the value did not come back")
	}
	return nil
}

func (c *Client) call(ctx context.Context, op string, body map[string]string, out any) error {
	return c.do(ctx, op, http.MethodPost, "/v1/"+c.mount+"/"+op+"/"+c.key, body, out)
}

func (c *Client) currentToken() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

func (c *Client) do(ctx context.Context, op, method, path string, body any, out any) error {
	return c.doAs(ctx, c.currentToken(), op, method, path, body, out)
}

func (c *Client) doAs(ctx context.Context, token, op, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return fmt.Errorf("transit %s: the request could not be built", op)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the cause, without the URL
		}
		return fmt.Errorf("transit %s at %s: %v", op, c.base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := "no reason given"
		if len(e.Errors) > 0 {
			msg = strings.Join(e.Errors, "; ")
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		return fmt.Errorf("transit %s at %s: status %d: %s", op, c.base, resp.StatusCode, strings.ReplaceAll(msg, token, "[token]"))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("transit %s: the answer is not JSON", op)
	}
	return nil
}

func sorted(s []string) []string {
	sort.Strings(s)
	return s
}

// DefaultRenewFloor is the shortest wait before a failed renewal is tried again (ADR-0053).
const DefaultRenewFloor = 5 * time.Second

// WithRenewFloor changes the shortest wait between two attempts at renewing; for tests.
func (c *Client) WithRenewFloor(d time.Duration) *Client {
	c.renewFloor = d
	return c
}

// TokenLife reads what is left of the token (auth/token/lookup-self): its time to live — zero for
// a token without an end — and whether it may be renewed.
func (c *Client) TokenLife(ctx context.Context) (ttl time.Duration, renewable bool, err error) {
	var out struct {
		Data struct {
			TTL       int64 `json:"ttl"`
			Renewable bool  `json:"renewable"`
		} `json:"data"`
	}
	if err := c.do(ctx, "lookup-self", http.MethodGet, "/v1/auth/token/lookup-self", nil, &out); err != nil {
		return 0, false, err
	}
	return time.Duration(out.Data.TTL) * time.Second, out.Data.Renewable, nil
}

// RenewSelf renews the token (auth/token/renew-self) and returns its new time to live.
func (c *Client) RenewSelf(ctx context.Context) (time.Duration, error) {
	var out struct {
		Auth struct {
			LeaseDuration int64 `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := c.do(ctx, "renew-self", http.MethodPost, "/v1/auth/token/renew-self", map[string]string{}, &out); err != nil {
		return 0, err
	}
	if out.Auth.LeaseDuration <= 0 {
		return 0, errors.New("transit renew-self: the answer holds no lease duration")
	}
	return time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}

// KeepAlive keeps the token alive until ctx ends (ADR-0053): a renewable token is renewed at half
// its life, then at half of each new one; a renewal that fails is tried again at a quarter of the
// time left (never sooner than the floor), and every failure is said. A token without an end, or
// that may not be renewed, is left as it is — and that is said once. The token is never written.
func (c *Client) KeepAlive(ctx context.Context, logf func(format string, args ...any)) {
	ttl, renewable, err := c.TokenLife(ctx)
	switch {
	case err != nil:
		logf("transit: the token's life cannot be read (%v): it is not renewed; give its policy auth/token/lookup-self and auth/token/renew-self", err)
		return
	case ttl <= 0:
		logf("transit: the token has no end: it is not renewed")
		return
	case !renewable:
		logf("transit: the token may not be renewed: it ends in %s", ttl)
		return
	}
	logf("transit: the token is renewed at half its life (now %s left)", ttl)
	deadline := time.Now().Add(ttl)
	wait := ttl / 2
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		next, err := c.RenewSelf(ctx)
		if err == nil {
			deadline = time.Now().Add(next)
			wait = next / 2
			continue
		}
		wait = time.Until(deadline) / 4
		if wait < c.renewFloor {
			wait = c.renewFloor
		}
		logf("transit: the token could not be renewed (%v): tried again in %s; it ends at %s", err, wait.Round(time.Second), deadline.UTC().Format(time.RFC3339))
	}
}

// DefaultTokenReload is how often the token file is read again (ADR-0056).
const DefaultTokenReload = 30 * time.Second

// ReloadToken reads the token file again (ADR-0056). A token that differs from the one in use is
// taken only once Transit has accepted it (auth/token/lookup-self); a file that cannot be used, or
// a token Transit refuses, leaves the token in use as it is — the error says why, and holds
// neither token.
func (c *Client) ReloadToken(ctx context.Context) (changed bool, err error) {
	next, err := readToken(c.tokenFile)
	if err != nil {
		return false, err
	}
	current := c.currentToken()
	if next == current {
		return false, nil
	}
	var out struct {
		Data struct {
			TTL int64 `json:"ttl"`
		} `json:"data"`
	}
	if err := c.doAs(ctx, next, "lookup-self", http.MethodGet, "/v1/auth/token/lookup-self", nil, &out); err != nil {
		return false, fmt.Errorf("the new token is refused by Transit: %s", strings.ReplaceAll(err.Error(), next, "[token]"))
	}
	c.tokenMu.Lock()
	c.token = next
	c.tokenMu.Unlock()
	return true, nil
}

// WatchTokenFile reads the token file every period until ctx ends, and takes a new token once
// Transit has accepted it (ADR-0056). Each change is said once; the tokens never are.
func (c *Client) WatchTokenFile(ctx context.Context, every time.Duration, logf func(format string, args ...any)) {
	last := ""
	logf("transit: the token file is read again every %s; a new token is taken once Transit accepts it", every)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := c.ReloadToken(ctx)
		switch {
		case err != nil:
			if msg := err.Error(); msg != last {
				last = msg
				logf("transit: the token file cannot be taken (%v): the token in use stays", err)
			}
		case changed:
			last = ""
			logf("transit: the token file changed: the new token, accepted by Transit, is used from now on")
		}
	}
}
