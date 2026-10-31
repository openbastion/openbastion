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
	token            string
	http             *http.Client
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
		base: u.Scheme + "://" + u.Host, mount: mount, key: cfg.Key, token: token,
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
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/"+c.mount+"/"+op+"/"+c.key, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("transit %s: the request could not be built", op)
	}
	req.Header.Set("X-Vault-Token", c.token)
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
		return fmt.Errorf("transit %s at %s: status %d: %s", op, c.base, resp.StatusCode, strings.ReplaceAll(msg, c.token, "[token]"))
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
