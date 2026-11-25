// Package scram implements the SCRAM-SHA-256 client side used only between
// Database Proxy and an upstream PostgreSQL target.
package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	minIterations    = 1
	maxIterations    = 1_000_000
	maxSaltBytes     = 1024
	maxPasswordBytes = 4096
)

var (
	ErrInvalidExchange = errors.New("invalid SCRAM-SHA-256 exchange")
	ErrServerProof     = errors.New("SCRAM-SHA-256 server proof did not match")
)

type Client struct {
	username        string
	password        []byte
	nonce           string
	clientFirstBare string
	authMessage     string
	serverSignature []byte
	started         bool
	continued       bool
}

func NewClient(username string, password []byte) (*Client, error) {
	var nonceBytes [24]byte
	if _, err := io.ReadFull(rand.Reader, nonceBytes[:]); err != nil {
		return nil, fmt.Errorf("generate SCRAM nonce: %w", err)
	}
	return newClientWithNonce(username, password, base64.RawStdEncoding.EncodeToString(nonceBytes[:])), nil
}

func newClientWithNonce(username string, password []byte, nonce string) *Client {
	return &Client{username: username, password: append([]byte(nil), password...), nonce: nonce}
}

// Start returns the SCRAM client-first-message, including the GS2 header.
func (c *Client) Start() (string, error) {
	if c.started || c.username == "" || len(c.username) > 256 || len(c.password) == 0 || len(c.password) > maxPasswordBytes || c.nonce == "" {
		return "", ErrInvalidExchange
	}
	for _, b := range []byte(c.username) {
		if b == 0 || b < 0x20 || b == 0x7f {
			return "", ErrInvalidExchange
		}
	}
	// PostgreSQL applies SASLprep to SCRAM passwords. Until the proxy ships a
	// standards-complete Unicode preparation table, accepting only printable
	// ASCII avoids authenticating a different password after normalization.
	for _, b := range c.password {
		if b < 0x20 || b > 0x7e {
			return "", fmt.Errorf("%w: upstream SCRAM password must be printable ASCII", ErrInvalidExchange)
		}
	}
	c.clientFirstBare = "n=" + escapeUsername(c.username) + ",r=" + c.nonce
	c.started = true
	return "n,," + c.clientFirstBare, nil
}

// Continue validates the server-first-message and returns the client-final-message.
func (c *Client) Continue(serverFirst string) (string, error) {
	if !c.started || c.continued {
		return "", ErrInvalidExchange
	}
	defer func() {
		zero(c.password)
		c.password = nil
	}()
	attrs, err := parseAttributes(serverFirst)
	if err != nil {
		return "", err
	}
	if _, exists := attrs["m"]; exists {
		return "", fmt.Errorf("%w: mandatory SCRAM extension is unsupported", ErrInvalidExchange)
	}
	serverNonce, okNonce := attrs["r"]
	saltText, okSalt := attrs["s"]
	iterationText, okIterations := attrs["i"]
	if !okNonce || !okSalt || !okIterations || !strings.HasPrefix(serverNonce, c.nonce) || len(serverNonce) <= len(c.nonce) || len(serverNonce) > 1024 {
		return "", ErrInvalidExchange
	}
	for _, b := range []byte(serverNonce) {
		if b < 0x21 || b > 0x7e || b == ',' {
			return "", ErrInvalidExchange
		}
	}
	salt, err := base64.StdEncoding.DecodeString(saltText)
	if err != nil || len(salt) == 0 || len(salt) > maxSaltBytes {
		return "", fmt.Errorf("%w: invalid SCRAM salt", ErrInvalidExchange)
	}
	iterations, err := strconv.Atoi(iterationText)
	if err != nil || iterations < minIterations || iterations > maxIterations {
		return "", fmt.Errorf("%w: SCRAM iteration count is outside the allowed range", ErrInvalidExchange)
	}

	clientFinalWithoutProof := "c=biws,r=" + serverNonce
	c.authMessage = c.clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	saltedPassword := pbkdf2SHA256(c.password, salt, iterations, sha256.Size)
	defer zero(saltedPassword)
	clientKey := hmacSum(saltedPassword, []byte("Client Key"))
	defer zero(clientKey)
	storedKey := sha256.Sum256(clientKey)
	clientSignature := hmacSum(storedKey[:], []byte(c.authMessage))
	defer zero(clientSignature)
	proof := make([]byte, len(clientKey))
	defer zero(proof)
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSignature[i]
	}
	serverKey := hmacSum(saltedPassword, []byte("Server Key"))
	defer zero(serverKey)
	c.serverSignature = hmacSum(serverKey, []byte(c.authMessage))
	c.continued = true
	return clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

// VerifyServerFinal verifies the server's proof before accepting AuthenticationOk.
func (c *Client) VerifyServerFinal(serverFinal string) error {
	if !c.continued || len(c.serverSignature) != sha256.Size {
		return ErrInvalidExchange
	}
	defer func() {
		zero(c.serverSignature)
		c.serverSignature = nil
		c.authMessage = ""
	}()
	attrs, err := parseAttributes(serverFinal)
	if err != nil {
		return err
	}
	if _, failed := attrs["e"]; failed {
		return fmt.Errorf("%w: upstream rejected SCRAM authentication", ErrInvalidExchange)
	}
	proof, ok := attrs["v"]
	if !ok || len(attrs) != 1 {
		return ErrInvalidExchange
	}
	got, err := base64.StdEncoding.DecodeString(proof)
	if err != nil || !hmac.Equal(got, c.serverSignature) {
		return ErrServerProof
	}
	return nil
}

func escapeUsername(username string) string {
	username = strings.ReplaceAll(username, "=", "=3D")
	return strings.ReplaceAll(username, ",", "=2C")
}

func parseAttributes(message string) (map[string]string, error) {
	if message == "" || len(message) > 16<<10 {
		return nil, ErrInvalidExchange
	}
	attrs := make(map[string]string)
	for _, item := range strings.Split(message, ",") {
		if len(item) < 2 || item[1] != '=' {
			return nil, ErrInvalidExchange
		}
		key := item[:1]
		if _, exists := attrs[key]; exists {
			return nil, ErrInvalidExchange
		}
		attrs[key] = item[2:]
	}
	return attrs, nil
}

func hmacSum(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	hLen := sha256.Size
	blocks := (keyLength + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	var counter [4]byte
	for block := 1; block <= blocks; block++ {
		counter[0] = byte(block >> 24)
		counter[1] = byte(block >> 16)
		counter[2] = byte(block >> 8)
		counter[3] = byte(block)
		u := hmacSum(password, append(append([]byte(nil), salt...), counter[:]...))
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			next := hmacSum(password, u)
			zero(u)
			u = next
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
		zero(t)
		zero(u)
	}
	return out[:keyLength]
}

// Purge clears the client-side credential and proof material when the exchange ends.
func (c *Client) Purge() {
	zero(c.password)
	zero(c.serverSignature)
	c.password = nil
	c.serverSignature = nil
	c.authMessage = ""
	c.clientFirstBare = ""
}

func zero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}
