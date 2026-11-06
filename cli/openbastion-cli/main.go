// Command openbastion-cli is the operator's tool (ADR-0033). It speaks to the internal routes
// under the admin-cli identity, from the certificate the environment names (INTERNAL_TLS,
// TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE — as every service). It does what a new
// installation cannot do through the public API: create the first users, and verify the audit
// chain.
//
//	openbastion-cli user create -authn https://authentication:8086 -username alice -roles platform-admin,vault-admin < password
//	openbastion-cli audit verify-chain -audit https://audit-service:8082
//
// A password is read from standard input, never from an argument (an argument is in the
// process list and the shell history).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "openbastion-cli:", err)
		os.Exit(1)
	}
}

// client is an http.Client that reaches exactly one peer, which must prove it is `service`.
func client(url, service string) (*http.Client, error) {
	rt, err := mtls.Setup(mtls.AdminCLI)
	if err != nil {
		return nil, err
	}
	if !rt.Enabled() {
		return nil, errors.New("INTERNAL_TLS must be required: the internal routes are reached only under the admin-cli identity")
	}
	return rt.Client(mtls.Peer{URL: url, Service: service})
}

func userCreate(authn, username, display, roles string, stdin io.Reader, stdout io.Writer) error {
	if authn == "" || username == "" || roles == "" {
		return errors.New("user create needs -authn, -username and -roles")
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return errors.New("user create reads the password from standard input, and it is empty")
	}
	if display == "" {
		display = username
	}
	var list []string
	for _, r := range strings.Split(roles, ",") {
		if r = strings.TrimSpace(r); r != "" {
			list = append(list, r)
		}
	}
	c, err := client(authn, mtls.Authentication)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"username": username, "displayName": display, "password": password, "roles": list})
	resp, err := c.Post(strings.TrimRight(authn, "/")+"/auth/v1/users", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("user create: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &created)
	fmt.Fprintf(stdout, "user %s created (%s) with roles %s\n", username, created.ID, strings.Join(list, ","))
	return nil
}

func verifyChain(audit string, stdout io.Writer) error {
	if audit == "" {
		return errors.New("audit verify-chain needs -audit")
	}
	c, err := client(audit, mtls.AuditService)
	if err != nil {
		return err
	}
	resp, err := c.Get(strings.TrimRight(audit, "/") + "/audit/v1/verify-chain")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the audit chain does not verify: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	fmt.Fprintf(stdout, "the audit chain verifies: %s\n", strings.TrimSpace(string(raw)))
	return nil
}

// mfaEnrollmentCode issues a one-time code with which an account enrolls its second factor
// (ADR-0062): for a local account by its name, for a directory account by its login name. The
// code is shown once, here; give it to the user by another channel than the password.
func mfaEnrollmentCode(authn, local, directory string, stdout io.Writer) error {
	if authn == "" || (local == "") == (directory == "") {
		return errors.New("mfa enrollment-code needs -authn and one of -local or -directory")
	}
	source, name := "local", local
	if directory != "" {
		source, name = "ldap", directory
	}
	c, err := client(authn, mtls.Authentication)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"source": source, "loginName": name})
	resp, err := c.Post(strings.TrimRight(authn, "/")+"/auth/v1/mfa/enrollment-codes", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mfa enrollment-code: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		EnrollmentCode string `json:"enrollmentCode"`
		ExpiresAt      string `json:"expiresAt"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.EnrollmentCode == "" {
		return errors.New("mfa enrollment-code: the answer holds no code")
	}
	fmt.Fprintf(stdout, "enrollment code for %s account %s, valid until %s (shown once):\n%s\n", source, name, out.ExpiresAt, out.EnrollmentCode)
	return nil
}

// mfaReset forgets an account's second factor (a lost device); it enrolls again with a new code.
func mfaReset(authn, username string, stdout io.Writer) error {
	if authn == "" || username == "" {
		return errors.New("mfa reset needs -authn and -username")
	}
	c, err := client(authn, mtls.Authentication)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"username": username})
	resp, err := c.Post(strings.TrimRight(authn, "/")+"/auth/v1/mfa/reset", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("mfa reset: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	fmt.Fprintf(stdout, "the second factor of %s was reset: it enrolls again with a new enrollment code\n", username)
	return nil
}

// mfaKeys lists an account's security keys (ADR-0066): which one to revoke when one is lost.
func mfaKeys(authn, username string, stdout io.Writer) error {
	if authn == "" || username == "" {
		return errors.New("mfa keys needs -authn and -username")
	}
	c, err := client(authn, mtls.Authentication)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"username": username})
	resp, err := c.Post(strings.TrimRight(authn, "/")+"/auth/v1/mfa/keys", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mfa keys: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Keys []struct {
			KeyID, CreatedAt, LastUsedAt string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return errors.New("mfa keys: the answer cannot be read")
	}
	if len(out.Keys) == 0 {
		fmt.Fprintf(stdout, "%s has no security key\n", username)
		return nil
	}
	for _, k := range out.Keys {
		last := k.LastUsedAt
		if last == "" {
			last = "never"
		}
		fmt.Fprintf(stdout, "%s  enrolled %s  last used %s\n", k.KeyID, k.CreatedAt, last)
	}
	return nil
}

// mfaRevokeKey revokes one security key of an account (ADR-0066); the others stay.
func mfaRevokeKey(authn, username, key string, stdout io.Writer) error {
	if authn == "" || username == "" || key == "" {
		return errors.New("mfa revoke-key needs -authn, -username and -key")
	}
	c, err := client(authn, mtls.Authentication)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"username": username, "keyId": key})
	resp, err := c.Post(strings.TrimRight(authn, "/")+"/auth/v1/mfa/revoke-key", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("mfa revoke-key: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	fmt.Fprintf(stdout, "the key %s of %s was revoked; its other keys stay\n", key, username)
	return nil
}
