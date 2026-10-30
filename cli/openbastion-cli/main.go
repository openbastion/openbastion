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
	"flag"
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

const usage = `usage:
  openbastion-cli user create -authn URL -username NAME -roles ROLE[,ROLE…] [-display NAME] < password
  openbastion-cli audit verify-chain -audit URL`

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 2 {
		return errors.New(usage)
	}
	switch args[0] + " " + args[1] {
	case "user create":
		return userCreate(args[2:], stdin, stdout)
	case "audit verify-chain":
		return verifyChain(args[2:], stdout)
	default:
		return errors.New(usage)
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

func userCreate(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	authn := fs.String("authn", "", "URL of the Authentication Service, e.g. https://authentication:8086")
	username := fs.String("username", "", "the new user's name")
	display := fs.String("display", "", "display name (defaults to the username)")
	roles := fs.String("roles", "", "comma-separated roles")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *authn == "" || *username == "" || *roles == "" {
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
	if *display == "" {
		*display = *username
	}
	var list []string
	for _, r := range strings.Split(*roles, ",") {
		if r = strings.TrimSpace(r); r != "" {
			list = append(list, r)
		}
	}
	c, err := client(*authn, mtls.Authentication)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"username": *username, "displayName": *display, "password": password, "roles": list})
	resp, err := c.Post(strings.TrimRight(*authn, "/")+"/auth/v1/users", "application/json", bytes.NewReader(body))
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
	fmt.Fprintf(stdout, "user %s created (%s) with roles %s\n", *username, created.ID, strings.Join(list, ","))
	return nil
}

func verifyChain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("audit verify-chain", flag.ContinueOnError)
	audit := fs.String("audit", "", "URL of the Audit Service, e.g. https://audit-service:8082")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *audit == "" {
		return errors.New("audit verify-chain needs -audit")
	}
	c, err := client(*audit, mtls.AuditService)
	if err != nil {
		return err
	}
	resp, err := c.Get(strings.TrimRight(*audit, "/") + "/audit/v1/verify-chain")
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
