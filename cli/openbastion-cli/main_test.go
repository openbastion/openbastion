package main

import (
	"bytes"
	"strings"
	"testing"
)

// What the CLI refuses before it touches the network (ADR-0033).
func TestRun_RefusesWhatCannotBeAskedRight(t *testing.T) {
	t.Setenv("INTERNAL_TLS", "required")
	for name, c := range map[string]struct {
		args  []string
		stdin string
		want  string
	}{
		"nothing":              {nil, "", "usage"},
		"an unknown command":   {[]string{"user", "delete"}, "", "usage"},
		"no Authentication":    {[]string{"user", "create", "-username", "a", "-roles", "r"}, "pw\n", "needs -authn"},
		"no username":          {[]string{"user", "create", "-authn", "https://authentication:8086", "-roles", "r"}, "pw\n", "needs -authn"},
		"no roles":             {[]string{"user", "create", "-authn", "https://authentication:8086", "-username", "a"}, "pw\n", "needs -authn"},
		"an empty password":    {[]string{"user", "create", "-authn", "https://authentication:8086", "-username", "a", "-roles", "r"}, "\n", "standard input"},
		"no Audit Service":     {[]string{"audit", "verify-chain"}, "", "needs -audit"},
		"a password argument":  {[]string{"user", "create", "-authn", "https://a:1", "-username", "a", "-roles", "r", "-password", "x"}, "pw\n", "-password"},
		"no certificate given": {[]string{"audit", "verify-chain", "-audit", "https://audit-service:8082"}, "", "TLS_"},
		// ADR-0062: one account, named one way.
		"mfa code, no Authentication":   {[]string{"mfa", "enrollment-code", "-local", "alice"}, "", "needs -authn and one of"},
		"mfa code, no account":          {[]string{"mfa", "enrollment-code", "-authn", "https://a:1"}, "", "needs -authn and one of"},
		"mfa code, two ways to name it": {[]string{"mfa", "enrollment-code", "-authn", "https://a:1", "-local", "a", "-directory", "a"}, "", "needs -authn and one of"},
		"mfa reset, no account":         {[]string{"mfa", "reset", "-authn", "https://a:1"}, "", "needs -authn and -username"},
		"mfa code, no certificate":      {[]string{"mfa", "enrollment-code", "-authn", "https://authentication:8086", "-local", "alice"}, "", "TLS_"},
	} {
		err := run(c.args, strings.NewReader(c.stdin), &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want an error mentioning %q", name, err, c.want)
		}
	}
}

func TestRun_WithoutMutualTLSItRefusesToCallAnything(t *testing.T) {
	t.Setenv("INTERNAL_TLS", "disabled")
	err := run([]string{"audit", "verify-chain", "-audit", "https://audit-service:8082"}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "INTERNAL_TLS must be required") {
		t.Fatalf("got %v", err)
	}
}
