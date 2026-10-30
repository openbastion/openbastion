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
