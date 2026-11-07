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
		"mfa code, no Authentication":    {[]string{"mfa", "enrollment-code", "-local", "alice"}, "", "needs -authn and one of"},
		"mfa code, no account":           {[]string{"mfa", "enrollment-code", "-authn", "https://a:1"}, "", "needs -authn and one of"},
		"mfa code, two ways to name it":  {[]string{"mfa", "enrollment-code", "-authn", "https://a:1", "-local", "a", "-directory", "a"}, "", "needs -authn and one of"},
		"mfa code, a directory id alone": {[]string{"mfa", "enrollment-code", "-authn", "https://a:1", "-local", "a", "-directory-id", "ad"}, "", "-directory-id goes with -directory"},
		"mfa reset, no account":          {[]string{"mfa", "reset", "-authn", "https://a:1"}, "", "needs -authn and -username"},
		"mfa code, no certificate":       {[]string{"mfa", "enrollment-code", "-authn", "https://authentication:8086", "-local", "alice"}, "", "TLS_"},
		// ADR-0066.
		"mfa keys, no account":       {[]string{"mfa", "keys", "-authn", "https://a:1"}, "", "needs -authn and -username"},
		"mfa revoke-key, no key":     {[]string{"mfa", "revoke-key", "-authn", "https://a:1", "-username", "a"}, "", "needs -authn, -username and -key"},
		"mfa revoke-key, no account": {[]string{"mfa", "revoke-key", "-authn", "https://a:1", "-key", "AQ"}, "", "needs -authn, -username and -key"},
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

func TestRun_VersionSupportsDetailedAndShortOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "short", args: []string{"version", "--short"}, want: "dev\n"},
		{name: "short legacy single dash", args: []string{"version", "-short"}, want: "dev\n"},
		{name: "detailed", args: []string{"version"}, want: "Version:           dev\nGo version:        "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := run(tc.args, strings.NewReader(""), &out); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(out.String(), tc.want) {
				t.Fatalf("output = %q, want prefix %q", out.String(), tc.want)
			}
		})
	}
}

func TestRun_LegacySingleDashLongFlagsRemainSupported(t *testing.T) {
	t.Setenv("INTERNAL_TLS", "disabled")
	err := run([]string{"audit", "verify-chain", "-audit", "https://audit-service:8082"}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "INTERNAL_TLS must be required") {
		t.Fatalf("legacy -audit flag was not parsed: %v", err)
	}
}

func TestRun_RejectsPositionalArgumentsAndPasswordFlags(t *testing.T) {
	for _, args := range [][]string{
		{"audit", "verify-chain", "--audit", "https://audit-service:8082", "unexpected"},
		{"user", "create", "--authn", "https://a:1", "--username", "alice", "--roles", "admin", "--password", "secret"},
	} {
		if err := run(args, strings.NewReader("password\n"), &bytes.Buffer{}); err == nil {
			t.Fatalf("run(%v) unexpectedly succeeded", args)
		}
	}
}

func TestRun_HelpListsExistingCommands(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"user", "audit", "mfa", "version"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help output does not contain %q: %s", want, out.String())
		}
	}
}
