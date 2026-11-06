package main

import (
	"errors"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/command"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "openbastion-pki",
		Short:         "Gère l'autorité et les identités mTLS OpenBastion",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          func(*cobra.Command, []string) error { return errors.New("expected init, issue, all, or version") },
	}
	root.AddCommand(newInitCommand(), newIssueCommand(), newAllCommand(), command.NewVersionCommand())
	return root
}

func newInitCommand() *cobra.Command {
	var dir, domain string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Crée l'autorité de certification",
		Args:  cobra.NoArgs,
		RunE:  func(_ *cobra.Command, _ []string) error { return runInit(dir, domain, ttl) },
	}
	cmd.Flags().StringVar(&dir, "dir", ".pki", "PKI directory")
	cmd.Flags().StringVar(&domain, "trust-domain", mtls.DefaultTrustDomain, "SPIFFE trust domain")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "authority lifetime (default 8760h)")
	return cmd
}

func newIssueCommand() *cobra.Command {
	var dir, domain, service, dns, ips string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Émet ou renouvelle une identité de service",
		Args:  cobra.NoArgs,
		RunE:  func(_ *cobra.Command, _ []string) error { return runIssue(dir, domain, service, ttl, dns, ips) },
	}
	cmd.Flags().StringVar(&dir, "dir", ".pki", "PKI directory")
	cmd.Flags().StringVar(&domain, "trust-domain", mtls.DefaultTrustDomain, "SPIFFE trust domain")
	cmd.Flags().StringVar(&service, "service", "", "service name (required)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "certificate lifetime (default 24h)")
	cmd.Flags().StringVar(&dns, "dns", "", "comma-separated DNS names; replaces defaults")
	cmd.Flags().StringVar(&ips, "ip", "", "comma-separated IP addresses; replaces defaults")
	return cmd
}

func newAllCommand() *cobra.Command {
	var dir, domain string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "all",
		Short: "Initialise l'autorité si nécessaire et émet les identités standard",
		Args:  cobra.NoArgs,
		RunE:  func(_ *cobra.Command, _ []string) error { return runAll(dir, domain, ttl) },
	}
	cmd.Flags().StringVar(&dir, "dir", ".pki", "PKI directory")
	cmd.Flags().StringVar(&domain, "trust-domain", mtls.DefaultTrustDomain, "SPIFFE trust domain")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "certificate lifetime (default 168h)")
	return cmd
}

// normalizeLegacyFlags preserves the historical single-dash long options while
// Cobra/pflag uses the conventional double-dash form internally.
func normalizeLegacyFlags(args []string) []string {
	known := map[string]struct{}{"dir": {}, "trust-domain": {}, "ttl": {}, "service": {}, "dns": {}, "ip": {}}
	out := make([]string, len(args))
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			name := strings.TrimPrefix(arg, "-")
			if equal := strings.IndexByte(name, '='); equal >= 0 {
				name = name[:equal]
			}
			if _, ok := known[name]; ok {
				out[i] = "-" + arg
				continue
			}
		}
		out[i] = arg
	}
	return out
}
