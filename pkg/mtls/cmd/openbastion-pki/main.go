// Command openbastion-pki is a small certificate authority for OpenBastion's
// internal mTLS (ADR-0010) — for development and for tests. A production
// deployment issues the same shape of certificate from its own infrastructure.
//
//	openbastion-pki init  -dir .pki [-trust-domain openbastion.local] [-ttl 8760h]
//	openbastion-pki issue -dir .pki -service password-vault [-ttl 24h] [-dns a,b] [-ip 10.0.0.1]
//	openbastion-pki all   -dir .pki [-ttl 168h]      (init if needed, then every standard service)
//
// Run issue (or all) again to renew: running services pick up the new files
// without a restart.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", ".pki", "PKI directory")
	domain := fs.String("trust-domain", mtls.DefaultTrustDomain, "SPIFFE trust domain")
	ttl := fs.Duration("ttl", 0, "lifetime (init: default 8760h; issue and all: default 24h and 168h)")
	service := fs.String("service", "", "service name (issue)")
	dns := fs.String("dns", "", "comma-separated DNS names to add to the certificate (issue); replaces the defaults")
	ips := fs.String("ip", "", "comma-separated IP addresses to add to the certificate (issue); replaces the defaults")
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "init":
		err = runInit(*dir, *domain, *ttl)
	case "issue":
		err = runIssue(*dir, *domain, *service, *ttl, *dns, *ips)
	case "all":
		err = runAll(*dir, *domain, *ttl)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "openbastion-pki:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: openbastion-pki init|issue|all -dir DIR [flags]  (see the package documentation)")
	os.Exit(2)
}

func runInit(dir, domain string, ttl time.Duration) error {
	if ttl == 0 {
		ttl = 365 * 24 * time.Hour
	}
	if _, err := pki.InitDir(dir, domain, ttl); err != nil {
		return err
	}
	fmt.Printf("created the authority for %s in %s (valid %s)\n", domain, dir, ttl)
	return nil
}

func runIssue(dir, domain, service string, ttl time.Duration, dns, ips string) error {
	if service == "" {
		return errors.New("issue needs -service")
	}
	ca, err := pki.LoadDir(dir, domain)
	if err != nil {
		return err
	}
	opts := pki.IssueOptions{TTL: ttl}
	if dns != "" {
		opts.DNSNames = split(dns)
	}
	if ips != "" {
		for _, s := range split(ips) {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("%q is not an IP address", s)
			}
			opts.IPs = append(opts.IPs, ip)
		}
	}
	leaf, err := pki.IssueToDir(ca, dir, service, opts)
	if err != nil {
		return err
	}
	fmt.Printf("issued %s (valid until %s): %s, %s\n", service, leaf.Cert.NotAfter.UTC().Format(time.RFC3339),
		pki.CertFile(dir, service), pki.KeyFile(dir, service))
	return nil
}

func runAll(dir, domain string, ttl time.Duration) error {
	if _, err := pki.InitDir(dir, domain, 365*24*time.Hour); err != nil && !errors.Is(err, pki.ErrCAExists) {
		return err
	}
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	ca, err := pki.LoadDir(dir, domain)
	if err != nil {
		return err
	}
	for _, svc := range pki.StandardServices {
		if _, err := pki.IssueToDir(ca, dir, svc, pki.IssueOptions{TTL: ttl}); err != nil {
			return err
		}
	}
	fmt.Printf("issued %d identities in %s, valid %s; the authority's key stays in %s/ca-key.pem\n", len(pki.StandardServices), dir, ttl, dir)
	return nil
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
