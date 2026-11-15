package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/openbastion/openbastion/pkg/mtls"
)

const maxSecretInjectionResponseBytes = 1 << 20

type secretInjectionOutcome struct {
	InjectionID string `json:"injection_id"`
	SessionID   string `json:"session_id"`
	AccountID   string `json:"account_id"`
	Protocol    string `json:"protocol"`
	Emitter     string `json:"emitter,omitempty"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	StartEvent  string `json:"start_event_id,omitempty"`
	ResultEvent string `json:"result_event_id,omitempty"`
}

type secretInjectionReconciliation struct {
	Outcomes                []secretInjectionOutcome `json:"outcomes"`
	Coverage                string                   `json:"coverage"`
	ArchivedHistoryExcluded bool                     `json:"archived_history_excluded"`
	ScannedEvents           int                      `json:"scanned_events"`
	ArchivedEvents          int                      `json:"archived_events"`
	HasMore                 bool                     `json:"has_more"`
	NextBefore              string                   `json:"next_before,omitempty"`
}

// secretInjections uses only the admin-cli mTLS identity. The endpoint is intentionally
// not routed through the public Gateway (ADR-0112); the browser must never receive this key.
func secretInjections(ctx context.Context, audit string, limit int, before, output string, stdout io.Writer) error {
	if audit == "" {
		return errors.New("audit secret-injections needs -audit")
	}
	if limit < 1 || limit > 500 {
		return errors.New("audit secret-injections -limit must be between 1 and 500")
	}
	if before != "" && !validReconciliationCursor(before) {
		return errors.New("audit secret-injections -before must be a 32-character lowercase hexadecimal injection ID")
	}
	if output != "table" && output != "json" {
		return errors.New("audit secret-injections -output must be table or json")
	}
	c, err := client(audit, mtls.AuditService)
	if err != nil {
		return err
	}
	return fetchSecretInjections(ctx, c, audit, limit, before, output, stdout)
}

func fetchSecretInjections(ctx context.Context, c *http.Client, audit string, limit int, before, output string, stdout io.Writer) error {
	base, err := url.Parse(strings.TrimRight(audit, "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("audit secret-injections needs an HTTPS Audit Service URL without credentials, query or fragment")
	}
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/audit/v1/secret-injections"
	query := endpoint.Query()
	query.Set("limit", fmt.Sprint(limit))
	if before != "" {
		query.Set("before", before)
	}
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.New("audit secret-injections: invalid request URL")
	}
	// Do not follow even same-host redirects: this operator endpoint has one fixed path,
	// and its mTLS identity must never be carried to a redirect target.
	safeClient := *c
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := safeClient.Do(req)
	if err != nil {
		return fmt.Errorf("audit secret-injections: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("audit secret-injections: Audit Service returned HTTP %d", resp.StatusCode)
	}
	if !hasNoStore(resp.Header.Get("Cache-Control")) {
		return errors.New("audit secret-injections: refusing a response without Cache-Control: no-store")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSecretInjectionResponseBytes+1))
	if err != nil {
		return errors.New("audit secret-injections: response could not be read")
	}
	if len(raw) > maxSecretInjectionResponseBytes {
		return errors.New("audit secret-injections: response exceeds the 1 MiB client limit")
	}
	var result secretInjectionReconciliation
	if err := json.Unmarshal(raw, &result); err != nil {
		return errors.New("audit secret-injections: Audit Service returned an invalid response")
	}
	if err := validateSecretInjectionReconciliation(result); err != nil {
		return err
	}
	if output == "json" {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return errors.New("audit secret-injections: response could not be encoded")
		}
		_, err = fmt.Fprintln(stdout, string(encoded))
		return err
	}
	return writeSecretInjectionTable(stdout, result)
}

func validateSecretInjectionReconciliation(result secretInjectionReconciliation) error {
	if result.ArchivedHistoryExcluded || result.ArchivedEvents < 0 || result.ScannedEvents < result.ArchivedEvents {
		return errors.New("audit secret-injections: response does not prove complete archive coverage")
	}
	if result.Coverage != "retained_audit_chain" && result.Coverage != "verified_archives_and_retained_chain" {
		return errors.New("audit secret-injections: response has an unknown coverage value")
	}
	if result.ArchivedEvents > 0 && result.Coverage != "verified_archives_and_retained_chain" {
		return errors.New("audit secret-injections: archived events lack verified archive coverage")
	}
	if result.HasMore {
		if len(result.Outcomes) == 0 || !validReconciliationCursor(result.NextBefore) || result.NextBefore != result.Outcomes[len(result.Outcomes)-1].InjectionID {
			return errors.New("audit secret-injections: response has an invalid pagination cursor")
		}
	}
	for _, outcome := range result.Outcomes {
		if !validReconciliationCursor(outcome.InjectionID) {
			return errors.New("audit secret-injections: response contains an invalid injection ID")
		}
		switch outcome.Status {
		case "completed", "failed", "outcome_unknown":
		default:
			return errors.New("audit secret-injections: response contains an unknown outcome status")
		}
	}
	return nil
}

func validReconciliationCursor(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

func writeSecretInjectionTable(stdout io.Writer, result secretInjectionReconciliation) error {
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "INJECTION ID\tSESSION\tACCOUNT\tPROTOCOL\tSTATUS\tSTARTED\tREASON")
	for _, outcome := range result.Outcomes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", outcome.InjectionID, terminalField(outcome.SessionID), terminalField(outcome.AccountID), terminalField(outcome.Protocol), outcome.Status, terminalField(outcome.StartedAt), terminalField(outcome.Reason))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "coverage=%s scanned_events=%d archived_events=%d archived_history_excluded=%t\n", result.Coverage, result.ScannedEvents, result.ArchivedEvents, result.ArchivedHistoryExcluded)
	if result.HasMore {
		fmt.Fprintf(stdout, "more results: repeat with -before %s\n", result.NextBefore)
	}
	if len(result.Outcomes) == 0 {
		fmt.Fprintln(stdout, "No secret injection evidence on this page.")
	}
	return nil
}

func hasNoStore(header string) bool {
	for _, directive := range strings.Split(header, ",") {
		name := strings.TrimSpace(strings.SplitN(directive, "=", 2)[0])
		if strings.EqualFold(name, "no-store") {
			return true
		}
	}
	return false
}

// terminalField prevents audit metadata from forging rows or terminal control sequences.
func terminalField(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return '�'
		}
		return r
	}, value)
}
