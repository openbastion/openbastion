package proxycore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type secretInjectionStep struct {
	name      string
	evidence  SecretInputEvidence
	err       error
	resultErr error
	secret    []byte
	steps     *[]string
}

func (s *secretInjectionStep) AuditSecretInput(_ context.Context, evidence SecretInputEvidence) error {
	*s.steps = append(*s.steps, s.name)
	s.evidence = evidence
	return s.err
}
func (s *secretInjectionStep) AuditSecretInputResult(_ context.Context, evidence SecretInputEvidence, _ bool) error {
	*s.steps = append(*s.steps, "audit-result")
	s.evidence = evidence
	return s.resultErr
}

func (s *secretInjectionStep) RecordSecretInput(_ context.Context, evidence SecretInputEvidence) error {
	*s.steps = append(*s.steps, s.name)
	s.evidence = evidence
	return s.err
}

func (s *secretInjectionStep) TypeSecret(_ context.Context, secret []byte) error {
	*s.steps = append(*s.steps, s.name)
	s.secret = append([]byte(nil), secret...)
	return s.err
}

func (s *secretInjectionStep) WithExclusiveInput(_ context.Context, operation func() error) error {
	return operation()
}

func TestInjectSecret_AuditsAndRecordsOnlyEvidenceBeforeTyping(t *testing.T) {
	for _, source := range []SecretInputSource{SecretInputVault, SecretInputOperator} {
		t.Run(string(source), func(t *testing.T) {
			secret := []byte("never-record-this-value")
			steps := []string{}
			audit := &secretInjectionStep{name: "audit", steps: &steps}
			record := &secretInjectionStep{name: "record", steps: &steps}
			typer := &secretInjectionStep{name: "type", steps: &steps}

			err := InjectSecret(context.Background(), "session-1", "rdp", source, "account-1", secret, audit, record, typer)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(steps, []string{"audit", "record", "type", "audit-result"}) {
				t.Fatalf("steps = %v", steps)
			}
			if !bytes.Equal(typer.secret, []byte("never-record-this-value")) {
				t.Fatalf("typed bytes = %q", typer.secret)
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("caller secret was not zeroed")
			}
			for _, evidence := range []SecretInputEvidence{audit.evidence, record.evidence} {
				if evidence.SessionID != "session-1" || evidence.Protocol != "rdp" || evidence.Source != source {
					t.Fatalf("wrong evidence identity: %+v", evidence)
				}
				if source == SecretInputVault {
					if evidence.AccountID != "account-1" || evidence.Length != 0 || evidence.SHA256 != "" {
						t.Fatalf("Vault evidence exposed more than its reference: %+v", evidence)
					}
				} else {
					sum := sha256.Sum256([]byte("never-record-this-value"))
					if evidence.AccountID != "account-1" || evidence.Length != len("never-record-this-value") ||
						evidence.SHA256 != hex.EncodeToString(sum[:]) {
						t.Fatalf("operator evidence is incomplete or unsafe: %+v", evidence)
					}
				}
			}
		})
	}
}

func TestInjectSecret_FailsClosedBeforeTyping(t *testing.T) {
	for _, failed := range []string{"audit", "record", "type"} {
		t.Run(failed, func(t *testing.T) {
			secret := []byte("sensitive")
			steps := []string{}
			audit := &secretInjectionStep{name: "audit", steps: &steps}
			record := &secretInjectionStep{name: "record", steps: &steps}
			typer := &secretInjectionStep{name: "type", steps: &steps}
			switch failed {
			case "audit":
				audit.err = errors.New("dependency detail must not escape")
			case "record":
				record.err = errors.New("dependency detail must not escape")
			case "type":
				typer.err = errors.New("target detail must not escape")
			}

			err := InjectSecret(context.Background(), "session-1", "ssh", SecretInputOperator, "account-1", secret, audit, record, typer)
			if !errors.Is(err, ErrSecretInjectionUnavailable) {
				t.Fatalf("InjectSecret error = %v", err)
			}
			if bytes.Contains([]byte(err.Error()), []byte("dependency detail")) ||
				bytes.Contains([]byte(err.Error()), []byte("target detail")) ||
				bytes.Contains([]byte(err.Error()), []byte("sensitive")) {
				t.Fatalf("unsafe error: %v", err)
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("caller secret was not zeroed after failure")
			}
			if failed == "audit" && !reflect.DeepEqual(steps, []string{"audit"}) {
				t.Fatalf("audit failure steps = %v", steps)
			}
			if failed == "record" && !reflect.DeepEqual(steps, []string{"audit", "record", "audit-result"}) {
				t.Fatalf("record failure steps = %v", steps)
			}
			if failed == "type" && !reflect.DeepEqual(steps, []string{"audit", "record", "type", "audit-result"}) {
				t.Fatalf("typing failure steps = %v", steps)
			}
		})
	}
}

func TestInjectSecret_RejectsIncompleteRequestAndStillPurges(t *testing.T) {
	secret := []byte("sensitive")
	if err := InjectSecret(context.Background(), "session-1", "ssh", SecretInputVault, "", secret,
		&secretInjectionStep{}, &secretInjectionStep{}, &secretInjectionStep{}); !errors.Is(err, ErrSecretInjectionInvalid) {
		t.Fatalf("InjectSecret error = %v", err)
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("invalid request did not purge the caller secret")
	}
}

func TestInjectSecret_OperatorInputIsOneBoundedLine(t *testing.T) {
	for name, value := range map[string][]byte{
		"too long":        []byte(strings.Repeat("x", 129)),
		"carriage return": []byte("password\r"),
		"line feed":       []byte("password\n"),
		"tab":             []byte("password\t"),
		"control":         []byte{'p', 0x01, 'w'},
		"invalid UTF-8":   {0xff, 0xfe},
	} {
		t.Run(name, func(t *testing.T) {
			secret := append([]byte(nil), value...)
			steps := []string{}
			audit := &secretInjectionStep{name: "audit", steps: &steps}
			record := &secretInjectionStep{name: "record", steps: &steps}
			typer := &secretInjectionStep{name: "type", steps: &steps}
			err := InjectSecret(context.Background(), "session-1", "ssh", SecretInputOperator,
				"target-prod", secret, audit, record, typer)
			if !errors.Is(err, ErrSecretInjectionInvalid) {
				t.Fatalf("InjectSecret error = %v, want invalid", err)
			}
			if len(steps) != 0 {
				t.Fatalf("invalid secret reached a dependency: %v", steps)
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("invalid secret buffer was not purged")
			}
		})
	}
}

func TestInjectSecret_ResultAuditFailureIsReportedAfterTyping(t *testing.T) {
	secret := []byte("password")
	steps := []string{}
	audit := &secretInjectionStep{name: "audit", steps: &steps, resultErr: errors.New("audit unavailable")}
	record := &secretInjectionStep{name: "record", steps: &steps}
	typer := &secretInjectionStep{name: "type", steps: &steps}
	err := InjectSecret(context.Background(), "session-1", "ssh", SecretInputVault, "account-1", secret, audit, record, typer)
	if !errors.Is(err, ErrSecretInjectionUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if !reflect.DeepEqual(steps, []string{"audit", "record", "type", "audit-result"}) {
		t.Fatalf("steps=%v", steps)
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("secret not purged")
	}
}

func TestInjectSecret_RejectsMultilineVaultSecretAndPurges(t *testing.T) {
	secret := []byte("password\nwhoami")
	steps := []string{}
	audit := &secretInjectionStep{name: "audit", steps: &steps}
	recorder := &secretInjectionStep{name: "record", steps: &steps}
	typer := &secretInjectionStep{name: "type", steps: &steps}
	err := InjectSecret(context.Background(), "session-1", "ssh", SecretInputVault, "account-1", secret, audit, recorder, typer)
	if !errors.Is(err, ErrSecretInjectionInvalid) {
		t.Fatalf("err=%v", err)
	}
	if len(steps) != 0 {
		t.Fatalf("multiline Vault value reached dependencies: %v", steps)
	}
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("secret byte %d not purged", i)
		}
	}
}
