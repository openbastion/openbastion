package pgwire

import (
	"errors"
	"testing"
)

func TestValidateStartupParametersPinsUserAndDatabase(t *testing.T) {
	app, err := ValidateStartupParameters(map[string]string{
		"user": "readonly", "database": "ledger", "application_name": "psql", "client_encoding": "UTF8",
	}, "readonly", "ledger")
	if err != nil || app != "psql" {
		t.Fatalf("application name=%q err=%v", app, err)
	}
}

func TestValidateStartupParametersRejectsIdentityOverridesAndUnknownOptions(t *testing.T) {
	base := map[string]string{"user": "readonly", "database": "ledger"}
	cases := []map[string]string{
		{"user": "other", "database": "ledger"},
		{"user": "readonly", "database": "other"},
		{"user": "readonly", "database": "ledger", "options": "-c role=superuser"},
		{"user": "readonly", "database": "ledger", "replication": "true"},
		{"user": "readonly", "database": "ledger", "unknown_parameter": "x"},
		{"user": "readonly", "database": "ledger", "client_encoding": "LATIN1"},
		{"user": "readonly", "database": "ledger", "application_name": "bad\nname"},
	}
	for i, params := range cases {
		if _, err := ValidateStartupParameters(params, "readonly", "ledger"); err == nil {
			t.Errorf("case %d accepted: %#v", i, params)
		}
	}
	if _, err := ValidateStartupParameters(base, "", "ledger"); !errors.Is(err, ErrStartupIdentityMismatch) {
		t.Fatalf("empty approved user error = %v", err)
	}
}

func TestParseSimpleQueryAndRejectCopy(t *testing.T) {
	query, err := ParseSimpleQuery(FrontendMessage{Type: 'Q', Payload: []byte("select 1\x00")})
	if err != nil || query != "select 1" {
		t.Fatalf("query=%q err=%v", query, err)
	}
	for _, sql := range []string{"COPY t TO STDOUT", " /* lead */ copy t from stdin", "COPY (SELECT 1) TO STDOUT"} {
		if _, err := ParseSimpleQuery(FrontendMessage{Type: 'Q', Payload: append([]byte(sql), 0)}); !errors.Is(err, ErrCopyUnsupported) {
			t.Errorf("COPY query %q error = %v", sql, err)
		}
	}
}

func TestFingerprintSQLNormalizesWhitespaceAndCommentsWithoutStoringSQL(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	one, err := FingerprintSQL(key, "SELECT  1 -- comment\nFROM ledger")
	if err != nil {
		t.Fatal(err)
	}
	two, err := FingerprintSQL(key, "SELECT 1 FROM ledger")
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("equivalent SQL fingerprints differ: %s != %s", one, two)
	}
	literal, err := FingerprintSQL(key, "SELECT 'a  b' FROM ledger")
	if err != nil {
		t.Fatal(err)
	}
	literal2, err := FingerprintSQL(key, "SELECT 'a b' FROM ledger")
	if err != nil {
		t.Fatal(err)
	}
	if literal == literal2 {
		t.Fatal("whitespace inside a SQL string literal was normalized away")
	}
}
