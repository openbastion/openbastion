package integration_test

// ADR-0050: the internal routes speak HTTP/JSON under mutual TLS, with the field names of the
// messages in proto/ — the contract a gRPC implementation would have. This test holds them to it,
// both ways: a JSON field that is not in its message, or a message field that the route does not
// carry, fails the test unless it is declared below, with its reason. And every struct with
// snake_case JSON fields in a service's interfaces or infrastructure must be in the table: a new
// internal route cannot escape the check.
//
// It reads source, not packages (go/parser, and a small reader of .proto messages): the structs
// are unexported and live in internal packages, which this module may not import.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type contractPair struct {
	file, goStruct string // the Go file (from the repository root) and its struct
	proto, message string // the .proto file and its message
	// jsonOnly and protoOnly are the declared divergences, field → reason.
	jsonOnly, protoOnly map[string]string
}

// Reasons used more than once.
const (
	whyContext   = "RequestContext is not carried: the caller is the certificate's (ADR-0010), the actor is a flat field"
	whyActor     = "context.actor_user_id, flattened"
	whyTTL       = "a duration rather than an absolute expires_at: the callee's clock decides the end"
	whyExpiresAt = "carried as ttl_seconds"
	whySignature = "the chain signs every event itself (HMAC, ADR-0027); an emitter's signature is not carried"
)

var contractPairs = []contractPair{
	{"services/recording-audit/audit-service/internal/interfaces/http.go", "emitEventRequest", "proto/audit/v1/audit.proto", "EmitEventRequest",
		map[string]string{"actor_id": whyActor}, map[string]string{"context": whyContext, "signature": whySignature}},
	{"services/recording-audit/audit-service/internal/interfaces/http.go", "emitEventResponse", "proto/audit/v1/audit.proto", "EmitEventResponse",
		nil, map[string]string{"ts": "the event's time stays in the chain; the emitter needs only the id"}},
	{"services/access/session-broker/internal/infrastructure/audit_client.go", "emitEventRequestBody", "proto/audit/v1/audit.proto", "EmitEventRequest",
		map[string]string{"actor_id": whyActor}, map[string]string{"context": whyContext, "signature": whySignature}},
	{"services/recording-audit/command-recorder/internal/infrastructure/audit_client.go", "emitEventRequestBody", "proto/audit/v1/audit.proto", "EmitEventRequest",
		map[string]string{"actor_id": whyActor}, map[string]string{"context": whyContext, "signature": whySignature}},
	{"services/vault/password-vault/internal/interfaces/http.go", "authorizeScopeRequest", "proto/vault/v1/vault.proto", "AuthorizeScopeRequest",
		map[string]string{"ttl_seconds": whyTTL}, map[string]string{"context": whyContext, "expires_at": whyExpiresAt}},
	{"services/access/session-broker/internal/infrastructure/vault_client.go", "authorizeScopeRequestBody", "proto/vault/v1/vault.proto", "AuthorizeScopeRequest",
		map[string]string{"ttl_seconds": whyTTL}, map[string]string{"context": whyContext, "expires_at": whyExpiresAt}},
	{"services/vault/password-vault/internal/interfaces/http.go", "authorizeScopeResponse", "proto/vault/v1/vault.proto", "AuthorizeScopeResponse", nil, nil},
	{"services/access/session-broker/internal/infrastructure/vault_client.go", "authorizeScopeResponseBody", "proto/vault/v1/vault.proto", "AuthorizeScopeResponse", nil, nil},
	{"services/vault/password-vault/internal/interfaces/http.go", "fetchCredentialRequest", "proto/vault/v1/vault.proto", "FetchCredentialRequest", nil, nil},
	{"services/vault/password-vault/internal/interfaces/http.go", "fetchCredentialResponse", "proto/vault/v1/vault.proto", "FetchCredentialResponse",
		nil, map[string]string{"valid_until": "the material is good for one connection; the scope's end was checked when it was redeemed"}},
	{"services/proxy/ssh-proxy/internal/interfaces/http.go", "establishSessionRequest", "proto/proxy/v1/proxy_control.proto", "EstablishSessionRequest",
		map[string]string{"ttl_seconds": whyTTL}, map[string]string{"context": whyContext, "expires_at": whyExpiresAt}},
	{"services/proxy/ssh-proxy/internal/interfaces/http.go", "establishSessionResponse", "proto/proxy/v1/proxy_control.proto", "EstablishSessionResponse", nil, nil},
	{"services/proxy/ssh-proxy/internal/interfaces/http.go", "revokeSessionRequest", "proto/proxy/v1/proxy_control.proto", "TerminateSessionRequest",
		map[string]string{"ttl_seconds": "how long the proxy must remember the revocation (ADR-0018)"},
		map[string]string{"context": whyContext}},
	{"services/proxy/ssh-proxy/internal/interfaces/http.go", "revokeSessionResponse", "proto/proxy/v1/proxy_control.proto", "TerminateSessionResponse",
		map[string]string{"tickets_revoked": "what was cut, for the Broker's log", "connections_cut": "what was cut, for the Broker's log"},
		map[string]string{"terminated": "the status says it: 200 only once nothing of the session is open (ADR-0018)"}},
	{"services/proxy/ssh-proxy/internal/infrastructure/command_recorder_client.go", "wireEntry", "proto/recording/v1/recording.proto", "CommandEntry", nil, nil},
	{"services/recording-audit/command-recorder/internal/interfaces/http.go", "commandEntryRequest", "proto/recording/v1/recording.proto", "CommandEntry", nil, nil},
	{"services/recording-audit/command-recorder/internal/interfaces/http.go", "recordResponse", "proto/recording/v1/recording.proto", "StreamAck", nil, nil},
	// The clients' side of the same routes (they built their bodies as maps before).
	{"services/access/session-broker/internal/infrastructure/proxy_client.go", "establishSessionRequestBody", "proto/proxy/v1/proxy_control.proto", "EstablishSessionRequest",
		map[string]string{"ttl_seconds": whyTTL}, map[string]string{"context": whyContext, "expires_at": whyExpiresAt}},
	{"services/access/session-broker/internal/infrastructure/proxy_client.go", "establishSessionResponseBody", "proto/proxy/v1/proxy_control.proto", "EstablishSessionResponse", nil, nil},
	{"services/access/session-broker/internal/infrastructure/proxy_client.go", "revokeSessionRequestBody", "proto/proxy/v1/proxy_control.proto", "TerminateSessionRequest",
		map[string]string{"ttl_seconds": "how long the proxy must remember the revocation (ADR-0018)"}, map[string]string{"context": whyContext}},
	{"services/proxy/ssh-proxy/internal/infrastructure/vault_client.go", "fetchCredentialRequestBody", "proto/vault/v1/vault.proto", "FetchCredentialRequest", nil, nil},
	{"services/proxy/ssh-proxy/internal/infrastructure/vault_client.go", "fetchCredentialResponseBody", "proto/vault/v1/vault.proto", "FetchCredentialResponse",
		nil, map[string]string{"valid_until": "the material is good for one connection; the scope's end was checked when it was redeemed"}},
	{"services/proxy/ssh-proxy/internal/infrastructure/audit_client.go", "emitEventRequestBody", "proto/audit/v1/audit.proto", "EmitEventRequest",
		map[string]string{"actor_id": whyActor}, map[string]string{"context": whyContext, "signature": whySignature}},
	{"services/vault/password-vault/internal/infrastructure/audit_client.go", "emitEventRequestBody", "proto/audit/v1/audit.proto", "EmitEventRequest",
		map[string]string{"actor_id": whyActor}, map[string]string{"context": whyContext, "signature": whySignature}},
	// ADR-0064: the Authentication Service writes logins and the second factor's gestures.
	{"services/access/authentication/internal/infrastructure/audit_client.go", "emitEventRequestBody", "proto/audit/v1/audit.proto", "EmitEventRequest",
		map[string]string{"actor_id": whyActor}, map[string]string{"context": whyContext, "signature": whySignature}},
}

// notMirrored are internal JSON structs with no message in proto/, each with its reason.
var notMirrored = map[string]string{
	"authorization/checkAccessRequest":         "the Authorization contract is described in docs/api/grpc/README.md §8, not yet in proto/",
	"authorization/checkAccessResponse":        "idem",
	"session-broker/checkAccessRequestBody":    "idem — the Broker's client of it",
	"session-broker/checkAccessResponseBody":   "idem",
	"password-vault/checkAccessRequestBody":    "idem — the Vault's client of it",
	"password-vault/checkAccessResponseBody":   "idem",
	"command-recorder/checkAccessRequestBody":  "idem — the Recorder's client of it",
	"command-recorder/checkAccessResponseBody": "idem",
	// Not routes between services: formats of a third party, or of a file.
	"authentication/idClaims":   "the claims of an OIDC identity token: the provider's format (ADR-0035)",
	"audit-service/anchorLine":  "a line of the anchor file (ADR-0028), not a message",
	"audit-service/archiveLine": "a line of an archive file (ADR-0032), not a message",
}

var protoMessage = regexp.MustCompile(`(?ms)^message (\w+) \{(.*?)^\}`)
var protoField = regexp.MustCompile(`(?m)^\s+(?:repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+`)

func protoFields(t *testing.T, root, file, message string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range protoMessage.FindAllStringSubmatch(string(b), -1) {
		if m[1] == message {
			var out []string
			for _, f := range protoField.FindAllStringSubmatch(m[2], -1) {
				out = append(out, f[1])
			}
			return out
		}
	}
	t.Fatalf("%s has no message %s", file, message)
	return nil
}

// goJSONFields maps every struct of a Go file to the names its json tags give.
func goJSONFields(t *testing.T, root, file string) map[string][]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, file), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
			if name := strings.Split(tag, ",")[0]; name != "" && name != "-" {
				out[ts.Name.Name] = append(out[ts.Name.Name], name)
			}
		}
		return true
	})
	return out
}

func TestContract_EveryInternalRouteCarriesTheFieldsOfItsProtoMessage_OrSaysWhyNot(t *testing.T) {
	root := repoRoot(t)
	for _, p := range contractPairs {
		t.Run(p.goStruct+"→"+p.message, func(t *testing.T) {
			js, ok := goJSONFields(t, root, p.file)[p.goStruct]
			if !ok {
				t.Fatalf("%s has no struct %s", p.file, p.goStruct)
			}
			pf := protoFields(t, root, p.proto, p.message)
			inJSON, inProto := set(js), set(pf)
			for f := range inJSON {
				if !inProto[f] && p.jsonOnly[f] == "" {
					t.Errorf("%s.%s is not a field of %s.%s, and no reason is declared", p.goStruct, f, p.message, f)
				}
			}
			for f := range inProto {
				if !inJSON[f] && p.protoOnly[f] == "" {
					t.Errorf("%s.%s is not carried by %s, and no reason is declared", p.message, f, p.goStruct)
				}
			}
			// A declared divergence that is no longer one is a stale reason: it would hide the next drift.
			for f := range p.jsonOnly {
				if !inJSON[f] || inProto[f] {
					t.Errorf("declared JSON-only field %q is not, or no longer, JSON-only", f)
				}
			}
			for f := range p.protoOnly {
				if inJSON[f] || !inProto[f] {
					t.Errorf("declared proto-only field %q is not, or no longer, proto-only", f)
				}
			}
		})
	}
}

// anonymousAllowed are files whose anonymous snake_case shapes are not routes between services.
var anonymousAllowed = map[string]string{
	"services/access/authentication/internal/infrastructure/oidc_provider.go": "the OIDC provider's discovery document and token response (ADR-0035)",
}

// anonymousJSON lists, in a Go file, the anonymous structs with snake_case json tags and the map
// literals with snake_case keys: the shapes the table cannot name, so that a body built that way
// would escape the check.
func anonymousJSON(t *testing.T, root, file string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	named := map[*ast.StructType]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if ts, ok := n.(*ast.TypeSpec); ok {
			if st, ok := ts.Type.(*ast.StructType); ok {
				named[st] = true
			}
		}
		return true
	})
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.StructType:
			if named[x] {
				return true
			}
			for _, field := range x.Fields.List {
				if field.Tag != nil && strings.Contains(strings.Split(reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json"), ",")[0], "_") {
					out = append(out, fmt.Sprintf("%s:%d anonymous struct", file, fset.Position(x.Pos()).Line))
					return true
				}
			}
		case *ast.CompositeLit:
			if _, ok := x.Type.(*ast.MapType); !ok {
				return true
			}
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "_") {
					out = append(out, fmt.Sprintf("%s:%d map literal", file, fset.Position(x.Pos()).Line))
					return true
				}
			}
		}
		return true
	})
	return out
}

func TestContract_NoInternalJSONStructEscapesTheTable(t *testing.T) {
	root := repoRoot(t)
	covered := map[string]bool{}
	for _, p := range contractPairs {
		covered[p.file+"#"+p.goStruct] = true
	}
	var files []string
	for _, pattern := range []string{"services/*/*/internal/interfaces/*.go", "services/*/*/internal/infrastructure/*.go"} {
		m, _ := filepath.Glob(filepath.Join(root, pattern))
		files = append(files, m...)
	}
	sort.Strings(files)
	var escaped []string
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		rel, _ := filepath.Rel(root, abs)
		service := strings.Split(rel, string(filepath.Separator))[2]
		if anonymousAllowed[rel] == "" {
			escaped = append(escaped, anonymousJSON(t, root, rel)...)
		}
		for name, fields := range goJSONFields(t, root, rel) {
			snake := false
			for _, f := range fields {
				snake = snake || strings.Contains(f, "_")
			}
			if !snake || covered[rel+"#"+name] || notMirrored[service+"/"+name] != "" {
				continue
			}
			escaped = append(escaped, rel+"#"+name)
		}
	}
	if len(escaped) > 0 {
		t.Fatalf("internal JSON structs with no contract pair and no declared reason (add them to contractPairs or notMirrored):\n%s", strings.Join(escaped, "\n"))
	}
}

func set(s []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}
	return m
}
