package pgwire

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var ErrStartupIdentityMismatch = errors.New("postgresql startup identity does not match the approved account")

// ValidateStartupParameters pins the database and role to Vault-approved
// metadata. Only presentation parameters are accepted from the client.
func ValidateStartupParameters(params map[string]string, approvedUser, approvedDatabase string) (string, error) {
	if !validStartupIdentity(approvedUser) || !validStartupIdentity(approvedDatabase) {
		return "", ErrStartupIdentityMismatch
	}
	user, hasUser := params["user"]
	database, hasDatabase := params["database"]
	if !hasUser || !hasDatabase || user != approvedUser || database != approvedDatabase {
		return "", ErrStartupIdentityMismatch
	}
	for key, value := range params {
		switch key {
		case "user", "database":
		case "application_name", "fallback_application_name":
			if !validApplicationName(value) {
				return "", fmt.Errorf("%w: invalid application name", ErrMalformedPacket)
			}
		case "client_encoding":
			if !strings.EqualFold(value, "UTF8") && !strings.EqualFold(value, "UTF-8") {
				return "", fmt.Errorf("%w: only UTF8 client encoding is supported", ErrMalformedPacket)
			}
		default:
			// In particular, options, replication, role, search_path and
			// unknown libpq extensions are never forwarded to the target.
			return "", fmt.Errorf("%w: unsupported startup parameter", ErrMalformedPacket)
		}
	}
	applicationName := params["application_name"]
	if applicationName == "" {
		applicationName = params["fallback_application_name"]
	}
	return applicationName, nil
}

func validStartupIdentity(value string) bool {
	if value == "" || len(value) > 63 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func validApplicationName(value string) bool {
	if len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
