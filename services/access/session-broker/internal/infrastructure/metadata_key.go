package infrastructure

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

var metadataKeyID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// LoadMetadataKey reads the HMAC key of ADR-0116 from path (variable names the setting, for the
// errors), under the identifier id. The file is the service's own: a regular file readable by its
// owner only, holding 32 bytes in hex. The errors never say what the file holds.
func LoadMetadataKey(variable, path, id string) (domain.MetadataKey, error) {
	if !metadataKeyID.MatchString(id) {
		return domain.MetadataKey{}, fmt.Errorf("%s: the key identifier must be 1 to 64 letters, digits, '.', '_' or '-'", variable)
	}
	info, err := os.Stat(path)
	if err != nil {
		return domain.MetadataKey{}, fmt.Errorf("%s cannot be read: %v", variable, err)
	}
	if !info.Mode().IsRegular() {
		return domain.MetadataKey{}, errors.New(variable + " must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return domain.MetadataKey{}, fmt.Errorf("%s is readable by its group or by others (mode %#o): make it 0600 or 0400", variable, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return domain.MetadataKey{}, fmt.Errorf("%s cannot be read: %v", variable, err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != domain.MetadataKeyBytes {
		return domain.MetadataKey{}, fmt.Errorf("%s must hold %d bytes in hex (openssl rand -hex %d)", variable, domain.MetadataKeyBytes, domain.MetadataKeyBytes)
	}
	return domain.MetadataKey{ID: id, Key: key}, nil
}
