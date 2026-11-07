package infrastructure

// The Entra ID profile of an OIDC provider (ADR-0079): the same OIDC flow, bound to one declared
// tenant. Its issuer is the v2 issuer of that tenant exactly; every ID token must carry the same
// tenant (tid); a token that says its groups are elsewhere (an overage) is refused, and no URL it
// names is followed.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
)

// ProfileOIDC and ProfileEntra are the profiles of an oidc entry of IDENTITY_PROVIDERS_FILE.
const (
	ProfileOIDC  = "oidc"
	ProfileEntra = "entra"
)

var tenantGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// EntraIssuer is the only issuer an Entra ID entry of tenant may have: its v2 issuer. A tenant
// that is not a GUID — common, organizations, consumers, a domain name — is refused: the trust
// boundary is one tenant, named at configuration.
func EntraIssuer(tenant string) (string, error) {
	if !tenantGUID.MatchString(tenant) {
		return "", errors.New("tenant_id must be the tenant's GUID, in lower case (common, organizations, consumers and domain names are refused)")
	}
	return "https://login.microsoftonline.com/" + tenant + "/v2.0", nil
}

// checkEntraIssuer says whether issuer is exactly the v2 issuer of tenant.
func checkEntraIssuer(tenant, issuer string) error {
	want, err := EntraIssuer(tenant)
	if err != nil {
		return err
	}
	if issuer != want {
		return fmt.Errorf("the issuer of an Entra ID entry is exactly %s, not %s", want, issuer)
	}
	return nil
}

// entraClaims checks, in a token whose signature is already verified, what the Entra ID profile
// adds: the tenant, and that the groups are all in the token.
func entraClaims(all map[string]json.RawMessage, tenant, groupsClaim string) error {
	var tid string
	if raw, ok := all["tid"]; !ok || json.Unmarshal(raw, &tid) != nil || tid == "" {
		return fmt.Errorf("%w: no tenant (tid) in the token", application.ErrOIDCRejected)
	}
	if strings.ToLower(tid) != tenant {
		return fmt.Errorf("%w: the token is of another tenant", application.ErrOIDCRejected)
	}
	// An overage (more groups than a token holds): the groups are replaced by a reference to fetch
	// them (_claim_names / _claim_sources), or by hasgroups. Refused, never followed (ADR-0079, 5).
	var hasGroups bool
	if raw, ok := all["hasgroups"]; ok && json.Unmarshal(raw, &hasGroups) == nil && hasGroups {
		return fmt.Errorf("%w: the token says its groups are not in it (hasgroups)", application.ErrOIDCRejected)
	}
	// _claim_sources is a dictionary of distributed-claim sources, not proof of group
	// overage by itself. _claim_names above identifies which claim is external; only a
	// reference for the configured groups claim (or the standard groups claim) is rejected.
	if raw, ok := all["_claim_names"]; ok {
		var names map[string]json.RawMessage
		if json.Unmarshal(raw, &names) != nil {
			return fmt.Errorf("%w: _claim_names is not an object", application.ErrOIDCRejected)
		}
		for name := range names {
			if name == groupsClaim || name == "groups" {
				return fmt.Errorf("%w: the token says its groups are not in it (_claim_names)", application.ErrOIDCRejected)
			}
		}
	}
	return nil
}
