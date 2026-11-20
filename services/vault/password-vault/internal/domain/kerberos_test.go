package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

func TestKerberosSettings_Normalized(t *testing.T) {
	got, err := domain.KerberosSettings{Realm: " corp.example.com ", KDCs: []string{"DC1.Corp.Example.com", "dc2.corp.example.com:8888", "10.0.0.4", "[2001:db8::1]:88"}}.Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if got.Realm != "CORP.EXAMPLE.COM" || strings.Join(got.KDCs, ",") != "dc1.corp.example.com:88,dc2.corp.example.com:8888,10.0.0.4:88,[2001:db8::1]:88" {
		t.Fatalf("normalized: %+v", got)
	}
	five := []string{"a:88", "b:88", "c:88", "d:88", "e:88"}
	for name, bad := range map[string]domain.KerberosSettings{
		"no realm":         {KDCs: []string{"dc1"}},
		"a realm with @":   {Realm: "CORP@EVIL", KDCs: []string{"dc1"}},
		"a realm with /":   {Realm: "CORP/X", KDCs: []string{"dc1"}},
		"a realm label":    {Realm: "CORP..EXAMPLE", KDCs: []string{"dc1"}},
		"no KDC":           {Realm: "CORP"},
		"five KDCs":        {Realm: "CORP", KDCs: five},
		"a URL":            {Realm: "CORP", KDCs: []string{"tcp://dc1:88"}},
		"a wildcard":       {Realm: "CORP", KDCs: []string{"*.corp:88"}},
		"port 0":           {Realm: "CORP", KDCs: []string{"dc1:0"}},
		"port 65536":       {Realm: "CORP", KDCs: []string{"dc1:65536"}},
		"port +88":         {Realm: "CORP", KDCs: []string{"dc1:+88"}},
		"an empty host":    {Realm: "CORP", KDCs: []string{":88"}},
		"a duplicate":      {Realm: "CORP", KDCs: []string{"DC1", "dc1:88"}},
		"a space":          {Realm: "CORP", KDCs: []string{"dc 1:88"}},
		"IPv6 no brackets": {Realm: "CORP", KDCs: []string{"2001:db8::1:88:x"}},
	} {
		if _, err := bad.Normalized(); !errors.Is(err, domain.ErrInvalidKerberos) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}
