package infrastructure

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// objectGUID is written by AD with its first three groups little-endian: the bytes of
// {3f2504e0-4f89-11d3-9a0c-0305e82c3301} are e0 04 25 3f 89 4f d3 11 9a 0c 03 05 e8 2c 33 01.
func TestStableID_ObjectGUIDInTheFormADWritesIt_EntryUUIDAsItIs(t *testing.T) {
	raw := []byte{0xe0, 0x04, 0x25, 0x3f, 0x89, 0x4f, 0xd3, 0x11, 0x9a, 0x0c, 0x03, 0x05, 0xe8, 0x2c, 0x33, 0x01}
	e := ldap.NewEntry("cn=alice,dc=example,dc=test", nil)
	e.Attributes = []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{raw}, Values: []string{string(raw)}}}
	if got := stableID("objectGUID", e); got != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Fatalf("objectGUID: %q", got)
	}
	short := ldap.NewEntry("cn=x", nil)
	short.Attributes = []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{raw[:15]}}}
	if got := stableID("objectGUID", short); got != "" {
		t.Fatalf("a GUID of 15 bytes: %q, want none", got)
	}
	u := ldap.NewEntry("uid=bob,dc=example,dc=test", map[string][]string{"entryUUID": {"7C3E9C3A-1111-4222-8333-444455556666"}})
	if got := stableID("entryUUID", u); got != "7c3e9c3a-1111-4222-8333-444455556666" {
		t.Fatalf("entryUUID: %q", got)
	}
}
