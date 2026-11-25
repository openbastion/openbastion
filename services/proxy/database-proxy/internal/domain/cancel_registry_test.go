package domain

import (
	"errors"
	"testing"
	"time"
)

func TestCancelRegistryTranslatesOpaqueKeyAndBindsPeerIP(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	registry, err := NewCancelRegistry(8, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := registry.Register("s1", "192.0.2.10", "198.51.100.4:5432", 1001, 2002, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if frontend.ProcessID == 1001 && frontend.SecretKey == 2002 {
		t.Fatal("frontend received the upstream backend key unchanged")
	}
	got, err := registry.Resolve(frontend, "192.0.2.10")
	if err != nil || got.TargetAddr != "198.51.100.4:5432" || got.ProcessID != 1001 || got.SecretKey != 2002 {
		t.Fatalf("Resolve = %#v, %v", got, err)
	}
	if _, err := registry.Resolve(frontend, "192.0.2.11"); !errors.Is(err, ErrInvalidCancelRequest) {
		t.Fatalf("wrong peer IP error = %v", err)
	}
}

func TestCancelRegistryExpiresAndRemovesSessionKeys(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	registry, err := NewCancelRegistry(8, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	key, err := registry.Register("s1", "192.0.2.10", "198.51.100.4:5432", 1, 2, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := registry.Resolve(key, "192.0.2.10"); !errors.Is(err, ErrInvalidCancelRequest) {
		t.Fatalf("expired key error = %v", err)
	}
	key, err = registry.Register("s2", "192.0.2.10", "198.51.100.4:5432", 1, 2, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	registry.RemoveSession("s2")
	if _, err := registry.Resolve(key, "192.0.2.10"); !errors.Is(err, ErrInvalidCancelRequest) {
		t.Fatalf("removed key error = %v", err)
	}
}

func TestCancelRegistryRejectsDNSNamesAndUnboundedEntries(t *testing.T) {
	now := time.Now().UTC()
	registry, err := NewCancelRegistry(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register("s1", "192.0.2.10", "db.example:5432", 1, 2, now.Add(time.Minute)); err == nil {
		t.Fatal("DNS target address was accepted for CancelRequest mapping")
	}
	if _, err := registry.Register("s1", "192.0.2.10", "198.51.100.4:5432", 1, 2, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register("s2", "192.0.2.10", "198.51.100.4:5432", 1, 2, now.Add(time.Minute)); !errors.Is(err, ErrCancelRegistryCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
}
