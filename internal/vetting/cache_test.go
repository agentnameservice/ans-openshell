package vetting

import (
	"testing"
	"time"
)

func TestVerdictCacheEvictsOldestWrite(t *testing.T) {
	t.Parallel()
	c := newVerdictCache(2)
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	ttl := 10 * time.Minute

	c.put("a", Verdict{Host: "a", Status: StatusRegistered}, now, ttl)
	c.put("b", Verdict{Host: "b", Status: StatusUnregistered}, now, ttl)
	c.put("c", Verdict{Host: "c", Status: StatusRevoked}, now, ttl)
	if _, ok := c.get("a"); ok {
		t.Fatal("a should have been evicted")
	}
	if c.len() != 2 {
		t.Fatalf("len() = %d, want 2", c.len())
	}

	c.put("b", Verdict{Host: "b", Status: StatusRegistered}, now.Add(time.Minute), ttl)
	c.put("d", Verdict{Host: "d", Status: StatusError}, now, ttl)
	if _, ok := c.get("c"); ok {
		t.Fatal("c should have been evicted after b was rewritten")
	}
	b, ok := c.get("b")
	if !ok || b.verdict.Status != StatusRegistered {
		t.Fatalf("get(b) = %+v, %v; want the rewritten entry", b, ok)
	}
	if want := now.Add(time.Minute + ttl); !b.expiresAt.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", b.expiresAt, want)
	}
	if want := now.Add(time.Minute + ttl - time.Minute); !b.refreshAt.Equal(want) {
		t.Fatalf("refreshAt = %v, want %v", b.refreshAt, want)
	}
	if _, ok := c.get("missing"); ok {
		t.Fatal("get(missing) should miss")
	}
}
