package vetting

import (
	"errors"
	"testing"
	"time"
)

func TestLookupClassifiesIPRanges(t *testing.T) {
	t.Parallel()
	h := newHarness()
	svc := h.service(t)
	for _, host := range []string{"198.51.100.0/24", "2001:db8::/32"} {
		v := svc.Lookup(t.Context(), host, time.Second)
		if v.Status != StatusUnregistered || v.Detail != "ip range" {
			t.Fatalf("Lookup(%q) = %+v, want unregistered ip range", host, v)
		}
	}
	if h.cdns.calls.Load() != 0 {
		t.Fatal("an IP range reached DNS")
	}
}

func TestRefreshFailureKeepsValidVerdict(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.cfg.CacheTTL = 10 * time.Minute
	h.registered("agent.example.com")
	svc := h.service(t)

	if v := svc.Lookup(t.Context(), "agent.example.com", 5*time.Second); v.Status != StatusRegistered {
		t.Fatalf("initial Lookup = %+v, want registered", v)
	}
	h.dns.WithError("agent.example.com", errors.New("servfail"))
	h.clock.Advance(9*time.Minute + 5*time.Second)
	if v := svc.Lookup(t.Context(), "agent.example.com", 0); v.Status != StatusRegistered {
		t.Fatalf("Lookup inside the refresh window = %+v, want the cached registered verdict", v)
	}
	eventually(t, "the failed refresh to be counted", func() bool { return svc.Stats().Errors == 1 })
	lookups := svc.Stats().Lookups
	h.clock.Advance(10 * time.Second)
	for range 3 {
		if v := svc.Lookup(t.Context(), "agent.example.com", 5*time.Second); v.Status != StatusRegistered {
			t.Fatalf("Lookup after a failed refresh = %+v, want the still-valid registered verdict", v)
		}
	}
	if got := svc.Stats().Lookups; got != lookups {
		t.Fatalf("a failed refresh was retried %d times before the error TTL elapsed", got-lookups)
	}
	h.clock.Advance(defaultErrorTTL)
	if v := svc.Lookup(t.Context(), "agent.example.com", 0); v.Status != StatusRegistered {
		t.Fatalf("Lookup at the retry point = %+v, want the cached registered verdict", v)
	}
	if got := svc.Stats().Lookups; got != lookups+1 {
		t.Fatalf("lookups after the error TTL = %d, want one retry (%d)", got, lookups+1)
	}
	h.clock.Advance(time.Minute)
	if v := svc.Lookup(t.Context(), "agent.example.com", 5*time.Second); v.Status != StatusError {
		t.Fatalf("Lookup after expiry with DNS failing = %+v, want error", v)
	}
}
