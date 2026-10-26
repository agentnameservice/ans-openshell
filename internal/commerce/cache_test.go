package commerce

import (
	"context"
	"errors"
	"testing"
)

// fakeClock implements Clock with a fixed timestamp
type fakeClock struct {
	now int64
}

func (f fakeClock) NowUnix() int64 {
	return f.now
}

// fakeAuthority implements AuthorityClient and counts calls
type fakeAuthority struct {
	mandate *Mandate
	calls   int
}

func (f *fakeAuthority) RequestMandate(_ context.Context, _ MandateInput) (*Mandate, error) {
	f.calls++
	if f.mandate == nil {
		return nil, errors.New("authority returned nil mandate")
	}
	return f.mandate, nil
}

func TestCache_HitOnMatchingQuoteAndJKT(t *testing.T) {
	cache := NewMandateCache()
	clock := fakeClock{now: 1000}
	authority := &fakeAuthority{
		mandate: &Mandate{
			MandateID:    "m1",
			QuoteID:      "q1",
			SubjectANS:   "ans://traveler.example.com",
			AudienceANS:  "ans://seller.example.com",
			Scope:        "commerce.pay",
			MaxAmount:    100.0,
			Currency:     "USD",
			NotBefore:    "2026-01-01T00:00:00Z",
			NotAfter:     "2026-01-01T01:00:00Z",
			JKT:          "jkt1",
			AuthorityANS: "ans://authority.example.com",
			Signature:    "sig1",
		},
	}

	qk := QuoteKey{QuoteID: "q1", Amount: 50.0, Currency: "USD"}
	ourJKT := "jkt1"
	sellerANS := "ans://seller.example.com"
	scopePrefix := "commerce.pay"
	build := func(qk QuoteKey) MandateInput {
		return MandateInput{
			QuoteID:     qk.QuoteID,
			Total:       qk.Amount,
			Currency:    qk.Currency,
			MerchantANS: sellerANS,
			ScopeHint:   scopePrefix,
		}
	}

	// First call should fetch from authority
	m1, err := cache.GetOrFetch(context.Background(), qk, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed: %v", err)
	}
	if m1 == nil {
		t.Fatal("GetOrFetch returned nil mandate")
	}
	if authority.calls != 1 {
		t.Errorf("Expected 1 authority call, got %d", authority.calls)
	}

	// Second call with same parameters should hit cache
	m2, err := cache.GetOrFetch(context.Background(), qk, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed on second call: %v", err)
	}
	if m2 == nil {
		t.Fatal("GetOrFetch returned nil mandate on second call")
	}
	if authority.calls != 1 {
		t.Errorf("Expected 1 authority call (cache hit), got %d", authority.calls)
	}
}

func TestCache_MissOnQuoteIDChange(t *testing.T) {
	cache := NewMandateCache()
	clock := fakeClock{now: 1000}

	qk1 := QuoteKey{QuoteID: "q1", Amount: 50.0, Currency: "USD"}
	qk2 := QuoteKey{QuoteID: "q2", Amount: 60.0, Currency: "USD"}
	ourJKT := "jkt1"
	sellerANS := "ans://seller.example.com"
	scopePrefix := "commerce.pay"

	authority := &fakeAuthority{}
	build := func(qk QuoteKey) MandateInput {
		return MandateInput{
			QuoteID:     qk.QuoteID,
			Total:       qk.Amount,
			Currency:    qk.Currency,
			MerchantANS: sellerANS,
			ScopeHint:   scopePrefix,
		}
	}

	// First call with q1
	authority.mandate = &Mandate{
		MandateID:    "m1",
		QuoteID:      "q1",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.example.com",
		Scope:        "commerce.pay",
		MaxAmount:    100.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-01-01T01:00:00Z",
		JKT:          "jkt1",
		AuthorityANS: "ans://authority.example.com",
		Signature:    "sig1",
	}
	_, err := cache.GetOrFetch(context.Background(), qk1, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed: %v", err)
	}
	if authority.calls != 1 {
		t.Errorf("Expected 1 authority call, got %d", authority.calls)
	}

	// Second call with q2 should miss cache
	authority.mandate = &Mandate{
		MandateID:    "m2",
		QuoteID:      "q2",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.example.com",
		Scope:        "commerce.pay",
		MaxAmount:    100.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-01-01T01:00:00Z",
		JKT:          "jkt1",
		AuthorityANS: "ans://authority.example.com",
		Signature:    "sig2",
	}
	_, err = cache.GetOrFetch(context.Background(), qk2, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed on second call: %v", err)
	}
	if authority.calls != 2 {
		t.Errorf("Expected 2 authority calls (cache miss), got %d", authority.calls)
	}
}

func TestCache_MissOnExpiryWithinSkew(t *testing.T) {
	cache := NewMandateCache()
	// Set clock to 30 seconds before expiry (within 60s skew)
	notAfterUnix := int64(2000)
	clock := fakeClock{now: notAfterUnix - 30}

	authority := &fakeAuthority{
		mandate: &Mandate{
			MandateID:    "m1",
			QuoteID:      "q1",
			SubjectANS:   "ans://traveler.example.com",
			AudienceANS:  "ans://seller.example.com",
			Scope:        "commerce.pay",
			MaxAmount:    100.0,
			Currency:     "USD",
			NotBefore:    "2026-01-01T00:00:00Z",
			NotAfter:     "1970-01-01T00:33:20Z", // 2000 seconds since epoch
			JKT:          "jkt1",
			AuthorityANS: "ans://authority.example.com",
			Signature:    "sig1",
		},
	}

	qk := QuoteKey{QuoteID: "q1", Amount: 50.0, Currency: "USD"}
	ourJKT := "jkt1"
	sellerANS := "ans://seller.example.com"
	scopePrefix := "commerce.pay"
	build := func(qk QuoteKey) MandateInput {
		return MandateInput{
			QuoteID:     qk.QuoteID,
			Total:       qk.Amount,
			Currency:    qk.Currency,
			MerchantANS: sellerANS,
			ScopeHint:   scopePrefix,
		}
	}

	// First call should fetch
	_, err := cache.GetOrFetch(context.Background(), qk, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed: %v", err)
	}
	if authority.calls != 1 {
		t.Errorf("Expected 1 authority call, got %d", authority.calls)
	}

	// Second call should refetch because we're within 60s of expiry
	_, err = cache.GetOrFetch(context.Background(), qk, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed on second call: %v", err)
	}
	if authority.calls != 2 {
		t.Errorf("Expected 2 authority calls (expired within skew), got %d", authority.calls)
	}
}

func TestCache_MissOnJKTChange(t *testing.T) {
	cache := NewMandateCache()
	clock := fakeClock{now: 1000}

	qk := QuoteKey{QuoteID: "q1", Amount: 50.0, Currency: "USD"}
	sellerANS := "ans://seller.example.com"
	scopePrefix := "commerce.pay"

	authority := &fakeAuthority{}
	build := func(qk QuoteKey) MandateInput {
		return MandateInput{
			QuoteID:     qk.QuoteID,
			Total:       qk.Amount,
			Currency:    qk.Currency,
			MerchantANS: sellerANS,
			ScopeHint:   scopePrefix,
		}
	}

	// First call with jkt1
	authority.mandate = &Mandate{
		MandateID:    "m1",
		QuoteID:      "q1",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.example.com",
		Scope:        "commerce.pay",
		MaxAmount:    100.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-01-01T01:00:00Z",
		JKT:          "jkt1",
		AuthorityANS: "ans://authority.example.com",
		Signature:    "sig1",
	}
	_, err := cache.GetOrFetch(context.Background(), qk, "jkt1", sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed: %v", err)
	}
	if authority.calls != 1 {
		t.Errorf("Expected 1 authority call, got %d", authority.calls)
	}

	// Second call with different JKT should miss cache
	authority.mandate = &Mandate{
		MandateID:    "m2",
		QuoteID:      "q1",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.example.com",
		Scope:        "commerce.pay",
		MaxAmount:    100.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-01-01T01:00:00Z",
		JKT:          "jkt2",
		AuthorityANS: "ans://authority.example.com",
		Signature:    "sig2",
	}
	_, err = cache.GetOrFetch(context.Background(), qk, "jkt2", sellerANS, scopePrefix, authority, clock, build)
	if err != nil {
		t.Fatalf("GetOrFetch failed on second call: %v", err)
	}
	if authority.calls != 2 {
		t.Errorf("Expected 2 authority calls (JKT changed), got %d", authority.calls)
	}
}

func TestCache_FetchValidatesAndPropagatesError(t *testing.T) {
	cache := NewMandateCache()
	clock := fakeClock{now: 1000}

	// Mandate with wrong JKT to trigger validation failure
	authority := &fakeAuthority{
		mandate: &Mandate{
			MandateID:    "m1",
			QuoteID:      "q1",
			SubjectANS:   "ans://traveler.example.com",
			AudienceANS:  "ans://seller.example.com",
			Scope:        "commerce.pay",
			MaxAmount:    100.0,
			Currency:     "USD",
			NotBefore:    "2026-01-01T00:00:00Z",
			NotAfter:     "2026-01-01T01:00:00Z",
			JKT:          "wrong-jkt", // This will fail validation
			AuthorityANS: "ans://authority.example.com",
			Signature:    "sig1",
		},
	}

	qk := QuoteKey{QuoteID: "q1", Amount: 50.0, Currency: "USD"}
	ourJKT := "jkt1"
	sellerANS := "ans://seller.example.com"
	scopePrefix := "commerce.pay"
	build := func(qk QuoteKey) MandateInput {
		return MandateInput{
			QuoteID:     qk.QuoteID,
			Total:       qk.Amount,
			Currency:    qk.Currency,
			MerchantANS: sellerANS,
			ScopeHint:   scopePrefix,
		}
	}

	// Call should fail validation and return error
	_, err := cache.GetOrFetch(context.Background(), qk, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err == nil {
		t.Fatal("Expected validation error, got nil")
	}
	if !errors.Is(err, ErrMandateInvalid) {
		t.Errorf("Expected ErrMandateInvalid, got %v", err)
	}
	if authority.calls != 1 {
		t.Errorf("Expected 1 authority call, got %d", authority.calls)
	}

	// Second call should also fail and refetch (nothing was cached)
	_, err = cache.GetOrFetch(context.Background(), qk, ourJKT, sellerANS, scopePrefix, authority, clock, build)
	if err == nil {
		t.Fatal("Expected validation error on second call, got nil")
	}
	if authority.calls != 2 {
		t.Errorf("Expected 2 authority calls (first call didn't cache), got %d", authority.calls)
	}
}
