package commerce

import (
	"context"
	"sync"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/commercekey"
)

const skewSecs = 60

// Clock provides the current Unix timestamp for testing.
type Clock interface {
	NowUnix() int64
}

// AuthorityClient requests mandates from an authority service.
type AuthorityClient interface {
	RequestMandate(ctx context.Context, in MandateInput) (*Mandate, error)
}

// MandateInput contains the parameters needed to request a mandate.
type MandateInput struct {
	QuoteID         string                `json:"quote_id"`
	Total           float64               `json:"total"`
	Currency        string                `json:"currency"`
	MerchantANS     string                `json:"merchant_ans"`
	ScopeHint       string                `json:"scope_hint"`
	SubjectANS      string                `json:"subject_ans"`
	TravelerDPoPJWK commercekey.JwkPublic `json:"traveler_dpop_jwk"`
}

// cachedMandate holds a cached mandate with its expiry and quote key.
type cachedMandate struct {
	mandate      *Mandate
	notAfterUnix int64
	quoteKey     QuoteKey
}

// MandateCache is a single-slot cache for mandates with 60s expiry skew.
type MandateCache struct {
	mu    sync.Mutex
	entry *cachedMandate
}

// NewMandateCache creates a new empty mandate cache.
func NewMandateCache() *MandateCache {
	return &MandateCache{}
}

// GetOrFetch returns a cached mandate if it matches the quote key, JKT, and is
// not within 60 seconds of expiry. Otherwise, fetches a new mandate from the
// authority, validates it, caches it, and returns it.
func (c *MandateCache) GetOrFetch(
	ctx context.Context,
	qk QuoteKey,
	ourJKT, sellerANS, scopePrefix string,
	authority AuthorityClient,
	clock Clock,
	build func(QuoteKey) MandateInput,
) (*Mandate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := clock.NowUnix()

	// Check if we can serve from cache
	if c.entry != nil {
		cached := c.entry
		// Cache hit if: quote key matches, JKT matches, and not within skew of expiry
		if cached.quoteKey == qk &&
			cached.mandate.JKT == ourJKT &&
			now < cached.notAfterUnix-skewSecs {
			return cached.mandate, nil
		}
	}

	// Cache miss: fetch new mandate
	input := build(qk)
	mandate, err := authority.RequestMandate(ctx, input)
	if err != nil {
		return nil, err
	}

	// Validate the mandate
	if err := Validate(mandate, qk, ourJKT, sellerANS, scopePrefix); err != nil {
		return nil, err
	}

	// Parse not_after to get expiry time
	notAfterTime, err := time.Parse(time.RFC3339, mandate.NotAfter)
	if err != nil {
		// This should not happen since Validate already checked it
		return nil, err
	}
	notAfterUnix := notAfterTime.Unix()

	// Store in cache
	c.entry = &cachedMandate{
		mandate:      mandate,
		notAfterUnix: notAfterUnix,
		quoteKey:     qk,
	}

	return mandate, nil
}
