package commerce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/ans-openshell/internal/commercekey"
)

// Nonce provides unique JWT IDs for DPoP token replay prevention.
type Nonce interface {
	JTI() string
}

// OutcomeKind represents the result of a rewrite operation.
type OutcomeKind int

const (
	// Passthrough means the request was not a book_flight call and should be forwarded as-is.
	Passthrough OutcomeKind = iota
	// Deny means the request was rejected (missing args, validation failure, oversize).
	Deny
	// Allow means the request was successfully rewritten with mandate and DPoP proof.
	Allow
)

// Config contains the configuration for the commerce rewriter.
type Config struct {
	SellerMCPURL string // MCP endpoint URL for the seller (used verbatim as DPoP htu)
	SellerANS    string // Seller's ANS identifier for mandate validation
	ScopePrefix  string // Expected prefix for mandate scope
	SubjectANS   string // Subject ANS identifier for mandate request
	MaxBodyBytes int    // Maximum allowed body size after rewriting
}

// Deps contains the dependencies for the commerce rewriter.
type Deps struct {
	Key       *commercekey.Key // Commerce DPoP key
	Cache     *MandateCache    // Mandate cache
	Authority AuthorityClient  // Authority service client
	Clock     Clock            // Clock for timestamps
	Nonce     Nonce            // Nonce generator for JTI
}

// Outcome represents the result of a rewrite operation.
type Outcome struct {
	Kind    OutcomeKind
	Body    []byte // Set only for Allow
	Reason  string // Set only for Deny
	SignURL string // Set only for Allow: externally-visible URL for identity proof htu binding
}

// RewriteBookFlight orchestrates mandate fetching and DPoP injection for book_flight requests.
// It mirrors the Rust implementation in commerce/mod.rs:19-146.
//
// Behavior:
//   - Passthrough (no deps called) if: body is not JSON, method != "tools/call", or params.name != "book_flight"
//   - Extract quote_id, amount, currency from params.arguments; missing → Deny
//   - Fetch mandate from cache (with validation); error → Deny
//   - Mint DPoP proof with htu = htuOverride (if set), else cfg.SellerMCPURL (verbatim, not reconstructed)
//   - Splice mandate and dpop_proof into arguments, re-marshal
//   - If re-marshaled body exceeds cfg.MaxBodyBytes → Deny; else Allow
//
// htuOverride: when non-empty, use this as the DPoP htu instead of cfg.SellerMCPURL (for discovered params).
//
// CRITICAL: Uses json.Decoder.UseNumber() to preserve numeric formatting (500 stays 500, not 500.0).
func RewriteBookFlight(ctx context.Context, body []byte, d Deps, cfg Config, htuOverride string) Outcome {
	// Parse the body with UseNumber() to preserve numeric formatting
	// CRITICAL: Must use json.Decoder with UseNumber() to prevent 500 → 500.0 conversion
	var req map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		// Not JSON → Passthrough
		return Outcome{Kind: Passthrough}
	}

	// Check method == "tools/call"
	method, ok := req["method"].(string)
	if !ok || method != "tools/call" {
		return Outcome{Kind: Passthrough}
	}

	// Extract params
	params, ok := req["params"].(map[string]any)
	if !ok {
		return Outcome{Kind: Passthrough}
	}

	// Check name == "book_flight"
	name, ok := params["name"].(string)
	if !ok || name != "book_flight" {
		return Outcome{Kind: Passthrough}
	}

	// Extract arguments
	args, ok := params["arguments"].(map[string]any)
	if !ok {
		return Outcome{Kind: Deny, Reason: "missing arguments"}
	}

	// Extract quote_id (string)
	quoteID, ok := args["quote_id"].(string)
	if !ok || quoteID == "" {
		return Outcome{Kind: Deny, Reason: "missing or invalid quote_id"}
	}

	// Extract amount (json.Number → float64 for QuoteKey)
	amountNum, ok := args["amount"].(json.Number)
	if !ok {
		return Outcome{Kind: Deny, Reason: "missing or invalid amount"}
	}
	amount, err := amountNum.Float64()
	if err != nil {
		return Outcome{Kind: Deny, Reason: fmt.Sprintf("invalid amount: %v", err)}
	}

	// Extract currency (string)
	currency, ok := args["currency"].(string)
	if !ok || currency == "" {
		return Outcome{Kind: Deny, Reason: "missing or invalid currency"}
	}

	// Build QuoteKey
	qk := QuoteKey{
		QuoteID:  quoteID,
		Amount:   amount,
		Currency: currency,
	}

	// Fetch mandate (with caching and validation)
	// Returns typed mandate (already validated by GetOrFetch) and raw bytes (for forwarding)
	_, rawMandateBytes, err := d.Cache.GetOrFetch(
		ctx,
		qk,
		d.Key.JKT(),
		cfg.SellerANS,
		cfg.ScopePrefix,
		d.Authority,
		d.Clock,
		func(qk QuoteKey) MandateInput {
			return MandateInput{
				QuoteID:         qk.QuoteID,
				Total:           qk.Amount,
				Currency:        qk.Currency,
				MerchantANS:     cfg.SellerANS,
				ScopeHint:       cfg.ScopePrefix,
				SubjectANS:      cfg.SubjectANS,
				TravelerDPoPJWK: d.Key.PublicJWK(),
			}
		},
	)
	if err != nil {
		return Outcome{Kind: Deny, Reason: fmt.Sprintf("mandate error: %v", err)}
	}

	// Mint DPoP proof
	// CRITICAL: htu is htuOverride (if set) or cfg.SellerMCPURL (trailing slash preserved), not reconstructed
	htu := cfg.SellerMCPURL
	if htuOverride != "" {
		htu = htuOverride
	}
	proof, err := MintDPoP(d.Key, htu, quoteID, d.Clock.NowUnix(), d.Nonce.JTI())
	if err != nil {
		return Outcome{Kind: Deny, Reason: fmt.Sprintf("dpop mint error: %v", err)}
	}

	// Splice mandate and dpop_proof into arguments (overwrite if present)
	// CRITICAL: Use json.RawMessage so Marshal emits the authority's bytes VERBATIM
	args["mandate"] = rawMandateBytes
	args["dpop_proof"] = proof

	// Re-marshal the request
	rewritten, err := json.Marshal(req)
	if err != nil {
		return Outcome{Kind: Deny, Reason: fmt.Sprintf("marshal error: %v", err)}
	}

	// Check size limit
	if len(rewritten) > cfg.MaxBodyBytes {
		return Outcome{Kind: Deny, Reason: fmt.Sprintf("oversize: %d > %d", len(rewritten), cfg.MaxBodyBytes)}
	}

	return Outcome{Kind: Allow, Body: rewritten, SignURL: htu}
}
