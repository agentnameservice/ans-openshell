package commerce

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-openshell/internal/commercekey"
)

// loadTestKey loads a fixed test key for deterministic tests.
func loadRewriteTestKey(t *testing.T) *commercekey.Key {
	t.Helper()
	tempPEM := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEjRWeJA0VniQNFZ4
kDRWeJA0VniQNFZ4kDRWeJA0VnihRANCAAR7VJCMjvKZnHnHvS3xdKaPXM5pHvEJ
qxLJH8nppWLHVdJvxMlvmJNLcQh3PRe6mXF1wnTvzWFhZj0c+0/qrjPd
-----END PRIVATE KEY-----`

	tmpfile := t.TempDir() + "/test.pem"
	if err := os.WriteFile(tmpfile, []byte(tempPEM), 0600); err != nil {
		t.Fatal(err)
	}

	key, err := commercekey.Load(tmpfile)
	if err != nil {
		t.Fatalf("failed to load test key: %v", err)
	}
	return key
}

// fakeAuthorityWithError is a fake AuthorityClient that can return errors.
type fakeAuthorityWithError struct {
	mandate *Mandate
	err     error
}

func (f *fakeAuthorityWithError) RequestMandate(_ context.Context, _ MandateInput) (*Mandate, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.mandate, nil
}

// fakeNonce is a fake Nonce for testing.
type fakeNonce struct {
	jti string
}

func (f *fakeNonce) JTI() string {
	return f.jti
}

func TestRewrite_PassthroughNonJSON(t *testing.T) {
	body := []byte("not json")
	deps := Deps{}
	cfg := Config{}

	outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

	if outcome.Kind != Passthrough {
		t.Errorf("expected Passthrough, got %v", outcome.Kind)
	}
	if len(outcome.Body) != 0 {
		t.Errorf("expected no body for Passthrough, got %d bytes", len(outcome.Body))
	}
}

func TestRewrite_PassthroughNotBookFlight(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"other_tool","arguments":{}}}`)
	deps := Deps{}
	cfg := Config{}

	outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

	if outcome.Kind != Passthrough {
		t.Errorf("expected Passthrough, got %v", outcome.Kind)
	}
	if len(outcome.Body) != 0 {
		t.Errorf("expected no body for Passthrough, got %d bytes", len(outcome.Body))
	}
}

func TestRewrite_DenyMissingArgs(t *testing.T) {
	// Missing quote_id
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_flight","arguments":{"amount":500,"currency":"USD"}}}`)
	deps := Deps{}
	cfg := Config{}

	outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

	if outcome.Kind != Deny {
		t.Errorf("expected Deny, got %v", outcome.Kind)
	}
	if len(outcome.Body) != 0 {
		t.Errorf("expected no body for Deny, got %d bytes", len(outcome.Body))
	}
	if !strings.Contains(outcome.Reason, "quote_id") {
		t.Errorf("expected reason to mention quote_id, got %q", outcome.Reason)
	}
}

func TestRewrite_AllowSplicesMandateAndProof(t *testing.T) {
	// Create a test commerce key
	key := loadRewriteTestKey(t)

	// Create a fake mandate that will pass validation
	mandate := &Mandate{
		MandateID:    "mandate-001",
		QuoteID:      "demo-quote-001",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.skybound-travel.com",
		Scope:        "commerce.payment:write",
		MaxAmount:    1000.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-12-31T23:59:59Z",
		JKT:          key.JKT(),
		AuthorityANS: "ans://authority.example.com",
		Signature:    "fake-signature",
	}

	fakeAuth := &fakeAuthorityWithError{mandate: mandate}
	clock := fakeClock{now: 1735689600} // 2025-01-01 00:00:00
	nonce := &fakeNonce{jti: "test-jti-123"}

	deps := Deps{
		Key:       key,
		Cache:     NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}

	cfg := Config{
		SellerMCPURL: "https://seller.skybound-travel.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)

	outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

	if outcome.Kind != Allow {
		t.Fatalf("expected Allow, got %v: %s", outcome.Kind, outcome.Reason)
	}

	if len(outcome.Body) == 0 {
		t.Fatal("expected body for Allow, got none")
	}

	// Parse the result
	var result map[string]any
	if err := json.Unmarshal(outcome.Body, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Check params.arguments
	params, ok := result["params"].(map[string]any)
	if !ok {
		t.Fatal("params not found or not a map")
	}

	args, ok := params["arguments"].(map[string]any)
	if !ok {
		t.Fatal("arguments not found or not a map")
	}

	// Check that mandate was spliced
	mandateObj, ok := args["mandate"].(map[string]any)
	if !ok {
		t.Fatal("mandate not found or not an object")
	}

	if mandateObj["mandate_id"] != "mandate-001" {
		t.Errorf("expected mandate_id mandate-001, got %v", mandateObj["mandate_id"])
	}

	// Check that dpop_proof was spliced
	dpopProof, ok := args["dpop_proof"].(string)
	if !ok {
		t.Fatal("dpop_proof not found or not a string")
	}

	// Check it's a 3-part JWS
	if len(strings.Split(dpopProof, ".")) != 3 {
		t.Errorf("expected 3-part JWS, got %q", dpopProof)
	}

	// Check original fields are preserved
	if args["quote_id"] != "demo-quote-001" {
		t.Errorf("quote_id not preserved")
	}

	if args["currency"] != "USD" {
		t.Errorf("currency not preserved")
	}

	// CRITICAL: Check that amount stays as 500, not 500.0
	// Re-marshal and check the byte representation
	bodyStr := string(outcome.Body)
	if !strings.Contains(bodyStr, `"amount":500`) {
		t.Errorf("expected amount to be preserved as 500 (no decimal), got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, `"amount":500.0`) {
		t.Errorf("amount was incorrectly converted to 500.0")
	}
}

func TestRewrite_DenyOversize(t *testing.T) {
	// Create a test commerce key
	key := loadRewriteTestKey(t)

	// Create a fake mandate
	mandate := &Mandate{
		MandateID:    "mandate-001",
		QuoteID:      "demo-quote-001",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.skybound-travel.com",
		Scope:        "commerce.payment:write",
		MaxAmount:    1000.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-12-31T23:59:59Z",
		JKT:          key.JKT(),
		AuthorityANS: "ans://authority.example.com",
		Signature:    "fake-signature",
	}

	fakeAuth := &fakeAuthorityWithError{mandate: mandate}
	clock := fakeClock{now: 1735689600}
	nonce := &fakeNonce{jti: "test-jti-123"}

	deps := Deps{
		Key:       key,
		Cache:     NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}

	cfg := Config{
		SellerMCPURL: "https://seller.skybound-travel.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10, // Tiny limit to trigger oversize
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)

	outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

	if outcome.Kind != Deny {
		t.Errorf("expected Deny for oversize, got %v", outcome.Kind)
	}

	if len(outcome.Body) != 0 {
		t.Errorf("expected no body for Deny, got %d bytes", len(outcome.Body))
	}

	if !strings.Contains(outcome.Reason, "oversize") && !strings.Contains(outcome.Reason, "size") {
		t.Errorf("expected reason to mention size, got %q", outcome.Reason)
	}
}

func TestRewrite_HtuOverride(t *testing.T) {
	// Test that htuOverride is used for DPoP htu when set, else static cfg.SellerMCPURL.
	key := loadRewriteTestKey(t)
	mandate := &Mandate{
		MandateID:    "mandate-001",
		QuoteID:      "demo-quote-001",
		SubjectANS:   "ans://traveler.example.com",
		AudienceANS:  "ans://seller.skybound-travel.com",
		Scope:        "commerce.payment:write",
		MaxAmount:    1000.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-12-31T23:59:59Z",
		JKT:          key.JKT(),
		AuthorityANS: "ans://authority.example.com",
		Signature:    "fake-signature",
	}

	fakeAuth := &fakeAuthorityWithError{mandate: mandate}
	clock := fakeClock{now: 1735689600}
	nonce := &fakeNonce{jti: "test-jti-123"}

	deps := Deps{
		Key:       key,
		Cache:     NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}

	cfg := Config{
		SellerMCPURL: "https://seller.skybound-travel.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)

	t.Run("with override", func(t *testing.T) {
		override := "https://other-seller.example.com/mcp/"
		outcome := RewriteBookFlight(context.Background(), body, deps, cfg, override)

		if outcome.Kind != Allow {
			t.Fatalf("expected Allow, got %v: %s", outcome.Kind, outcome.Reason)
		}

		// Decode dpop_proof and check htu == override
		var result map[string]any
		if err := json.Unmarshal(outcome.Body, &result); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		params := result["params"].(map[string]any)
		args := params["arguments"].(map[string]any)
		dpopProof := args["dpop_proof"].(string)

		parts := strings.Split(dpopProof, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3-part JWS, got %d parts", len(parts))
		}
		var claims map[string]any
		if err := json.Unmarshal(mustBase64Decode(parts[1]), &claims); err != nil {
			t.Fatalf("unmarshal claims: %v", err)
		}
		htu, ok := claims["htu"].(string)
		if !ok {
			t.Fatal("htu not found in claims")
		}
		if htu != override {
			t.Errorf("htu = %q, want %q", htu, override)
		}
	})

	t.Run("without override", func(t *testing.T) {
		outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

		if outcome.Kind != Allow {
			t.Fatalf("expected Allow, got %v: %s", outcome.Kind, outcome.Reason)
		}

		// Decode dpop_proof and check htu == cfg.SellerMCPURL
		var result map[string]any
		if err := json.Unmarshal(outcome.Body, &result); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		params := result["params"].(map[string]any)
		args := params["arguments"].(map[string]any)
		dpopProof := args["dpop_proof"].(string)

		parts := strings.Split(dpopProof, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3-part JWS, got %d parts", len(parts))
		}
		var claims map[string]any
		if err := json.Unmarshal(mustBase64Decode(parts[1]), &claims); err != nil {
			t.Fatalf("unmarshal claims: %v", err)
		}
		htu, ok := claims["htu"].(string)
		if !ok {
			t.Fatal("htu not found in claims")
		}
		if htu != cfg.SellerMCPURL {
			t.Errorf("htu = %q, want %q", htu, cfg.SellerMCPURL)
		}
	})
}

func mustBase64Decode(s string) []byte {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestRewrite_DenyOnMandateError(t *testing.T) {
	// Create a test commerce key
	key := loadRewriteTestKey(t)

	// Create a fake authority that returns an error
	fakeAuth := &fakeAuthorityWithError{err: context.DeadlineExceeded}
	clock := fakeClock{now: 1735689600}
	nonce := &fakeNonce{jti: "test-jti-123"}

	deps := Deps{
		Key:       key,
		Cache:     NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}

	cfg := Config{
		SellerMCPURL: "https://seller.skybound-travel.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)

	outcome := RewriteBookFlight(context.Background(), body, deps, cfg, "")

	if outcome.Kind != Deny {
		t.Errorf("expected Deny on mandate error, got %v", outcome.Kind)
	}

	if len(outcome.Body) != 0 {
		t.Errorf("expected no body for Deny, got %d bytes", len(outcome.Body))
	}
}
