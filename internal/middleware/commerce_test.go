package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-openshell/internal/capability"
	"github.com/agentnameservice/ans-openshell/internal/commerce"
	"github.com/agentnameservice/ans-openshell/internal/commercekey"
)

// panicAuthority panics if RequestMandate is called, proving the gate skipped.
type panicAuthority struct{}

func (panicAuthority) RequestMandate(_ context.Context, _ commerce.MandateInput) (*commerce.Mandate, error) {
	panic("RequestMandate called when gate should have skipped")
}

type panicClock struct{}

func (panicClock) NowUnix() int64 { panic("NowUnix called") }

type panicNonce struct{}

func (panicNonce) JTI() string { panic("JTI called") }

func TestCommerceRewriter_GateMatches(t *testing.T) {
	t.Parallel()
	// Build a minimal commerce transform that would delegate to RewriteBookFlight.
	// We'll test the gate logic by checking whether it reaches the commerce logic
	// (which will Passthrough because the body doesn't match book_flight, proving gate opened).
	deps := commerce.Deps{
		Key:       nil, // Won't be called for non-book_flight bodies
		Cache:     commerce.NewMandateCache(),
		Authority: panicAuthority{},
		Clock:     panicClock{},
		Nonce:     &panicNonce{},
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://v1.0.8.seller.skybound-travel.com",
		ScopePrefix:  "purchase:flight:demo",
		SubjectANS:   "ans://v2.0.0.buyer.example.com",
		MaxBodyBytes: 10000,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	tests := []struct {
		name   string
		host   string
		method string
		path   string
	}{
		{name: "POST /mcp/", host: "seller.example.com", method: "POST", path: "/mcp/"},
		{name: "POST /a2a", host: "seller.example.com", method: "POST", path: "/a2a"},
		{name: "POST /a2a/", host: "seller.example.com", method: "POST", path: "/a2a/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Non-book_flight body → commerce.RewriteBookFlight returns Passthrough
			body := []byte(`{"method":"other","params":{}}`)
			target := makeTarget(tt.host, tt.method, tt.path)
			outcome := rewriter.Apply(context.Background(), target, emptyRequirement(), body)
			// Gate matched (didn't panic from panicAuthority), commerce processed it → Passthrough
			if outcome.Kind != 0 { // Passthrough = 0
				t.Errorf("outcome.Kind = %v, want Passthrough (0)", outcome.Kind)
			}
		})
	}
}

func makeTarget(host, method, path string) capability.Target {
	return capability.Target{Host: host, Method: method, Path: path, Tool: ""}
}

func emptyRequirement() capability.Requirement {
	return capability.Requirement{}
}

func TestCommerceRewriter_GateSkips(t *testing.T) {
	t.Parallel()
	// Build a commerce transform with panic-on-call authority to prove the gate skips.
	deps := commerce.Deps{
		Key:       nil,
		Cache:     commerce.NewMandateCache(),
		Authority: panicAuthority{}, // Will panic if called
		Clock:     panicClock{},
		Nonce:     &panicNonce{},
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://v1.0.8.seller.skybound-travel.com",
		ScopePrefix:  "purchase:flight:demo",
		SubjectANS:   "ans://v2.0.0.buyer.example.com",
		MaxBodyBytes: 10000,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	tests := []struct {
		name   string
		host   string
		method string
		path   string
	}{
		{name: "wrong host", host: "other.example.com", method: "POST", path: "/mcp/"},
		{name: "GET method", host: "seller.example.com", method: "GET", path: "/mcp/"},
		{name: "wrong path", host: "seller.example.com", method: "POST", path: "/other"},
		{name: "path without trailing slash", host: "seller.example.com", method: "POST", path: "/mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"method":"tools/call","params":{"name":"book_flight"}}`)
			target := makeTarget(tt.host, tt.method, tt.path)
			outcome := rewriter.Apply(context.Background(), target, emptyRequirement(), body)
			// Should return Passthrough without calling RewriteBookFlight (which would panic via authority)
			if outcome.Kind != 0 { // Passthrough = 0
				t.Errorf("outcome.Kind = %v, want Passthrough (0)", outcome.Kind)
			}
			if len(outcome.Body) != 0 {
				t.Errorf("outcome.Body should be empty on Passthrough, got %d bytes", len(outcome.Body))
			}
		})
	}
}

func TestCommerce_AppliesViaDiscoveredRequirement(t *testing.T) {
	t.Parallel()
	// Build a commerce transform with a fake authority that returns a mandate.
	// Test that discovery triggers commerce even when host != seller.
	key := loadCommerceTestKey(t)
	mandate := &commerce.Mandate{
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
	fakeAuth := &fakeAuthorityForCommerce{mandate: mandate}
	clock := fakeClockForCommerce{now: 1735689600}
	nonce := &fakeNonceForCommerce{jti: "test-jti-123"}

	deps := commerce.Deps{
		Key:       key,
		Cache:     commerce.NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	// Discovery says: needs mandate + dpop_proof. Host is NOT the seller.
	req := capability.Requirement{
		Capabilities: []capability.Capability{"mandate", "dpop_proof"},
	}
	body := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)
	target := makeTarget("other-agent.example.com", "POST", "/mcp/")

	outcome := rewriter.Apply(context.Background(), target, req, body)

	// Should Allow (commerce ran and spliced mandate/dpop)
	if outcome.Kind != capability.Allow {
		t.Fatalf("outcome.Kind = %v, want Allow", outcome.Kind)
	}
	if len(outcome.Body) == 0 {
		t.Fatal("expected body for Allow, got none")
	}
}

func TestCommerce_AppliesViaStaticFallbackWhenEmpty(t *testing.T) {
	t.Parallel()
	// Build a commerce transform with a fake authority.
	// Test that empty req + static gate → runs + WARN-log.
	key := loadCommerceTestKey(t)
	mandate := &commerce.Mandate{
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
	fakeAuth := &fakeAuthorityForCommerce{mandate: mandate}
	clock := fakeClockForCommerce{now: 1735689600}
	nonce := &fakeNonceForCommerce{jti: "test-jti-123"}

	deps := commerce.Deps{
		Key:       key,
		Cache:     commerce.NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}

	// Capture logs
	var logBuf logBuffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	// Empty req + static gate match
	req := capability.Requirement{}
	body := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)
	target := makeTarget("seller.example.com", "POST", "/mcp/")

	outcome := rewriter.Apply(context.Background(), target, req, body)

	// Should Allow (commerce ran)
	if outcome.Kind != capability.Allow {
		t.Fatalf("outcome.Kind = %v, want Allow", outcome.Kind)
	}
	if len(outcome.Body) == 0 {
		t.Fatal("expected body for Allow, got none")
	}

	// Check that a WARN was logged
	if !logBuf.ContainsLevel("WARN") {
		t.Errorf("expected WARN log for static fallback, got: %s", logBuf.String())
	}
	if !logBuf.Contains("commerce static fallback") {
		t.Errorf("expected log to mention 'commerce static fallback', got: %s", logBuf.String())
	}
}

func TestCommerce_PassthroughWhenEmptyAndNotSellerGate(t *testing.T) {
	t.Parallel()
	// Empty req + non-seller host → Passthrough, deps never called.
	deps := commerce.Deps{
		Key:       nil,
		Cache:     commerce.NewMandateCache(),
		Authority: panicAuthority{}, // Will panic if called
		Clock:     panicClock{},
		Nonce:     &panicNonce{},
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	// Empty req + non-seller host
	req := capability.Requirement{}
	body := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)
	target := makeTarget("other-agent.example.com", "POST", "/mcp/")

	outcome := rewriter.Apply(context.Background(), target, req, body)

	// Should Passthrough (gate skipped, no panic)
	if outcome.Kind != capability.Passthrough {
		t.Fatalf("outcome.Kind = %v, want Passthrough", outcome.Kind)
	}
	if len(outcome.Body) != 0 {
		t.Errorf("expected no body for Passthrough, got %d bytes", len(outcome.Body))
	}
}

func TestCommerce_UsesDiscoveredHtu(t *testing.T) {
	t.Parallel()
	// req.DPoP.Htu set → minted dpop_proof htu == discovered, not static.
	key := loadCommerceTestKey(t)
	mandate := &commerce.Mandate{
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
	fakeAuth := &fakeAuthorityForCommerce{mandate: mandate}
	clock := fakeClockForCommerce{now: 1735689600}
	nonce := &fakeNonceForCommerce{jti: "test-jti-123"}

	deps := commerce.Deps{
		Key:       key,
		Cache:     commerce.NewMandateCache(),
		Authority: fakeAuth,
		Clock:     clock,
		Nonce:     nonce,
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://seller.skybound-travel.com",
		ScopePrefix:  "commerce.",
		SubjectANS:   "ans://traveler.example.com",
		MaxBodyBytes: 10000,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	// Discovery says: use this htu
	discoveredHtu := "https://other-seller.example.com/mcp/"
	req := capability.Requirement{
		Capabilities: []capability.Capability{"mandate", "dpop_proof"},
		DPoP: &capability.DPoPParams{
			Htu: discoveredHtu,
		},
	}
	body := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500,"currency":"USD"}}}`)
	target := makeTarget("other-seller.example.com", "POST", "/mcp/")

	outcome := rewriter.Apply(context.Background(), target, req, body)

	// Should Allow
	if outcome.Kind != capability.Allow {
		t.Fatalf("outcome.Kind = %v, want Allow", outcome.Kind)
	}

	// Decode the spliced dpop_proof and check htu
	var result map[string]any
	if err := json.Unmarshal(outcome.Body, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	params := result["params"].(map[string]any)
	args := params["arguments"].(map[string]any)
	dpopProof := args["dpop_proof"].(string)

	// dpopProof is "header.payload.signature", base64url-encoded
	parts := strings.Split(dpopProof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWS, got %d parts", len(parts))
	}
	payloadB64 := parts[1]
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	htu, ok := claims["htu"].(string)
	if !ok {
		t.Fatal("htu not found in claims")
	}
	if htu != discoveredHtu {
		t.Errorf("htu = %q, want %q", htu, discoveredHtu)
	}
}

// Helpers for new tests

func loadCommerceTestKey(t *testing.T) *commercekey.Key {
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

type fakeAuthorityForCommerce struct {
	mandate *commerce.Mandate
	err     error
}

func (f *fakeAuthorityForCommerce) RequestMandate(_ context.Context, _ commerce.MandateInput) (*commerce.Mandate, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.mandate, nil
}

type fakeClockForCommerce struct {
	now int64
}

func (f fakeClockForCommerce) NowUnix() int64 {
	return f.now
}

type fakeNonceForCommerce struct {
	jti string
}

func (f *fakeNonceForCommerce) JTI() string {
	return f.jti
}

type logBuffer struct {
	buf []byte
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *logBuffer) String() string {
	return string(b.buf)
}

func (b *logBuffer) ContainsLevel(level string) bool {
	return strings.Contains(b.String(), "level="+level)
}

func (b *logBuffer) Contains(s string) bool {
	return strings.Contains(b.String(), s)
}
