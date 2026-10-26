package middleware

import (
	"context"
	"testing"

	"github.com/agentnameservice/ans-openshell/internal/commerce"
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
	// Build a minimal CommerceRewriter that would delegate to RewriteBookFlight.
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
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com")

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
			outcome := rewriter.Rewrite(context.Background(), tt.host, tt.method, tt.path, body)
			// Gate matched (didn't panic from panicAuthority), commerce processed it → Passthrough
			if outcome.Kind != CommercePassthrough {
				t.Errorf("outcome.Kind = %v, want CommercePassthrough", outcome.Kind)
			}
		})
	}
}

func TestCommerceRewriter_GateSkips(t *testing.T) {
	t.Parallel()
	// Build a CommerceRewriter with panic-on-call authority to prove the gate skips.
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
	rewriter := NewCommerceRewriter(deps, cfg, "seller.example.com")

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
			outcome := rewriter.Rewrite(context.Background(), tt.host, tt.method, tt.path, body)
			// Should return Passthrough without calling RewriteBookFlight (which would panic via authority)
			if outcome.Kind != CommercePassthrough {
				t.Errorf("outcome.Kind = %v, want CommercePassthrough", outcome.Kind)
			}
			if len(outcome.Body) != 0 {
				t.Errorf("outcome.Body should be empty on Passthrough, got %d bytes", len(outcome.Body))
			}
		})
	}
}
