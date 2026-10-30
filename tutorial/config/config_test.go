package config

import (
	"testing"
	"time"

	coreconfig "github.com/agentnameservice/ans-openshell/internal/config"
)

// parse unmarshals YAML into dst using the core config loader's strict parser.
func parse(t *testing.T, yml string, dst any) {
	t.Helper()
	if err := coreconfig.Parse([]byte(yml), dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestCommerceConfig_ParseAndValidate(t *testing.T) {
	t.Run("all fields round-trip", func(t *testing.T) {
		yml := `
seller_mcp_url: https://seller.example.com/mcp/
authority_mcp_url: https://authority.example.com/mcp/
seller_ans: ans://v1.0.8.seller.skybound-travel.com
authority_ans: ans://v1.0.8.authority.skybound-travel.com
scope_hint: purchase:flight:demo
subject_ans: ans://v2.0.0.buyer.example.com
commerce_dpop_key_path: /path/to/key.json
demo_quote_id: demo-quote-001
demo_amount: 500
demo_currency: USD
max_body_bytes: 10000
`
		var c Commerce
		parse(t, yml, &c)

		if c.SellerMCPURL != "https://seller.example.com/mcp/" {
			t.Errorf("SellerMCPURL = %q, want https://seller.example.com/mcp/", c.SellerMCPURL)
		}
		if c.AuthorityMCPURL != "https://authority.example.com/mcp/" {
			t.Errorf("AuthorityMCPURL = %q, want https://authority.example.com/mcp/", c.AuthorityMCPURL)
		}
		if c.SellerANS != "ans://v1.0.8.seller.skybound-travel.com" {
			t.Errorf("SellerANS = %q", c.SellerANS)
		}
		if c.AuthorityANS != "ans://v1.0.8.authority.skybound-travel.com" {
			t.Errorf("AuthorityANS = %q", c.AuthorityANS)
		}
		if c.ScopeHint != "purchase:flight:demo" {
			t.Errorf("ScopeHint = %q", c.ScopeHint)
		}
		if c.SubjectANS != "ans://v2.0.0.buyer.example.com" {
			t.Errorf("SubjectANS = %q", c.SubjectANS)
		}
		if c.CommerceDPoPKeyPath != "/path/to/key.json" {
			t.Errorf("CommerceDPoPKeyPath = %q", c.CommerceDPoPKeyPath)
		}
		if c.DemoQuoteID != "demo-quote-001" {
			t.Errorf("DemoQuoteID = %q", c.DemoQuoteID)
		}
		if c.DemoAmount != 500 {
			t.Errorf("DemoAmount = %v, want 500", c.DemoAmount)
		}
		if c.DemoCurrency != "USD" {
			t.Errorf("DemoCurrency = %q", c.DemoCurrency)
		}
		if c.MaxBodyBytes != 10000 {
			t.Errorf("MaxBodyBytes = %d, want 10000", c.MaxBodyBytes)
		}
	})

	t.Run("Enabled reflects key presence", func(t *testing.T) {
		c := Commerce{}
		if c.Enabled() {
			t.Errorf("Enabled() = true for empty config")
		}

		c.CommerceDPoPKeyPath = "/path/to/key.json"
		if !c.Enabled() {
			t.Errorf("Enabled() = false with key path set")
		}

		c.CommerceDPoPKeyPath = ""
		t.Setenv("COMMERCE_DPOP_KEY", "/env/key.json")
		if !c.Enabled() {
			t.Errorf("Enabled() = false with COMMERCE_DPOP_KEY env set")
		}
	})

	t.Run("Validate requires fields when Enabled", func(t *testing.T) {
		c := Commerce{}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() = %v for disabled config", err)
		}

		c.CommerceDPoPKeyPath = "/path/to/key.json"
		if err := c.Validate(); err == nil {
			t.Errorf("Validate() = nil, want error for missing URLs/ANS")
		}

		c.SellerMCPURL = "https://seller.example.com/mcp/"
		c.AuthorityMCPURL = "https://authority.example.com/mcp/"
		c.SellerANS = "ans://v1.0.8.seller.skybound-travel.com"
		c.AuthorityANS = "ans://v1.0.8.authority.skybound-travel.com"
		c.ScopeHint = "purchase:flight:demo"
		c.SubjectANS = "ans://v2.0.0.buyer.example.com"
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() = %v for complete config", err)
		}
	})

	t.Run("DiscoveryTTL field parses", func(t *testing.T) {
		yml := `
seller_mcp_url: https://seller.example.com/mcp/
authority_mcp_url: https://authority.example.com/mcp/
seller_ans: ans://v1.0.8.seller.skybound-travel.com
authority_ans: ans://v1.0.8.authority.skybound-travel.com
scope_hint: purchase:flight:demo
subject_ans: ans://v2.0.0.buyer.example.com
commerce_dpop_key_path: /path/to/key.json
discovery_ttl: 5m
`
		var c Commerce
		parse(t, yml, &c)
		if c.DiscoveryTTL != 5*time.Minute {
			t.Errorf("DiscoveryTTL = %v, want 5m", c.DiscoveryTTL)
		}

		yml2 := `
seller_mcp_url: https://seller.example.com/mcp/
authority_mcp_url: https://authority.example.com/mcp/
seller_ans: ans://v1.0.8.seller.skybound-travel.com
authority_ans: ans://v1.0.8.authority.skybound-travel.com
scope_hint: purchase:flight:demo
subject_ans: ans://v2.0.0.buyer.example.com
commerce_dpop_key_path: /path/to/key.json
`
		var c2 Commerce
		parse(t, yml2, &c2)
		if c2.DiscoveryTTL != 0 {
			t.Errorf("DiscoveryTTL = %v, want 0 when omitted", c2.DiscoveryTTL)
		}
	})
}
