// Package config holds the tutorial (commerce) configuration. It is separate
// from the core middleware config: the production binary never parses it. The
// demo binary embeds the generic app.Config and adds this Commerce block.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/agentnameservice/ans-openshell/app"
)

// FileConfig is the YAML shape the demo binary loads: the generic middleware
// app.Config inlined, plus the tutorial Commerce block. Both the demo binary
// (tutorial/cmd/ans-demo-middleware) and the example-config test use this type,
// so the two cannot drift from each other.
type FileConfig struct {
	app.Config `yaml:",inline"`
	Commerce   Commerce `yaml:"commerce"`
}

// Commerce configures the commerce capability transform (AP2 mandate + DPoP).
type Commerce struct {
	// SellerMCPURL is the seller's MCP endpoint URL (used as DPoP htu).
	SellerMCPURL string `yaml:"seller_mcp_url"`
	// AuthorityMCPURL is the authority's MCP endpoint URL.
	AuthorityMCPURL string `yaml:"authority_mcp_url"`
	// SellerANS is the seller's ANS identifier.
	SellerANS string `yaml:"seller_ans"`
	// AuthorityANS is the authority's ANS identifier.
	AuthorityANS string `yaml:"authority_ans"`
	// ScopeHint is the expected scope prefix for mandates.
	ScopeHint string `yaml:"scope_hint"`
	// SubjectANS is the subject ANS identifier for mandate requests.
	SubjectANS string `yaml:"subject_ans"`
	// CommerceDPoPKeyPath is the path to the commerce DPoP key JSON file.
	CommerceDPoPKeyPath string `yaml:"commerce_dpop_key_path"`
	// DemoQuoteID is the quote ID for demo mandate prefetch.
	DemoQuoteID string `yaml:"demo_quote_id"`
	// DemoAmount is the amount for demo mandate prefetch.
	DemoAmount float64 `yaml:"demo_amount"`
	// DemoCurrency is the currency for demo mandate prefetch.
	DemoCurrency string `yaml:"demo_currency"`
	// MaxBodyBytes is the maximum body size after rewriting.
	MaxBodyBytes int `yaml:"max_body_bytes"`
	// DiscoveryTTL is the agent-card/tools-list discovery cache TTL; 0 means the default.
	DiscoveryTTL time.Duration `yaml:"discovery_ttl"`
}

// Enabled reports whether commerce is configured (a DPoP key is provided either
// in the file or via the COMMERCE_DPOP_KEY environment variable).
func (c Commerce) Enabled() bool {
	return c.CommerceDPoPKeyPath != "" || os.Getenv("COMMERCE_DPOP_KEY") != ""
}

// Validate checks that all required commerce fields are present when enabled.
func (c Commerce) Validate() error {
	if !c.Enabled() {
		return nil
	}
	var missing []string
	if c.SellerMCPURL == "" {
		missing = append(missing, "seller_mcp_url")
	}
	if c.AuthorityMCPURL == "" {
		missing = append(missing, "authority_mcp_url")
	}
	if c.SellerANS == "" {
		missing = append(missing, "seller_ans")
	}
	if c.AuthorityANS == "" {
		missing = append(missing, "authority_ans")
	}
	if c.ScopeHint == "" {
		missing = append(missing, "scope_hint")
	}
	if c.SubjectANS == "" {
		missing = append(missing, "subject_ans")
	}
	if len(missing) > 0 {
		return fmt.Errorf("commerce: missing %v", missing)
	}
	return nil
}
