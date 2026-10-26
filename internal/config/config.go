// Package config holds the configuration blocks shared by the extension
// binaries and loads them from YAML.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// TLS configures the extension's own gRPC listener certificate. OpenShell
// verifies it with the registration's tls_ca_cert_path.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether a certificate is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// Validate checks that both halves of the key pair are present when either is.
func (t TLS) Validate() error {
	if t.Enabled() && (t.CertFile == "" || t.KeyFile == "") {
		return errors.New("tls: cert_file and key_file must both be set")
	}
	return nil
}

// Auth configures verification of the JWT OpenShell presents on every call.
type Auth struct {
	// GatewayIssuer is the exact iss claim, "openshell-gateway:<gateway_id>".
	GatewayIssuer string `yaml:"gateway_issuer"`
	// Audience is the exact aud claim configured on the OpenShell registration,
	// by default "urn:openshell:extension:middleware:<name>" or
	// "urn:openshell:extension:interceptor:<name>".
	Audience string `yaml:"audience"`
	// JWKSFile is the operator-provisioned gateway signing key set, the
	// cold-start trust anchor.
	JWKSFile string `yaml:"jwks_file"`
	// JWKSURL is the gateway's /.well-known/jwks.json for steady-state key
	// refresh. Optional; keys from the file remain trusted.
	JWKSURL string `yaml:"jwks_url"`
	// JWKSRefreshInterval bounds how often JWKSURL is polled. Zero selects the
	// package default.
	JWKSRefreshInterval time.Duration `yaml:"jwks_refresh_interval"`
	// AllowInsecureNoAuth disables JWT verification. It matches an OpenShell
	// registration with allow_insecure_transport = true and is for local
	// development only: without it, anyone who can reach the service can have
	// proofs minted in the agent's name.
	AllowInsecureNoAuth bool `yaml:"allow_insecure_no_auth"`
}

// Validate checks the block is usable: either insecure mode is explicit or an
// issuer, audience and at least one key source are set.
func (a Auth) Validate() error {
	if a.AllowInsecureNoAuth {
		return nil
	}
	var missing []string
	if a.GatewayIssuer == "" {
		missing = append(missing, "gateway_issuer")
	}
	if a.Audience == "" {
		missing = append(missing, "audience")
	}
	if a.JWKSFile == "" && a.JWKSURL == "" {
		missing = append(missing, "jwks_file or jwks_url")
	}
	if len(missing) > 0 {
		return fmt.Errorf("auth: missing %v (or set allow_insecure_no_auth: true for local development)", missing)
	}
	return nil
}

// TransparencyLog configures the ANS transparency log the identities'
// receipts and status tokens are fetched from.
type TransparencyLog struct {
	BaseURL string `yaml:"base_url"`
	// RootKeys are the log's trusted signing keys in C2SP format. RootKeysFile
	// may supply them one per line instead of, or in addition to, RootKeys.
	RootKeys     []string `yaml:"root_keys"`
	RootKeysFile string   `yaml:"root_keys_file"`
	// AllowInsecureTransport permits an http:// base URL for local development.
	AllowInsecureTransport bool `yaml:"allow_insecure_transport"`
}

// Validate checks a base URL is set.
func (t TransparencyLog) Validate() error {
	if t.BaseURL == "" {
		return errors.New("transparency_log: base_url is required")
	}
	return nil
}

// Vetting configures destination vetting for the middleware and interceptor.
type Vetting struct {
	// TrustedTLDomains is the allowlist of transparency-log hosts an
	// _ans-badge record may point at. It is the trust root of the badge tier
	// and must come from operator configuration, never from DNS.
	TrustedTLDomains []string `yaml:"trusted_tl_domains"`
	// CacheTTL is how long a verdict is served without a fresh lookup.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// RequestBudget is the longest the middleware waits for an in-flight lookup
	// on a cache miss under require_registered; observe mode never waits.
	RequestBudget time.Duration `yaml:"request_budget"`
	// TrustIndexURL enables the Trust Vector threshold check when set; it
	// requires MinTrustScore.
	TrustIndexURL string `yaml:"trust_index_url"`
	// MinTrustScore is the floor every Trust Vector dimension (0 to 100) must
	// clear. The Trust Index publishes no composite score.
	MinTrustScore float64 `yaml:"min_trust_score"`
	// ExemptHosts are destinations never vetted (provider APIs that are not
	// ANS agents, for example). Exact hostnames or "*.suffix" patterns.
	ExemptHosts []string `yaml:"exempt_hosts"`
}

// Commerce configures the commerce rewriter for Tier 2 demo.
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

// Enabled reports whether commerce is configured.
func (c Commerce) Enabled() bool {
	return c.CommerceDPoPKeyPath != "" || os.Getenv("COMMERCE_DPOP_KEY") != ""
}

// Validate checks that required fields are set when Enabled.
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

// Load reads the YAML file at path into dst, rejecting unknown fields so a
// misspelled key cannot silently disable a control.
func Load(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	return Parse(b, dst)
}

// Parse decodes YAML bytes into dst with strict field checking.
func Parse(b []byte, dst any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}
