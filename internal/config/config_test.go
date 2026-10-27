package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tls     TLS
		enabled bool
		wantErr bool
	}{
		{name: "disabled", tls: TLS{}, enabled: false},
		{name: "both set", tls: TLS{CertFile: "c.pem", KeyFile: "k.pem"}, enabled: true},
		{name: "cert only", tls: TLS{CertFile: "c.pem"}, enabled: true, wantErr: true},
		{name: "key only", tls: TLS{KeyFile: "k.pem"}, enabled: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.tls.Enabled(); got != tt.enabled {
				t.Fatalf("Enabled() = %v, want %v", got, tt.enabled)
			}
			if err := tt.tls.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		auth    Auth
		wantErr string
	}{
		{name: "insecure explicit", auth: Auth{AllowInsecureNoAuth: true}},
		{name: "file source", auth: Auth{GatewayIssuer: "openshell-gateway:g1", Audience: "urn:openshell:extension:middleware:ans", JWKSFile: "jwks.json"}},
		{name: "url source", auth: Auth{GatewayIssuer: "openshell-gateway:g1", Audience: "urn:openshell:extension:middleware:ans", JWKSURL: "https://gw/.well-known/jwks.json"}},
		{name: "missing everything", auth: Auth{}, wantErr: "gateway_issuer audience jwks_file or jwks_url"},
		{name: "missing keys", auth: Auth{GatewayIssuer: "i", Audience: "a"}, wantErr: "jwks_file or jwks_url"},
		{name: "missing audience", auth: Auth{GatewayIssuer: "i", JWKSFile: "f"}, wantErr: "audience"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.auth.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error mentioning %q", tt.wantErr)
			}
			for _, want := range strings.Fields(strings.ReplaceAll(tt.wantErr, "jwks_file or jwks_url", "jwks_file")) {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Validate() error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestTransparencyLogValidate(t *testing.T) {
	t.Parallel()
	if err := (TransparencyLog{}).Validate(); err == nil {
		t.Fatal("Validate() = nil for empty base_url")
	}
	if err := (TransparencyLog{BaseURL: "https://tl.example"}).Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

type sample struct {
	TLS     TLS             `yaml:"tls"`
	Auth    Auth            `yaml:"auth"`
	TL      TransparencyLog `yaml:"transparency_log"`
	Vetting Vetting         `yaml:"vetting"`
}

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		yaml    string
		want    func(t *testing.T, s sample)
		wantErr bool
	}{
		{
			name: "full document",
			yaml: `
tls: {cert_file: c.pem, key_file: k.pem}
auth:
  gateway_issuer: openshell-gateway:g1
  audience: urn:openshell:extension:middleware:ans
  jwks_file: jwks.json
  jwks_refresh_interval: 5m
transparency_log:
  base_url: https://tl.example
  root_keys: ["tl+aaaaaaaa+AAAA"]
vetting:
  trusted_tl_domains: [tl.example]
  cache_ttl: 10m
  request_budget: 150ms
  min_trust_score: 60
  exempt_hosts: ["*.openai.com"]
`,
			want: func(t *testing.T, s sample) {
				t.Helper()
				if s.Auth.JWKSRefreshInterval != 5*time.Minute {
					t.Fatalf("jwks_refresh_interval = %v", s.Auth.JWKSRefreshInterval)
				}
				if s.Vetting.RequestBudget != 150*time.Millisecond || s.Vetting.MinTrustScore != 60 {
					t.Fatalf("vetting = %+v", s.Vetting)
				}
				if len(s.TL.RootKeys) != 1 || s.Vetting.ExemptHosts[0] != "*.openai.com" {
					t.Fatalf("lists not decoded: %+v %+v", s.TL, s.Vetting)
				}
			},
		},
		{name: "unknown field rejected", yaml: "auth: {gateway_isuer: x}", wantErr: true},
		{name: "malformed", yaml: "auth: [", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var s sample
			err := Parse([]byte(tt.yaml), &s)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want != nil {
				tt.want(t, s)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("tls: {cert_file: c, key_file: k}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var s sample
	if err := Load(path, &s); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.TLS.CertFile != "c" {
		t.Fatalf("Load() decoded %+v", s.TLS)
	}
	if err := Load(filepath.Join(dir, "missing.yaml"), &s); err == nil {
		t.Fatal("Load() = nil for a missing file")
	}
}
