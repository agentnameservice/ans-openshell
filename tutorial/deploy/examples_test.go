package deploy

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	tutorialcfg "github.com/agentnameservice/ans-openshell/tutorial/config"
)

// examplesDir is the path to the demo example configs, which live in the core
// repo's deploy/examples directory (this test lives in the tutorial module).
const examplesDir = "../../deploy/examples/"

// middlewareFile mirrors the demo binary's fileConfig (cmd/ans-demo-middleware):
// the generic middleware config plus the tutorial commerce block.
type middlewareFile struct {
	Listen            string                     `yaml:"listen"`
	HealthListen      string                     `yaml:"health_listen"`
	TLS               config.TLS                 `yaml:"tls"`
	Auth              config.Auth                `yaml:"auth"`
	TransparencyLog   config.TransparencyLog     `yaml:"transparency_log"`
	Identities        map[string]identity.Config `yaml:"identities"`
	SandboxIdentities map[string]string          `yaml:"sandbox_identities"`
	Vetting           *config.Vetting            `yaml:"vetting"`
	MaxPayloadBytes   uint64                     `yaml:"max_payload_bytes"`
	RequestTimeout    time.Duration              `yaml:"request_timeout"`
	Commerce          tutorialcfg.Commerce       `yaml:"commerce"`
}

// loadMiddlewareFile loads a middleware YAML config into the mirror struct.
func loadMiddlewareFile(t *testing.T, path string) middlewareFile {
	t.Helper()
	var cfg middlewareFile
	if err := config.Load(path, &cfg); err != nil {
		t.Fatalf("failed to load %s: %v", path, err)
	}
	return cfg
}

func TestExampleConfig_AgentA(t *testing.T) {
	cfg := loadMiddlewareFile(t, examplesDir+"middleware-agent-a.yaml")

	if cfg.Listen != ":50051" {
		t.Errorf("Listen = %q, want :50051", cfg.Listen)
	}

	if cfg.MaxPayloadBytes != 262144 {
		t.Errorf("MaxPayloadBytes = %d, want 262144", cfg.MaxPayloadBytes)
	}

	if len(cfg.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(cfg.Identities))
	}

	var ident identity.Config
	for _, id := range cfg.Identities {
		ident = id
		break
	}

	if ident.DevMode {
		t.Errorf("identity DevMode = true, want false")
	}

	if !strings.Contains(ident.KeyFile, "/.secrets/") {
		t.Errorf("identity KeyFile = %q, want path containing /.secrets/", ident.KeyFile)
	}

	if !strings.Contains(ident.CertFile, "/.secrets/") {
		t.Errorf("identity CertFile = %q, want path containing /.secrets/", ident.CertFile)
	}

	if cfg.Commerce.CommerceDPoPKeyPath == "" {
		t.Error("Commerce.CommerceDPoPKeyPath is empty, want configured")
	}

	wantSellerURL := "https://seller.skybound-travel.com/mcp/"
	if cfg.Commerce.SellerMCPURL != wantSellerURL {
		t.Errorf("Commerce.SellerMCPURL = %q, want %q (exact, with trailing slash)", cfg.Commerce.SellerMCPURL, wantSellerURL)
	}

	if cfg.Commerce.SellerANS == "" {
		t.Error("Commerce.SellerANS is empty, want configured")
	}

	if cfg.Commerce.AuthorityANS == "" {
		t.Error("Commerce.AuthorityANS is empty, want configured")
	}
}

func TestExampleConfig_AgentB(t *testing.T) {
	cfg := loadMiddlewareFile(t, examplesDir+"middleware-agent-b.yaml")

	if cfg.Listen != ":50052" {
		t.Errorf("Listen = %q, want :50052", cfg.Listen)
	}

	if cfg.MaxPayloadBytes != 262144 {
		t.Errorf("MaxPayloadBytes = %d, want 262144", cfg.MaxPayloadBytes)
	}

	if len(cfg.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(cfg.Identities))
	}

	var ident identity.Config
	for _, id := range cfg.Identities {
		ident = id
		break
	}

	if !ident.DevMode {
		t.Errorf("identity DevMode = false, want true")
	}

	wantANS := "ans://v9.9.9.rogue.example"
	if ident.AnsName != wantANS {
		t.Errorf("identity AnsName = %q, want %q", ident.AnsName, wantANS)
	}

	if cfg.Commerce.SellerMCPURL != "" {
		t.Errorf("Commerce.SellerMCPURL = %q, want empty (no commerce)", cfg.Commerce.SellerMCPURL)
	}

	if cfg.Commerce.CommerceDPoPKeyPath != "" {
		t.Errorf("Commerce.CommerceDPoPKeyPath = %q, want empty (no commerce)", cfg.Commerce.CommerceDPoPKeyPath)
	}
}

func TestDemoWiring_NamesAndHostsAgree(t *testing.T) {
	// Parse the two sandbox policies
	policyA := loadPolicyFile(t, examplesDir+"policy-a.yaml")
	policyB := loadPolicyFile(t, examplesDir+"policy-b.yaml")

	// Parse the Tier 2 gateway registration
	gatewayMiddlewares := loadGatewayTier2(t, examplesDir+"gateway-tier2.toml")

	// (G2) Check that policy-a network_middlewares key AND its .middleware value == "ans-egress-a"
	// and that it matches a gateway middleware name
	checkPolicyMiddlewareName(t, policyA, "ans-egress-a", gatewayMiddlewares)

	// (G2) Same for policy-b with "ans-egress-b"
	checkPolicyMiddlewareName(t, policyB, "ans-egress-b", gatewayMiddlewares)

	// (G3) Check that every gateway supervisor-middleware entry has max_payload_bytes == 262144
	for _, mw := range gatewayMiddlewares {
		if mw.MaxPayloadBytes != 262144 {
			t.Errorf("gateway middleware %q has MaxPayloadBytes = %d, want 262144", mw.Name, mw.MaxPayloadBytes)
		}
	}

	// (G6) Check that policy endpoint hosts and gateway grpc_endpoint contain "<HOST_IP>"
	// and NEVER contain "127.0.0.1" or "host.docker.internal"
	checkHostPlaceholder(t, policyA, "policy-a")
	checkHostPlaceholder(t, policyB, "policy-b")
	for _, mw := range gatewayMiddlewares {
		if !strings.Contains(mw.GRPCEndpoint, "<HOST_IP>") {
			t.Errorf("gateway middleware %q grpc_endpoint = %q, want to contain <HOST_IP>", mw.Name, mw.GRPCEndpoint)
		}
		if strings.Contains(mw.GRPCEndpoint, "127.0.0.1") || strings.Contains(mw.GRPCEndpoint, "host.docker.internal") {
			t.Errorf("gateway middleware %q grpc_endpoint = %q, must not contain 127.0.0.1 or host.docker.internal", mw.Name, mw.GRPCEndpoint)
		}
	}

	// (G9) Check that each policy has version, filesystem_policy, landlock, and a network policy with name+endpoints+binaries
	checkPolicyStructure(t, policyA, "policy-a")
	checkPolicyStructure(t, policyB, "policy-b")

	// (G1) Check that policy-a routes to the ingress host:50060 (the ingress bind), NOT directly to the seller
	checkIngressPort(t, policyA, "policy-a", 50060)
	checkIngressPort(t, policyB, "policy-b", 50060)
}

// policyFile represents the sandbox policy YAML structure
type policyFile struct {
	Version            int                               `yaml:"version"`
	FilesystemPolicy   *filesystemPolicy                 `yaml:"filesystem_policy"`
	Landlock           *landlockConfig                   `yaml:"landlock"`
	NetworkPolicies    map[string]networkPolicy          `yaml:"network_policies"`
	NetworkMiddlewares map[string]networkMiddlewareEntry `yaml:"network_middlewares"`
}

type filesystemPolicy struct {
	IncludeWorkdir bool     `yaml:"include_workdir"`
	ReadOnly       []string `yaml:"read_only"`
	ReadWrite      []string `yaml:"read_write"`
}

type landlockConfig struct {
	Compatibility string `yaml:"compatibility"`
}

type networkPolicy struct {
	Name      string            `yaml:"name"`
	Endpoints []networkEndpoint `yaml:"endpoints"`
	Binaries  []binaryEntry     `yaml:"binaries"`
}

type networkEndpoint struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Protocol    string `yaml:"protocol"`
	Enforcement string `yaml:"enforcement"`
	Access      string `yaml:"access"`
}

type binaryEntry struct {
	Path string `yaml:"path"`
}

type networkMiddlewareEntry struct {
	Name       string           `yaml:"name"`
	Middleware string           `yaml:"middleware"`
	Order      int              `yaml:"order"`
	Config     map[string]any   `yaml:"config"`
	OnError    string           `yaml:"on_error"`
	Endpoints  middlewareEndpts `yaml:"endpoints"`
}

type middlewareEndpts struct {
	Include []string `yaml:"include"`
}

// gatewayMiddleware represents a gateway supervisor middleware entry
type gatewayMiddleware struct {
	Name            string `json:"name"`
	GRPCEndpoint    string `json:"grpc_endpoint"`
	MaxPayloadBytes int    `json:"max_payload_bytes"`
}

func loadPolicyFile(t *testing.T, path string) policyFile {
	t.Helper()
	var policy policyFile
	if err := config.Load(path, &policy); err != nil {
		t.Fatalf("failed to load %s: %v", path, err)
	}
	return policy
}

func loadGatewayTier2(t *testing.T, path string) []gatewayMiddleware {
	t.Helper()
	// Use Python tomllib to parse the gateway TOML, similar to deployment_test.go
	const parse = `import json, sys, tomllib
with open(sys.argv[1], "rb") as source:
    json.dump(tomllib.load(source)["openshell"]["supervisor"]["middleware"], sys.stdout)
`
	data, err := exec.CommandContext(t.Context(), "python3", "-c", parse, path).CombinedOutput()
	if err != nil {
		t.Fatalf("parse gateway TOML with Python 3.11+: %v\n%s", err, data)
	}
	var middlewares []gatewayMiddleware
	if err := json.Unmarshal(data, &middlewares); err != nil {
		t.Fatalf("unmarshal gateway middlewares: %v", err)
	}
	return middlewares
}

func checkPolicyMiddlewareName(t *testing.T, policy policyFile, expectedName string, gatewayMiddlewares []gatewayMiddleware) {
	t.Helper()

	// Check that the network_middlewares map has the expected key
	mw, ok := policy.NetworkMiddlewares[expectedName]
	if !ok {
		t.Errorf("policy network_middlewares missing key %q", expectedName)
		return
	}

	// Check that the middleware name field matches
	if mw.Name != expectedName {
		t.Errorf("policy network_middleware name = %q, want %q", mw.Name, expectedName)
	}

	// Check that the middleware field matches
	if mw.Middleware != expectedName {
		t.Errorf("policy network_middleware middleware = %q, want %q", mw.Middleware, expectedName)
	}

	// Check that a gateway middleware with this name exists
	found := false
	for _, gmw := range gatewayMiddlewares {
		if gmw.Name == expectedName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("gateway middlewares missing entry with name %q", expectedName)
	}
}

func checkHostPlaceholder(t *testing.T, policy policyFile, policyName string) {
	t.Helper()

	// Check network policy endpoints
	for _, np := range policy.NetworkPolicies {
		for _, ep := range np.Endpoints {
			if !strings.Contains(ep.Host, "<HOST_IP>") {
				t.Errorf("%s network endpoint host = %q, want to contain <HOST_IP>", policyName, ep.Host)
			}
			if strings.Contains(ep.Host, "127.0.0.1") || strings.Contains(ep.Host, "host.docker.internal") {
				t.Errorf("%s network endpoint host = %q, must not contain 127.0.0.1 or host.docker.internal", policyName, ep.Host)
			}
		}
	}

	// Check network middleware endpoints
	for _, mw := range policy.NetworkMiddlewares {
		for _, host := range mw.Endpoints.Include {
			if !strings.Contains(host, "<HOST_IP>") {
				t.Errorf("%s network middleware endpoint = %q, want to contain <HOST_IP>", policyName, host)
			}
			if strings.Contains(host, "127.0.0.1") || strings.Contains(host, "host.docker.internal") {
				t.Errorf("%s network middleware endpoint = %q, must not contain 127.0.0.1 or host.docker.internal", policyName, host)
			}
		}
	}
}

func checkPolicyStructure(t *testing.T, policy policyFile, policyName string) {
	t.Helper()

	// Check version exists and is non-zero
	if policy.Version == 0 {
		t.Errorf("%s missing version field", policyName)
	}

	// Check filesystem_policy exists
	if policy.FilesystemPolicy == nil {
		t.Errorf("%s missing filesystem_policy", policyName)
	}

	// Check landlock exists
	if policy.Landlock == nil {
		t.Errorf("%s missing landlock", policyName)
	}

	// Check that at least one network policy exists with name, endpoints, and binaries
	if len(policy.NetworkPolicies) == 0 {
		t.Errorf("%s missing network_policies", policyName)
		return
	}

	for key, np := range policy.NetworkPolicies {
		if np.Name == "" {
			t.Errorf("%s network_policies[%q] missing name", policyName, key)
		}
		if len(np.Endpoints) == 0 {
			t.Errorf("%s network_policies[%q] missing endpoints", policyName, key)
		}
		if len(np.Binaries) == 0 {
			t.Errorf("%s network_policies[%q] missing binaries", policyName, key)
		}
	}
}

func checkIngressPort(t *testing.T, policy policyFile, policyName string, expectedPort int) {
	t.Helper()

	// Look for the ingress network policy
	ingress, ok := policy.NetworkPolicies["ingress"]
	if !ok {
		t.Errorf("%s missing 'ingress' network policy", policyName)
		return
	}

	// Check that at least one endpoint has the expected port
	foundPort := false
	for _, ep := range ingress.Endpoints {
		if ep.Port == expectedPort {
			foundPort = true
			break
		}
	}

	if !foundPort {
		t.Errorf("%s ingress policy does not have an endpoint on port %d", policyName, expectedPort)
	}
}
