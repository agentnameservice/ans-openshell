package identity

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

// writeIdentityFiles writes id's key and certificate PEMs into dir.
func writeIdentityFiles(t *testing.T, dir, name string, id *testfixtures.Identity) (string, string) {
	t.Helper()
	keyFile := filepath.Join(dir, name+"-key.pem")
	certFile := filepath.Join(dir, name+"-cert.pem")
	if err := os.WriteFile(keyFile, id.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, id.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, certFile
}

func writeFile(t *testing.T, path string, b []byte) string {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type stubSigner struct{}

func (stubSigner) Sign(context.Context, string, string, [32]byte) (string, error) {
	return "proof", nil
}

func TestNewIdentityValidation(t *testing.T) {
	t.Parallel()
	src := NewStaticSource(Artifacts{ReceiptBase64: "r", StatusTokenBase64: "t"})
	tests := []struct {
		name      string
		idName    string
		ansName   string
		agentID   string
		signer    Signer
		artifacts ArtifactSource
		wantErr   string
	}{
		{name: "ok", idName: "a", ansName: testAnsName, agentID: testAgentID, signer: stubSigner{}, artifacts: src},
		{name: "empty name", ansName: testAnsName, agentID: testAgentID, signer: stubSigner{}, artifacts: src, wantErr: "name"},
		{name: "bad ans name", idName: "a", ansName: "https://example.com", agentID: testAgentID, signer: stubSigner{}, artifacts: src, wantErr: "ans_name"},
		{name: "empty agent id", idName: "a", ansName: testAnsName, signer: stubSigner{}, artifacts: src, wantErr: "agent_id"},
		{name: "nil signer", idName: "a", ansName: testAnsName, agentID: testAgentID, artifacts: src, wantErr: "signer"},
		{name: "nil artifacts", idName: "a", ansName: testAnsName, agentID: testAgentID, signer: stubSigner{}, wantErr: "artifact source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, err := NewIdentity(tt.idName, tt.ansName, tt.agentID, tt.signer, tt.artifacts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewIdentity() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewIdentity() error = %v", err)
			}
			if id.Name() != tt.idName || id.AnsName() != tt.ansName || id.AgentID() != tt.agentID ||
				id.Signer() != tt.signer || id.Artifacts() != tt.artifacts {
				t.Fatalf("accessors do not return the constructor arguments: %+v", id)
			}
		})
	}
}

func TestNewRegistryFromIdentities(t *testing.T) {
	t.Parallel()
	src := NewStaticSource(Artifacts{ReceiptBase64: "r", StatusTokenBase64: "t"})
	a, err := NewIdentity("a", testAnsName, testAgentID, stubSigner{}, src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIdentity("b", testAnsName, "agent-b", stubSigner{}, NewStaticSource(Artifacts{}))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistryFromIdentities(b, a)
	if err != nil {
		t.Fatalf("NewRegistryFromIdentities: %v", err)
	}
	defer reg.Close()
	if got := reg.Names(); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("Names() = %v", got)
	}
	if got, ok := reg.Identity("a"); !ok || got != a {
		t.Fatalf("Identity(a) = %v, %v", got, ok)
	}
	if _, ok := reg.Identity("zzz"); ok {
		t.Fatal("Identity(zzz) found")
	}
	if reg.Healthy() {
		t.Fatal("Healthy() = true with an identity lacking artifacts")
	}
	if _, err := NewRegistryFromIdentities(a, a); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	if _, err := NewRegistryFromIdentities(a, nil); err == nil {
		t.Fatal("nil identity accepted")
	}
	reg.Close()
}

func TestNewRegistryFromTransparencyLog(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	payments := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	search := testfixtures.MustNewIdentity("agent-search", "ans://v2.1.0.search.example.com")
	pinned := testfixtures.MustNewIdentity("agent-pinned", "ans://v1.0.0.pinned.example.com")
	srv := testfixtures.FakeTLServer(tl, payments, search)
	defer srv.Close()

	dir := t.TempDir()
	payKey, payCert := writeIdentityFiles(t, dir, "payments", payments)
	searchKey, searchCert := writeIdentityFiles(t, dir, "search", search)
	pinnedKey, pinnedCert := writeIdentityFiles(t, dir, "pinned", pinned)
	receiptFile := writeFile(t, filepath.Join(dir, "receipt.cose"), tl.Receipt(pinned.AgentID, pinned.AnsName))
	tokenFile := writeFile(t, filepath.Join(dir, "token.cose"), tl.FreshStatusToken(pinned))
	rootKeysFile := writeFile(t, filepath.Join(dir, "root-keys.txt"), []byte("\n  "+tl.RootKeyC2SP()+"  \n\n"))

	identities := map[string]Config{
		"payments-agent": {AnsName: testAnsName, AgentID: payments.AgentID, KeyFile: payKey, CertFile: payCert},
		"search-agent":   {AnsName: search.AnsName, AgentID: search.AgentID, KeyFile: searchKey, CertFile: searchCert},
		"pinned-agent": {AnsName: pinned.AnsName, AgentID: pinned.AgentID, KeyFile: pinnedKey, CertFile: pinnedCert,
			ReceiptFile: receiptFile, StatusTokenFile: tokenFile},
	}
	tlCfg := config.TransparencyLog{BaseURL: srv.URL, RootKeysFile: rootKeysFile, AllowInsecureTransport: true}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	reg, err := NewRegistry(t.Context(), identities, tlCfg, logger)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()
	if got := reg.Names(); !slices.Equal(got, []string{"payments-agent", "pinned-agent", "search-agent"}) {
		t.Fatalf("Names() = %v", got)
	}
	if !reg.Healthy() {
		t.Fatal("Healthy() = false")
	}
	for _, name := range reg.Names() {
		id, ok := reg.Identity(name)
		if !ok {
			t.Fatalf("Identity(%q) missing", name)
		}
		arts := id.Artifacts().Current()
		if arts.ReceiptBase64 == "" || arts.StatusTokenBase64 == "" {
			t.Fatalf("%s: artifacts = %+v", name, arts)
		}
		if _, err := id.Signer().Sign(t.Context(), "GET", "https://tools.example.com/", [32]byte{}); err != nil {
			t.Fatalf("%s: Sign: %v", name, err)
		}
	}
	if id, _ := reg.Identity("payments-agent"); id.AnsName() != testAnsName || id.AgentID() != payments.AgentID {
		t.Fatalf("payments-agent = %s %s", id.AnsName(), id.AgentID())
	}
	reg.Close()
}

func TestNewRegistryFailsClosed(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	unregistered := testfixtures.MustNewIdentity("agent-unregistered", "ans://v1.0.0.ghost.example.com")
	noSAN := testfixtures.MustNewIdentity("agent-nosan", "https://not-an-ans-name.example.com/")
	otherVersion := testfixtures.MustNewIdentity(testAgentID, "ans://v2.0.0.payments.example.com")
	srv := testfixtures.FakeTLServer(tl, id)
	t.Cleanup(srv.Close)
	down := testfixtures.FakeTLServer(tl, id)
	down.Close()

	dir := t.TempDir()
	keyFile, certFile := writeIdentityFiles(t, dir, "id", id)
	_, unregCert := writeIdentityFiles(t, dir, "unreg", unregistered)
	noSANKey, noSANCert := writeIdentityFiles(t, dir, "nosan", noSAN)
	otherKey, otherCert := writeIdentityFiles(t, dir, "other", otherVersion)
	receiptFile := writeFile(t, filepath.Join(dir, "receipt.cose"), tl.Receipt(id.AgentID, id.AnsName))
	badKeyFile := writeFile(t, filepath.Join(dir, "bad-key.pem"), []byte("not a key"))
	missing := filepath.Join(dir, "missing")

	good := Config{AnsName: testAnsName, AgentID: id.AgentID, KeyFile: keyFile, CertFile: certFile}
	goodTL := config.TransparencyLog{BaseURL: srv.URL, RootKeys: []string{tl.RootKeyC2SP()}, AllowInsecureTransport: true}
	with := func(mod func(c *Config)) Config {
		c := good
		mod(&c)
		return c
	}

	tests := []struct {
		name    string
		cfg     Config
		tl      config.TransparencyLog
		wantErr string
	}{
		{name: "bad ans_name", cfg: with(func(c *Config) { c.AnsName = "payments.example.com" }), tl: goodTL, wantErr: "ans_name"},
		{name: "empty agent_id", cfg: with(func(c *Config) { c.AgentID = "" }), tl: goodTL, wantErr: "agent_id"},
		{name: "missing key file", cfg: with(func(c *Config) { c.KeyFile = missing }), tl: goodTL, wantErr: "read key_file"},
		{name: "missing cert file", cfg: with(func(c *Config) { c.CertFile = missing }), tl: goodTL, wantErr: "read cert_file"},
		{name: "unusable key", cfg: with(func(c *Config) { c.KeyFile = badKeyFile }), tl: goodTL, wantErr: "private key"},
		{name: "cert for another key", cfg: with(func(c *Config) { c.CertFile = unregCert }), tl: goodTL, wantErr: "signer"},
		{name: "cert without ans SAN", cfg: with(func(c *Config) { c.KeyFile, c.CertFile = noSANKey, noSANCert }), tl: goodTL,
			wantErr: "no ans:// URI SAN"},
		{name: "cert SAN version differs", cfg: with(func(c *Config) { c.KeyFile, c.CertFile = otherKey, otherCert }), tl: goodTL,
			wantErr: "does not match ans_name"},
		{name: "only receipt_file", cfg: with(func(c *Config) { c.ReceiptFile = receiptFile }), tl: goodTL, wantErr: "must both be set"},
		{name: "missing static token", cfg: with(func(c *Config) { c.ReceiptFile, c.StatusTokenFile = receiptFile, missing }), tl: goodTL,
			wantErr: "read status_token_file"},
		{name: "no base_url", cfg: good, tl: config.TransparencyLog{RootKeys: goodTL.RootKeys}, wantErr: "base_url"},
		{name: "no root keys", cfg: good, tl: config.TransparencyLog{BaseURL: srv.URL, AllowInsecureTransport: true}, wantErr: "root key"},
		{name: "unparseable root key", cfg: good, tl: config.TransparencyLog{BaseURL: srv.URL, RootKeys: []string{"junk"}, AllowInsecureTransport: true},
			wantErr: "root keys"},
		{name: "missing root_keys_file", cfg: good, tl: config.TransparencyLog{BaseURL: srv.URL, RootKeysFile: missing, AllowInsecureTransport: true},
			wantErr: "read root_keys_file"},
		{name: "http without insecure opt-in", cfg: good, tl: config.TransparencyLog{BaseURL: srv.URL, RootKeys: goodTL.RootKeys},
			wantErr: "https"},
		{name: "log does not know the agent", cfg: with(func(c *Config) { c.AgentID = "someone-else" }), tl: goodTL, wantErr: "fetch artifacts"},
		{name: "log unreachable", cfg: good, tl: config.TransparencyLog{BaseURL: down.URL, RootKeys: goodTL.RootKeys, AllowInsecureTransport: true},
			wantErr: "fetch artifacts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			reg, err := NewRegistry(ctx, map[string]Config{"id": tt.cfg}, tt.tl, nil)
			if err == nil {
				reg.Close()
				t.Fatal("NewRegistry() succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewRegistry() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewRegistryEmpty(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry(t.Context(), nil, config.TransparencyLog{}, nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()
	if len(reg.Names()) != 0 || !reg.Healthy() {
		t.Fatalf("empty registry: names %v healthy %v", reg.Names(), reg.Healthy())
	}
}
