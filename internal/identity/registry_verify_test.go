package identity

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

func TestNewRegistryRejectsInvalidStaticReceipts(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	dir := t.TempDir()
	key, cert := writeIdentityFiles(t, dir, "id", id)
	token := writeFile(t, filepath.Join(dir, "status.cose"), tl.FreshStatusToken(id))
	for _, tt := range []struct {
		name    string
		receipt []byte
		wantErr bool
	}{
		{name: "valid", receipt: tl.Receipt(id.AgentID, id.AnsName)},
		{name: "malformed", receipt: []byte("bad COSE"), wantErr: true},
		{name: "wrong agent", receipt: tl.Receipt("other", id.AnsName), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file := writeFile(t, filepath.Join(t.TempDir(), "receipt.cose"), tt.receipt)
			cfg := Config{AnsName: id.AnsName, AgentID: id.AgentID, KeyFile: key, CertFile: cert, ReceiptFile: file, StatusTokenFile: token}
			r, err := NewRegistry(t.Context(), map[string]Config{"id": cfg}, config.TransparencyLog{RootKeys: []string{tl.RootKeyC2SP()}}, nil)
			if r != nil {
				defer r.Close()
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewRegistry()=%v wantErr=%v", err, tt.wantErr)
			}
			if err == nil {
				loaded, _ := r.Identity("id")
				source, ok := loaded.Artifacts().(*certificateSource)
				if !ok {
					t.Fatalf("source=%T, want certificate validity bound", loaded.Artifacts())
				}
				source.now = func() time.Time { return source.cert.NotAfter.Add(time.Second) }
				if r.Healthy() || loaded.Artifacts().Current().complete() {
					t.Fatal("expired identity remains usable")
				}
			}
		})
	}
}

func TestNewRegistryRefreshesPublishedKey(t *testing.T) {
	t.Parallel()
	oldTL, newTL := testfixtures.MustNewTL(), testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	srv := testfixtures.FakeTLServer(newTL, id)
	t.Cleanup(srv.Close)
	key, cert := writeIdentityFiles(t, t.TempDir(), "id", id)
	cfg := Config{AnsName: id.AnsName, AgentID: id.AgentID, KeyFile: key, CertFile: cert}
	r, err := NewRegistry(t.Context(), map[string]Config{"id": cfg}, config.TransparencyLog{
		BaseURL: srv.URL, RootKeys: []string{oldTL.RootKeyC2SP()}, AllowInsecureTransport: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.Healthy() {
		t.Fatal("identity unhealthy after refreshing the published signing key")
	}
}

// TestNewRegistryVerifiesArtifacts covers the startup binding between the
// configured certificate and the status token the log (or a pinned file)
// vouches with, for both artifact sources.
func TestNewRegistryVerifiesArtifacts(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	otherKey := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	now := time.Now()
	expiredCert, err := testfixtures.NewIdentityValid(testAgentID, testAnsName, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv := testfixtures.FakeTLServer(tl, id, expiredCert)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	keyFile, certFile := writeIdentityFiles(t, dir, "id", id)
	otherKeyFile, otherCertFile := writeIdentityFiles(t, dir, "other", otherKey)
	expiredKeyFile, expiredCertFile := writeIdentityFiles(t, dir, "expired", expiredCert)
	receiptFile := writeFile(t, filepath.Join(dir, "receipt.cose"), tl.Receipt(id.AgentID, id.AnsName))
	freshToken := writeFile(t, filepath.Join(dir, "fresh.cose"), tl.FreshStatusToken(id))
	otherToken := writeFile(t, filepath.Join(dir, "other.cose"), tl.FreshStatusToken(otherKey))
	expiredToken := writeFile(t, filepath.Join(dir, "expired.cose"), tl.StatusToken(id.AgentID, id.AnsName, scitt.StatusActive,
		now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix(), id.Fingerprint))
	wrongAgentToken := writeFile(t, filepath.Join(dir, "wrong-agent.cose"), tl.StatusToken("someone-else", id.AnsName, scitt.StatusActive,
		now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), id.Fingerprint))
	wrongNameToken := writeFile(t, filepath.Join(dir, "wrong-name.cose"), tl.StatusToken(id.AgentID, "ans://v9.0.0.other.example.com",
		scitt.StatusActive, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), id.Fingerprint))
	rootKeysFile := writeFile(t, filepath.Join(dir, "root-keys.txt"), []byte("# fixture log\n"+tl.RootKeyC2SP()+"\n\n# end\n"))
	tlCfg := config.TransparencyLog{BaseURL: srv.URL, RootKeysFile: rootKeysFile, AllowInsecureTransport: true}
	base := Config{AnsName: testAnsName, AgentID: id.AgentID, KeyFile: keyFile, CertFile: certFile}
	static := func(token string) Config {
		c := base
		c.ReceiptFile, c.StatusTokenFile = receiptFile, token
		return c
	}

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{name: "static fresh token", cfg: static(freshToken)},
		{name: "static token for another certificate", cfg: static(otherToken), wantErr: "does not vouch"},
		{name: "static expired token", cfg: static(expiredToken), wantErr: "status token"},
		{name: "static token for another agent", cfg: static(wrongAgentToken), wantErr: "names agent"},
		{name: "static token for another name", cfg: static(wrongNameToken), wantErr: "configured ans_name"},
		{name: "log vouches for a different key", cfg: Config{AnsName: testAnsName, AgentID: id.AgentID, KeyFile: otherKeyFile, CertFile: otherCertFile},
			wantErr: "does not vouch"},
		{name: "certificate outside validity", cfg: Config{AnsName: testAnsName, AgentID: expiredCert.AgentID, KeyFile: expiredKeyFile, CertFile: expiredCertFile},
			wantErr: "validity period"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			reg, err := NewRegistry(ctx, map[string]Config{"id": tt.cfg}, tlCfg, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewRegistry() error = %v", err)
				}
				defer reg.Close()
				if !reg.Healthy() {
					t.Fatal("Healthy() = false")
				}
				return
			}
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
