package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

func TestServeSandboxApprovals(t *testing.T) {
	t.Parallel()
	const startupTimeout = 10 * time.Second
	for _, tt := range []struct {
		name     string
		approval string
		want     map[string]string
		wantErr  string
	}{
		{name: "approved sandbox", approval: "{sb-1: test-agent}", want: map[string]string{"sb-1": "test-agent"}},
		{name: "empty approvals", approval: "{}", want: map[string]string{}},
		{name: "unknown identity", approval: "{sb-1: unknown}", want: map[string]string{"sb-1": "unknown"}, wantErr: "sandbox_identities: sandbox \"sb-1\" names unknown identity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := loadStartupConfig(t, tt.approval)
			if !maps.Equal(cfg.SandboxIdentities, tt.want) {
				t.Fatalf("loaded sandbox approvals = %v, want %v", cfg.SandboxIdentities, tt.want)
			}
			if tt.wantErr != "" {
				cfg.Listen = "not-an-address"
			}
			ctx, cancel := context.WithTimeout(t.Context(), startupTimeout)
			defer cancel()
			logs := &startupLogWriter{cancel: cancel}
			err := serve(ctx, cfg, slog.New(slog.NewTextHandler(logs, nil)))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("serve() error = %v, want %q before listener validation", err, tt.wantErr)
				}
				if logs.started.Load() {
					t.Fatal("invalid approval reached server startup")
				}
				return
			}
			if err != nil || !logs.started.Load() {
				t.Fatalf("serve() = %v, started = %v", err, logs.started.Load())
			}
		})
	}
}

func loadStartupConfig(t *testing.T, approval string) fileConfig {
	t.Helper()
	dir := t.TempDir()
	id := testfixtures.MustNewIdentity("test-agent-id", "ans://v1.0.0.test.example")
	tl := testfixtures.MustNewTL()
	for name, content := range map[string][]byte{
		"key.pem":      id.KeyPEM,
		"cert.pem":     id.CertPEM,
		"receipt.cose": tl.Receipt(id.AgentID, id.AnsName),
		"status.cose":  tl.FreshStatusToken(id),
		"roots.txt":    []byte(tl.RootKeyC2SP()),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	yaml := fmt.Sprintf(`listen: "127.0.0.1:0"
auth:
  allow_insecure_no_auth: true
transparency_log:
  root_keys_file: %q
identities:
  test-agent:
    ans_name: %q
    agent_id: %q
    key_file: %q
    cert_file: %q
    receipt_file: %q
    status_token_file: %q
sandbox_identities: %s
`, filepath.Join(dir, "roots.txt"), id.AnsName, id.AgentID,
		filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "receipt.cose"), filepath.Join(dir, "status.cose"), approval)
	path := filepath.Join(dir, "middleware.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg fileConfig
	if err := config.Load(path, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

type startupLogWriter struct {
	cancel  context.CancelFunc
	started atomic.Bool
}

func (w *startupLogWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("ans-openshell-middleware starting")) {
		w.started.Store(true)
		w.cancel()
	}
	return len(p), nil
}
