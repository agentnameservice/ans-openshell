package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/middleware"
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
			cfg := loadStartupConfig(t, tt.approval, "  allow_insecure_no_auth: true", "")
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

// loadStartupConfig writes a complete middleware configuration with one static
// identity; auth is the indented body of the auth block.
func loadStartupConfig(t *testing.T, approval, auth, healthListen string) fileConfig {
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
health_listen: %q
auth:
%s
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
`, healthListen, auth, filepath.Join(dir, "roots.txt"), id.AnsName, id.AgentID,
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

func TestServiceConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  fileConfig
		want middleware.Config
	}{
		{
			name: "vetting budget propagates",
			cfg: fileConfig{Auth: config.Auth{Audience: "aud"}, MaxPayloadBytes: 1024, RequestTimeout: time.Second,
				Vetting: &config.Vetting{RequestBudget: 150 * time.Millisecond}},
			want: middleware.Config{Audience: "aud", MaxPayloadBytes: 1024, RequestTimeout: time.Second,
				ImplementationVersion: version, VettingBudget: 150 * time.Millisecond, RequireAuthenticatedCaller: true},
		},
		{
			name: "no vetting block",
			cfg:  fileConfig{Auth: config.Auth{Audience: "aud"}},
			want: middleware.Config{Audience: "aud", ImplementationVersion: version, RequireAuthenticatedCaller: true},
		},
		{
			name: "insecure local mode does not require an authenticated caller",
			cfg:  fileConfig{Auth: config.Auth{AllowInsecureNoAuth: true}},
			want: middleware.Config{ImplementationVersion: version},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := serviceConfig(tt.cfg); got != tt.want {
				t.Fatalf("serviceConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

type fakeHealth struct {
	ready     bool
	names     []string
	unhealthy []string
}

func (f *fakeHealth) Ready() bool         { return f.ready }
func (f *fakeHealth) Names() []string     { return f.names }
func (f *fakeHealth) Unhealthy() []string { return f.unhealthy }

func TestReadinessProbe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		states    []fakeHealth
		want      []bool
		wantLogs  int
		wantLevel string
	}{
		{name: "no gateway key with healthy identities", states: []fakeHealth{{names: []string{"a"}}}, want: []bool{false}, wantLogs: 1, wantLevel: "WARN"},
		{name: "key held and identities healthy", states: []fakeHealth{{ready: true, names: []string{"a"}}}, want: []bool{true}, wantLogs: 1, wantLevel: "INFO"},
		{name: "one unhealthy identity of two stays ready", states: []fakeHealth{{ready: true, names: []string{"a", "b"}, unhealthy: []string{"b"}}}, want: []bool{true}, wantLogs: 1, wantLevel: "WARN"},
		{name: "every identity unhealthy", states: []fakeHealth{{ready: true, names: []string{"a"}, unhealthy: []string{"a"}}}, want: []bool{false}, wantLogs: 1, wantLevel: "WARN"},
		{name: "unchanged state is logged once", states: []fakeHealth{{names: []string{"a"}}, {names: []string{"a"}}}, want: []bool{false, false}, wantLogs: 1, wantLevel: "WARN"},
		{name: "recovery is applied and logged", states: []fakeHealth{{names: []string{"a"}}, {ready: true, names: []string{"a"}}}, want: []bool{false, true}, wantLogs: 2, wantLevel: "INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			src := &fakeHealth{}
			probe := readinessProbe(t.Context(), src, src, slog.New(slog.NewTextHandler(&logs, nil)))
			for i, st := range tt.states {
				*src = st
				if got := probe(); got != tt.want[i] {
					t.Fatalf("probe() #%d = %v, want %v", i+1, got, tt.want[i])
				}
			}
			if n := strings.Count(logs.String(), "readiness evaluated"); n != tt.wantLogs {
				t.Fatalf("logged %d readiness evaluations, want %d:\n%s", n, tt.wantLogs, logs.String())
			}
			lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
			if last := lines[len(lines)-1]; !strings.Contains(last, "level="+tt.wantLevel) {
				t.Fatalf("last readiness log %q, want level %s", last, tt.wantLevel)
			}
		})
	}
}

func TestServeNotReadyWithoutGatewayKeys(t *testing.T) {
	t.Parallel()
	cfg := loadStartupConfig(t, "{sb-1: test-agent}",
		"  gateway_issuer: openshell-gateway:test\n  audience: urn:openshell:extension:middleware:ans\n  jwks_url: https://127.0.0.1:1/.well-known/jwks.json",
		"127.0.0.1:0")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	logs := newHealthLogWatcher()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, slog.New(slog.NewTextHandler(logs, nil))) }()
	if code := readyzStatus(ctx, t, logs); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz without gateway keys = %d, want 503", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve() error = %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "readiness evaluated") || !strings.Contains(out, "gateway_keys=false") {
		t.Fatalf("readiness was not evaluated as lacking gateway keys:\n%s", out)
	}
}

// healthLogWatcher captures the service log and reports the health listener's
// bound address once grpcserver logs it.
type healthLogWatcher struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	addr chan string
	once sync.Once
}

func newHealthLogWatcher() *healthLogWatcher { return &healthLogWatcher{addr: make(chan string, 1)} }

func (w *healthLogWatcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	const marker = `msg="health endpoints listening" addr=`
	if i := bytes.Index(p, []byte(marker)); i >= 0 {
		rest := p[i+len(marker):]
		if end := bytes.IndexAny(rest, " \n"); end >= 0 {
			rest = rest[:end]
		}
		w.once.Do(func() { w.addr <- string(rest) })
	}
	return len(p), nil
}

func (w *healthLogWatcher) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// readyzStatus waits for the health listener to be announced and returns the
// first /readyz status it answers with.
func readyzStatus(ctx context.Context, t *testing.T, logs *healthLogWatcher) int {
	t.Helper()
	var addr string
	select {
	case addr = <-logs.addr:
	case <-ctx.Done():
		t.Fatalf("health listener was never announced:\n%s", logs.String())
	}
	for range 50 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET /readyz on %s never answered", addr)
	return 0
}
