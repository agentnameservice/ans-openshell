package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/interceptor"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

func TestServiceConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     fileConfig
		want    interceptor.Config
		wantErr string
	}{
		{
			name: "defaults to observe",
			cfg:  fileConfig{Auth: config.Auth{Audience: "aud"}},
			want: interceptor.Config{Audience: "aud", Mode: vetting.ModeObserve, ImplementationVersion: version},
		},
		{
			name: "require_registered with lookup wait",
			cfg:  fileConfig{DestinationPolicy: "require_registered", LookupWait: 250 * time.Millisecond},
			want: interceptor.Config{Mode: vetting.ModeRequire, LookupWait: 250 * time.Millisecond, ImplementationVersion: version},
		},
		{name: "off", cfg: fileConfig{DestinationPolicy: "off"}, want: interceptor.Config{Mode: vetting.ModeOff, ImplementationVersion: version}},
		{name: "unknown policy", cfg: fileConfig{DestinationPolicy: "maybe"}, wantErr: "destination_policy"},
		{name: "request_budget belongs to the middleware", cfg: fileConfig{Vetting: config.Vetting{RequestBudget: time.Second}}, wantErr: "request_budget"},
		{name: "negative lookup wait", cfg: fileConfig{LookupWait: -time.Second}, wantErr: "lookup_wait"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := serviceConfig(tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("serviceConfig() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("serviceConfig() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("serviceConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

type fakeKeys struct{ ready bool }

func (f *fakeKeys) Ready() bool { return f.ready }

func TestReadinessProbe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		states    []bool
		wantLogs  int
		wantLevel string
	}{
		{name: "no gateway key", states: []bool{false}, wantLogs: 1, wantLevel: "WARN"},
		{name: "key held", states: []bool{true}, wantLogs: 1, wantLevel: "INFO"},
		{name: "unchanged state is logged once", states: []bool{true, true}, wantLogs: 1, wantLevel: "INFO"},
		{name: "loss then recovery", states: []bool{true, false, true}, wantLogs: 3, wantLevel: "INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			keys := &fakeKeys{}
			probe := readinessProbe(t.Context(), keys, slog.New(slog.NewTextHandler(&logs, nil)))
			for i, st := range tt.states {
				keys.ready = st
				if got := probe(); got != st {
					t.Fatalf("probe() #%d = %v, want %v", i+1, got, st)
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
	cfg := fileConfig{
		Listen:       "127.0.0.1:0",
		HealthListen: "127.0.0.1:0",
		Auth: config.Auth{GatewayIssuer: "openshell-gateway:test", Audience: "urn:openshell:extension:interceptor:ans",
			JWKSURL: "https://127.0.0.1:1/.well-known/jwks.json"},
		Vetting: config.Vetting{TrustedTLDomains: []string{"tl.example.com"}},
	}
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
	if out := logs.String(); !strings.Contains(out, "readiness evaluated") || !strings.Contains(out, "ready=false") {
		t.Fatalf("readiness was not evaluated as not ready:\n%s", out)
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
