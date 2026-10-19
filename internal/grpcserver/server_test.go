package grpcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

func TestNew_Errors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct {
		name string
		opts Options
	}{
		{name: "half tls", opts: Options{Listen: "127.0.0.1:0", TLS: config.TLS{CertFile: "c"}}},
		{name: "missing cert files", opts: Options{Listen: "127.0.0.1:0", TLS: config.TLS{CertFile: filepath.Join(dir, "no.crt"), KeyFile: filepath.Join(dir, "no.key")}}},
		{name: "bad address", opts: Options{Listen: "256.256.256.256:99999"}},
		{name: "bad health address", opts: Options{Listen: "127.0.0.1:0", HealthListen: "256.256.256.256:99999"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(context.Background(), tt.opts, nil); err == nil {
				t.Fatal("New() = nil error")
			}
		})
	}
}

func TestServe_PlaintextHealthAndShutdown(t *testing.T) {
	t.Parallel()
	var seen int
	count := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		seen++
		return h(ctx, req)
	}
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0", Unary: []grpc.UnaryServerInterceptor{count}, ShutdownGrace: time.Second}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	conn, err := grpc.NewClient(s.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hc := grpc_health_v1.NewHealthClient(conn)
	resp, err := hc.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, %v; want SERVING", resp.GetStatus(), err)
	}
	s.SetHealthy(false)
	resp, err = hc.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("health = %v, %v; want NOT_SERVING", resp.GetStatus(), err)
	}
	s.SetHealthy(true)
	if seen != 2 {
		t.Fatalf("interceptor saw %d calls, want 2", seen)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after cancel")
	}
	if _, err := hc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{}); status.Code(err) == codes.OK {
		t.Fatal("health check succeeded after shutdown")
	}
}

func TestServe_TLS(t *testing.T) {
	t.Parallel()
	tc := selfSigned(t)
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0", TLS: config.TLS{CertFile: tc.certFile, KeyFile: tc.keyFile}}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx) }()

	creds := credentials.NewTLS(&tls.Config{RootCAs: tc.pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	conn, err := grpc.NewClient(s.Addr().String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resp, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health over TLS = %v, %v", resp.GetStatus(), err)
	}
	plain, err := grpc.NewClient(s.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	shortCtx, shortCancel := context.WithTimeout(ctx, 2*time.Second)
	defer shortCancel()
	if _, err := grpc_health_v1.NewHealthClient(plain).Check(shortCtx, &grpc_health_v1.HealthCheckRequest{}); err == nil {
		t.Fatal("plaintext client reached a TLS server")
	}
}

func TestServe_ListenerFailure(t *testing.T) {
	t.Parallel()
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.lis.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("Serve() = nil on a closed listener")
	}
}

type testCert struct {
	certFile, keyFile string
	pool              *x509.CertPool
}

func selfSigned(t *testing.T) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(mustParse(t, der))
	return testCert{certFile: certFile, keyFile: keyFile, pool: pool}
}

func TestServe_ForcedStopAfterGrace(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	block := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		close(entered)
		<-release
		return h(ctx, req)
	}
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0", Unary: []grpc.UnaryServerInterceptor{block}, ShutdownGrace: 50 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	conn, err := grpc.NewClient(s.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	callErr := make(chan error, 1)
	go func() {
		_, err := grpc_health_v1.NewHealthClient(conn).Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
		callErr <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the blocking call never reached the server")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve() did not return: forced stop did not happen")
	}
	close(release)
	<-callErr
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServe_HealthEndpoints(t *testing.T) {
	t.Parallel()
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0", HealthListen: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	base := "http://" + s.HealthAddr().String()
	get := func(path string) int {
		t.Helper()
		var code int
		for range 50 {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				code = resp.StatusCode
				_ = resp.Body.Close()
				return code
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("GET %s never answered", path)
		return 0
	}
	if got := get("/healthz"); got != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", got)
	}
	if got := get("/readyz"); got != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200 while healthy", got)
	}
	s.SetHealthy(false)
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503 when unhealthy", got)
	}
	if got := get("/healthz"); got != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200 regardless of readiness", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/healthz", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("health listener still answering after shutdown")
	}
}

func TestHealthAddr_NilWithoutListener(t *testing.T) {
	t.Parallel()
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.lis.Close()
	if s.HealthAddr() != nil {
		t.Fatal("HealthAddr() != nil without HealthListen")
	}
}

func TestServe_DrainDelayReportsNotReadyFirst(t *testing.T) {
	t.Parallel()
	s, err := New(context.Background(), Options{Listen: "127.0.0.1:0", HealthListen: "127.0.0.1:0", DrainDelay: 300 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	base := "http://" + s.HealthAddr().String()
	for range 50 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/readyz", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	started := time.Now()
	cancel()
	time.Sleep(50 * time.Millisecond)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/readyz", nil)
	resp, getErr := http.DefaultClient.Do(req)
	if getErr != nil {
		t.Fatalf("health listener closed before the drain delay elapsed: %v", getErr)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz during drain = %d, want 503", resp.StatusCode)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond {
		t.Fatalf("Serve() returned after %v, before the drain delay", elapsed)
	}
}
