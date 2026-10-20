package extauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

func TestParseJWKS(t *testing.T) {
	t.Parallel()
	k1, k2 := newSigner(t, "k1"), newSigner(t, "k2")
	rsa := map[string]any{"kty": "RSA", "kid": "r1", "n": "AQAB", "e": "AQAB"}
	padded := k1.jwk()
	padded["x"] = padded["x"].(string) + "="
	short := map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "short", "x": "AQAB"}
	x25519 := map[string]any{"kty": "OKP", "crv": "X25519", "kid": "x", "x": b64(k1.pub)}
	tests := []struct {
		name        string
		data        []byte
		wantKids    []string
		wantSkipped []string
		wantErr     error
		wantAnyErr  bool
	}{
		{name: "single key", data: jwksJSON(t, k1.jwk()), wantKids: []string{"k1"}},
		{name: "two keys", data: jwksJSON(t, k1.jwk(), k2.jwk()), wantKids: []string{"k1", "k2"}},
		{name: "invalid json", data: []byte("{"), wantAnyErr: true},
		{name: "keys not an array", data: []byte(`{"keys":{}}`), wantAnyErr: true},
		{name: "no keys member", data: []byte(`{}`), wantErr: ErrNoUsableKeys},
		{name: "empty keys", data: []byte(`{"keys":[]}`), wantErr: ErrNoUsableKeys},
		{name: "only rsa", data: jwksJSON(t, rsa), wantErr: ErrNoUsableKeys, wantSkipped: []string{"not an Ed25519 OKP key"}},
		{name: "x25519 is not a signing curve", data: jwksJSON(t, x25519), wantErr: ErrNoUsableKeys, wantSkipped: []string{"not an Ed25519 OKP key"}},
		{name: "padded x", data: jwksJSON(t, padded), wantErr: ErrNoUsableKeys, wantSkipped: []string{"x is not a base64url Ed25519 public key"}},
		{name: "short x", data: jwksJSON(t, short), wantErr: ErrNoUsableKeys, wantSkipped: []string{"x is not a base64url Ed25519 public key"}},
		{name: "mixed", data: jwksJSON(t, rsa, k1.jwk(), short, k1.jwk()), wantKids: []string{"k1"},
			wantSkipped: []string{"not an Ed25519 OKP key", "x is not a base64url Ed25519 public key", "duplicate kid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keys, skipped, err := parseJWKS(tt.data)
			if tt.wantAnyErr || tt.wantErr != nil {
				if err == nil {
					t.Fatalf("parseJWKS() = %v, want error", keys)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("parseJWKS() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("parseJWKS() error = %v", err)
			}
			var kids []string
			for kid := range keys {
				kids = append(kids, kid)
			}
			slices.Sort(kids)
			if !slices.Equal(kids, tt.wantKids) {
				t.Fatalf("parseJWKS() kids = %v, want %v", kids, tt.wantKids)
			}
			var reasons []string
			for _, sk := range skipped {
				reasons = append(reasons, sk.reason)
			}
			if !slices.Equal(reasons, tt.wantSkipped) {
				t.Fatalf("parseJWKS() skipped = %v, want %v", reasons, tt.wantSkipped)
			}
		})
	}
}

type jwksServer struct {
	*httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	body []byte
	code int
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	t.Helper()
	s := &jwksServer{body: body, code: http.StatusOK}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		body, code := s.body, s.code
		s.mu.Unlock()
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) serve(body []byte, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.code = body, code
}

func remoteAuth(t *testing.T, url string, file ...signer) config.Auth {
	t.Helper()
	cfg := config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSURL: url}
	if len(file) > 0 {
		cfg.JWKSFile = fileAuth(t, file...).JWKSFile
	}
	return cfg
}

func mustVerify(t *testing.T, v *Verifier, tok string) {
	t.Helper()
	if _, err := v.Verify(t.Context(), tok); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func mustReject(t *testing.T, v *Verifier, tok string, want error) {
	t.Helper()
	if _, err := v.Verify(t.Context(), tok); !errors.Is(err, want) {
		t.Fatalf("Verify() error = %v, want %v", err, want)
	}
}

func mustHits(t *testing.T, srv *jwksServer, want int32) {
	t.Helper()
	if got := srv.hits.Load(); got != want {
		t.Fatalf("jwks fetches = %d, want %d", got, want)
	}
}

func TestRemoteKeyLookup(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	fileKey, k1, k2 := newSigner(t, "file"), newSigner(t, "k1"), newSigner(t, "k2")
	srv := newJWKSServer(t, jwksJSON(t, k1.jwk()))
	v, err := NewVerifier(remoteAuth(t, srv.URL, fileKey), discardLogger(), WithClock(clock.Now), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	mustVerify(t, v, gatewayToken(t, fileKey, clock.now))
	mustHits(t, srv, 0)

	mustVerify(t, v, gatewayToken(t, k1, clock.now))
	mustHits(t, srv, 1)

	mustReject(t, v, gatewayToken(t, k2, clock.now), ErrUnknownKey)
	clock.advance(29 * time.Second)
	mustReject(t, v, gatewayToken(t, k2, clock.now), ErrUnknownKey)
	mustHits(t, srv, 1)

	clock.advance(2 * time.Second)
	mustReject(t, v, gatewayToken(t, k2, clock.now), ErrUnknownKey)
	mustHits(t, srv, 2)

	srv.serve(jwksJSON(t, k2.jwk()), http.StatusOK)
	clock.advance(31 * time.Second)
	mustVerify(t, v, gatewayToken(t, k2, clock.now))
	mustHits(t, srv, 3)
	mustReject(t, v, gatewayToken(t, k1, clock.now), ErrUnknownKey)
	mustHits(t, srv, 3)

	srv.serve(nil, http.StatusInternalServerError)
	clock.advance(31 * time.Second)
	mustReject(t, v, gatewayToken(t, k1, clock.now), ErrUnknownKey)
	mustHits(t, srv, 4)
	mustVerify(t, v, gatewayToken(t, k2, clock.now))
	mustVerify(t, v, gatewayToken(t, fileKey, clock.now))
}

func TestRefreshErrorsKeepPreviousKeys(t *testing.T) {
	t.Parallel()
	k1 := newSigner(t, "k1")
	rsa := map[string]any{"kty": "RSA", "kid": "r1", "n": "AQAB", "e": "AQAB"}
	oversize := []byte(`{"keys":[],"pad":"` + strings.Repeat("x", maxJWKSBytes) + `"}`)
	tests := []struct {
		name    string
		body    []byte
		code    int
		wantErr error
	}{
		{name: "not found", code: http.StatusNotFound},
		{name: "oversize", body: oversize, code: http.StatusOK, wantErr: ErrJWKSTooLarge},
		{name: "bad json", body: []byte("{"), code: http.StatusOK},
		{name: "no usable keys", body: jwksJSON(t, rsa), code: http.StatusOK, wantErr: ErrNoUsableKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
			srv := newJWKSServer(t, jwksJSON(t, k1.jwk()))
			v, err := NewVerifier(remoteAuth(t, srv.URL), discardLogger(), WithClock(clock.Now), WithHTTPClient(srv.Client()))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			if err := v.keys.refresh(t.Context()); err != nil {
				t.Fatalf("initial refresh error = %v", err)
			}
			srv.serve(tt.body, tt.code)
			err = v.keys.refresh(t.Context())
			if err == nil {
				t.Fatal("refresh() = nil, want error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("refresh() error = %v, want %v", err, tt.wantErr)
			}
			mustVerify(t, v, gatewayToken(t, k1, clock.now))
		})
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestFetchTransportError(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	logger, buf := bufferLogger()
	cfg := remoteAuth(t, "https://gateway.invalid/.well-known/jwks.json")
	v, err := NewVerifier(cfg, logger, WithClock(fixedClock(now)), WithHTTPClient(&http.Client{Transport: failingTransport{}}))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if err := v.keys.refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "fetch jwks") {
		t.Fatalf("refresh() error = %v, want fetch failure", err)
	}
	clock := &fakeClock{now: now.Add(time.Minute)}
	v.now, v.keys.now = clock.Now, clock.Now
	mustReject(t, v, gatewayToken(t, newSigner(t, "k1"), clock.now), ErrUnknownKey)
	if !strings.Contains(buf.String(), "jwks fetch for unknown kid failed") {
		t.Fatalf("missing fetch failure warning in log:\n%s", buf.String())
	}
}

func TestRunRefreshesPeriodically(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	k1 := newSigner(t, "k1")
	srv := newJWKSServer(t, jwksJSON(t, k1.jwk()))
	v, err := NewVerifier(remoteAuth(t, srv.URL), discardLogger(),
		WithClock(fixedClock(now)), WithHTTPClient(srv.Client()), WithRefreshInterval(2*time.Millisecond))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		v.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for srv.hits.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("Run() fetched %d times, want at least 3", srv.hits.Load())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
	mustVerify(t, v, gatewayToken(t, k1, now))
}

func TestRunLogsRefreshFailure(t *testing.T) {
	t.Parallel()
	logger, buf := bufferLogger()
	srv := newJWKSServer(t, nil)
	srv.serve(nil, http.StatusInternalServerError)
	v, err := NewVerifier(remoteAuth(t, srv.URL), logger, WithHTTPClient(srv.Client()), WithRefreshInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		v.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for srv.hits.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("Run() never fetched")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if !strings.Contains(buf.String(), "scheduled jwks refresh failed") {
		t.Fatalf("missing refresh failure warning in log:\n%s", buf.String())
	}
}

func TestRunWithoutURLWaits(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	insecureV, err := NewVerifier(config.Auth{AllowInsecureNoAuth: true}, discardLogger())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for name, v := range map[string]*Verifier{"file only": fileVerifier(t, now, newSigner(t, "k1")), "insecure": insecureV} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				v.Run(ctx)
				close(done)
			}()
			select {
			case <-done:
				t.Fatal("Run() returned before cancel")
			case <-time.After(20 * time.Millisecond):
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run() did not return after cancel")
			}
		})
	}
}
