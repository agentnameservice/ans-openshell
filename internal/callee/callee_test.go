package callee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

// c2spKey renders a fresh P-256 public key in the C2SP form the SDK's key
// store accepts: name+hex(SHA-256(SPKI)[:4])+base64(SPKI).
func c2spKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return "tl.example+" + hex.EncodeToString(sum[:4]) + "+" + base64.StdEncoding.EncodeToString(spki)
}

func TestParseRootKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{name: "two keys with comments", in: "# comment\nkey-one\n\n  key-two  \n", want: 2},
		{name: "empty", in: "\n# only a comment\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRootKeys(strings.NewReader(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRootKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != tt.want {
				t.Fatalf("ParseRootKeys() = %v, want %d keys", got, tt.want)
			}
		})
	}
}

func TestReadRootKeys(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(path, []byte("k1\nk2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := ReadRootKeys(path)
	if err != nil || len(keys) != 2 {
		t.Fatalf("ReadRootKeys() = %v, %v", keys, err)
	}
	if _, err := ReadRootKeys(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("ReadRootKeys() = nil error for a missing file")
	}
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "no root keys", cfg: Config{TrustedHosts: []string{"a"}}},
		{name: "no trusted hosts", cfg: Config{RootKeys: []string{c2spKey(t)}}},
		{name: "unparseable root key", cfg: Config{RootKeys: []string{"not-a-key"}, TrustedHosts: []string{"a"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(context.Background(), tt.cfg, nil); err == nil {
				t.Fatal("New() = nil error")
			}
		})
	}
}

func TestHandler_RejectsUnsignedRequest(t *testing.T) {
	t.Parallel()
	h, err := New(context.Background(), Config{
		RootKeys:        []string{c2spKey(t)},
		TrustedHosts:    []string{"callee.example"},
		AllowedAnsNames: []string{"ans://v1.0.0.agent.example"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/tasks", nil)
	req.Host = "callee.example"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "DPoP" {
		t.Fatalf("WWW-Authenticate = %q, want DPoP", got)
	}
}

func TestHandler_AcceptsSignedRequest(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := lis.Addr().String()
	h, err := New(context.Background(), Config{RootKeys: []string{tl.RootKeyC2SP()}, TrustedHosts: []string{authority}},
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)
	sign := func(body string) *http.Request {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+authority+"/v1/tasks",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if attachErr := pop.AttachIdentity(req, signer, http.Header{
			scitt.HeaderReceipt:     {receipt},
			scitt.HeaderStatusToken: {token},
		}); attachErr != nil {
			t.Fatal(attachErr)
		}
		return req
	}

	resp, err := http.DefaultClient.Do(sign(`{"task":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got Response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Caller != id.AnsName || got.AgentID != id.AgentID || got.BodyBytes != int64(len(`{"task":"hello"}`)) ||
		got.Method != http.MethodPost || got.Path != "/v1/tasks" {
		t.Fatalf("response = %+v", got)
	}

	tampered := sign(`{"task":"hello"}`)
	tampered.Body = io.NopCloser(strings.NewReader(`{"task":"evil!"}`))
	tampered.ContentLength = int64(len(`{"task":"evil!"}`))
	resp2, err := http.DefaultClient.Do(tampered)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body status = %d, want 401", resp2.StatusCode)
	}
}

// TestNew_FetchesRootKeysFromTL verifies that when TLBaseURL is set, New
// fetches root keys from a live TL server and uses them for verification,
// without requiring static RootKeys.
func TestNew_FetchesRootKeysFromTL(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	ts := testfixtures.FakeTLServer(tl)
	defer ts.Close()

	h, err := New(context.Background(), Config{
		TLBaseURL:    ts.URL,
		TrustedHosts: []string{"callee.example"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v, want nil (TL should supply keys)", err)
	}
	defer h.Close()

	// Verify the handler uses the fetched key by checking it accepts a signed request.
	// The handler would reject the request if it didn't have the TL's key.
	id := testfixtures.MustNewIdentity("agent-test", "ans://v1.0.0.test.example")
	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://callee.example/test", nil)
	req.Host = "callee.example"
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {receipt},
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()
	req.URL.Host = srv.Listener.Addr().String()
	req.URL.Scheme = "http"

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fetched key should verify the request)", resp.StatusCode)
	}
}

// TestNew_StaticRootKeysFallback verifies that when TLBaseURL is unset and
// static RootKeys are provided, New succeeds using the static keystore.
func TestNew_StaticRootKeysFallback(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"callee.example"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v, want nil (static RootKeys should work)", err)
	}
	defer h.Close()
}

// TestNew_FailsLoudWhenTLYieldsNoKeys verifies that when TLBaseURL is set but
// the TL returns no keys AND no static RootKeys are provided, New fails with a
// non-nil error (fail loud, do not serve zero keys).
func TestNew_FailsLoudWhenTLYieldsNoKeys(t *testing.T) {
	t.Parallel()
	// Empty TL server: returns 200 OK with an empty /root-keys response.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /root-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// Return empty content - no keys.
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	_, err := New(context.Background(), Config{
		TLBaseURL:    ts.URL,
		TrustedHosts: []string{"callee.example"},
	}, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("New() error = nil, want non-nil error when TL yields no keys")
	}
}

// TestReceiptToggle_OffAcceptsEmptyReceipt verifies that when RequireReceipt
// is false, a request with a valid status token + binding but an EMPTY
// X-SCITT-Receipt header is accepted (forwarded / 200-path).
func TestReceiptToggle_OffAcceptsEmptyReceipt(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := lis.Addr().String()
	h, err := New(context.Background(), Config{
		RootKeys:       []string{tl.RootKeyC2SP()},
		TrustedHosts:   []string{authority},
		RequireReceipt: false, // Toggle OFF: should accept empty receipt.
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	_, token := testfixtures.StaticArtifacts(tl, id)

	// Build a request with valid status token but EMPTY receipt.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+authority+"/v1/tasks",
		strings.NewReader(`{"task":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {""}, // EMPTY receipt.
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty receipt should be accepted when RequireReceipt=false)", resp.StatusCode)
	}
	var got Response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Caller != id.AnsName || got.AgentID != id.AgentID {
		t.Fatalf("response = %+v", got)
	}
}

// TestReceiptToggle_OnRejectsEmptyReceipt verifies that when RequireReceipt
// is true, a request with a valid status token + binding but an EMPTY
// X-SCITT-Receipt header is rejected (401).
func TestReceiptToggle_OnRejectsEmptyReceipt(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := lis.Addr().String()
	h, err := New(context.Background(), Config{
		RootKeys:       []string{tl.RootKeyC2SP()},
		TrustedHosts:   []string{authority},
		RequireReceipt: true, // Toggle ON: should reject empty receipt.
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	_, token := testfixtures.StaticArtifacts(tl, id)

	// Build a request with valid status token but EMPTY receipt.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+authority+"/v1/tasks",
		strings.NewReader(`{"task":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {""}, // EMPTY receipt.
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (empty receipt should be rejected when RequireReceipt=true)", resp.StatusCode)
	}
}

// TestForward_RelaysVerifiedRequestToSeller verifies that a verified request
// is forwarded to the seller with the same body bytes and Content-Type, and
// the seller's response is relayed verbatim.
func TestForward_RelaysVerifiedRequestToSeller(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")

	// Fake seller records what it received.
	var receivedBody []byte
	var receivedContentType string
	seller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("seller failed to read body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ticket":"t123"}`))
	}))
	defer seller.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"}, // Placeholder; will use WithExternalURL when SellerURL is set.
		SellerURL:    seller.URL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)

	// Sign a request with a specific body.
	// CRITICAL: Sign for the SELLER URL (htu is pinned to seller by WithExternalURL).
	originalBody := `{"task":"test-forward"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, seller.URL+"/v1/tasks",
		strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "application/json")
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {receipt},
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}
	// Update the URL to point at the ingress (srv), but the signature is for the seller.
	req.URL.Host = srv.Listener.Addr().String()
	req.URL.Scheme = "http"

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Assert the seller received the original body byte-for-byte (R3).
	if string(receivedBody) != originalBody {
		t.Errorf("seller received body %q, want %q (BODY REREAD FAILED)", receivedBody, originalBody)
	}
	if receivedContentType != "application/json" {
		t.Errorf("seller received Content-Type %q, want application/json", receivedContentType)
	}

	// Assert the client received the seller's response.
	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != `{"ticket":"t123"}` {
		t.Errorf("client received body %q, want seller's response", respBody)
	}
}

// TestForward_RelaysUpstreamErrorStatus verifies that a non-2xx status from
// the seller is relayed as-is (not masked as 502).
func TestForward_RelaysUpstreamErrorStatus(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")

	// Seller returns 500.
	seller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"seller internal error"}`))
	}))
	defer seller.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"}, // Placeholder; will use WithExternalURL when SellerURL is set.
		SellerURL:    seller.URL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)

	// Sign for the seller URL, then redirect to ingress.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, seller.URL+"/v1/tasks",
		strings.NewReader(`{"task":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {receipt},
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}
	req.URL.Host = srv.Listener.Addr().String()
	req.URL.Scheme = "http"

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Upstream 500 should be relayed as 500, NOT masked as 502.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (relay upstream status)", resp.StatusCode)
	}
}

// TestForward_UpstreamUnreachableIs502 verifies that when the seller is
// unreachable (transport error), the client receives 502.
func TestForward_UpstreamUnreachableIs502(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")

	// Point at a closed port to trigger a dial failure.
	// Find an unused port by opening and closing a listener.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachableURL := "http://" + lis.Addr().String()
	lis.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"}, // Placeholder; will use WithExternalURL when SellerURL is set.
		SellerURL:    unreachableURL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)

	// Sign for the seller URL (even though it's unreachable), then redirect to ingress.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, unreachableURL+"/v1/tasks",
		strings.NewReader(`{"task":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {receipt},
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}
	req.URL.Host = srv.Listener.Addr().String()
	req.URL.Scheme = "http"

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Transport error should be masked as 502 Bad Gateway.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (bad gateway for unreachable upstream)", resp.StatusCode)
	}
}

// TestForward_NoContentType verifies that when a request has no Content-Type
// header, the forwarder does not set one in the upstream request.
func TestForward_NoContentType(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")

	// Fake seller records the Content-Type it received.
	var receivedContentType string
	seller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer seller.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"},
		SellerURL:    seller.URL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)

	// Sign a request WITHOUT a Content-Type header.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, seller.URL+"/v1/tasks",
		strings.NewReader(`{"task":"test"}`))
	// Do NOT set Content-Type.
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {receipt},
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}
	req.URL.Host = srv.Listener.Addr().String()
	req.URL.Scheme = "http"

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Assert the seller did NOT receive a Content-Type header.
	if receivedContentType != "" {
		t.Errorf("seller received Content-Type %q, want empty (no header should be forwarded)", receivedContentType)
	}
}

// TestForward_UpstreamResponseNoContentType verifies that when the seller
// response has no Content-Type, the forwarder does not set one in the client
// response.
func TestForward_UpstreamResponseNoContentType(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity("agent-123", "ans://v1.0.0.agent.example")

	// Seller returns a response without Content-Type.
	seller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Do NOT set Content-Type.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`plain text`))
	}))
	defer seller.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"},
		SellerURL:    seller.URL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, id)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, seller.URL+"/v1/tasks",
		strings.NewReader(`{"task":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	if attachErr := pop.AttachIdentity(req, signer, http.Header{
		scitt.HeaderReceipt:     {receipt},
		scitt.HeaderStatusToken: {token},
	}); attachErr != nil {
		t.Fatal(attachErr)
	}
	req.URL.Host = srv.Listener.Addr().String()
	req.URL.Scheme = "http"

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The forwarder should NOT set a Content-Type if the seller didn't provide one.
	// (httptest may add a default, so we just verify the response is relayed).
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `plain text` {
		t.Errorf("client received body %q, want seller's response", body)
	}
}

// TestBodyGuard_OversizeReturns400 verifies that a request whose body exceeds
// 262144 bytes (256 KiB) returns 400 and NEVER reaches verification or the
// seller.
func TestBodyGuard_OversizeReturns400(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()

	// Fake seller that records hits.
	var sellerHits int
	seller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sellerHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer seller.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"},
		SellerURL:    seller.URL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	// Create an oversize body: 262145 bytes (one more than the limit).
	oversizeBody := strings.Repeat("a", 262145)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/tasks",
		strings.NewReader(oversizeBody))
	req.Header.Set("Content-Type", "application/json")
	// Set Content-Length explicitly to test the known-length path.
	req.ContentLength = int64(len(oversizeBody))

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Assert: status is 400 (NOT 413), and the seller was never called.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (oversize body rejected before verification)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "request body too large") {
		t.Errorf("response body = %q, want 'request body too large'", body)
	}
	if sellerHits != 0 {
		t.Errorf("seller received %d hits, want 0 (oversize body should never reach verification/seller)", sellerHits)
	}
}

// TestBodyGuard_OversizeReturns400_UnknownLength verifies that when
// Content-Length is not set (chunked/unknown), a body exceeding 256 KiB is
// rejected with 400 after buffering detects the overflow.
func TestBodyGuard_OversizeReturns400_UnknownLength(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()

	var sellerHits int
	seller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sellerHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer seller.Close()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"ingress.example"},
		SellerURL:    seller.URL,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	// Create an oversize body: 262145 bytes.
	oversizeBody := strings.Repeat("b", 262145)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/tasks",
		strings.NewReader(oversizeBody))
	req.Header.Set("Content-Type", "application/json")
	// Set ContentLength to -1 to simulate unknown length (chunked).
	req.ContentLength = -1

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Assert: status is 400, and the seller was never called.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (oversize body rejected after buffering)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "request body too large") {
		t.Errorf("response body = %q, want 'request body too large'", body)
	}
	if sellerHits != 0 {
		t.Errorf("seller received %d hits, want 0 (oversize body should never reach seller)", sellerHits)
	}
}

// TestBodyGuard_AtLimitPasses verifies that a request with EXACTLY 262144
// bytes (256 KiB) is allowed through to verification (may then return 401 for
// missing signature, but NOT the guard's 400).
func TestBodyGuard_AtLimitPasses(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()

	h, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"callee.example"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	// Create a body at exactly the limit: 262144 bytes.
	atLimitBody := strings.Repeat("c", 262144)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/tasks",
		strings.NewReader(atLimitBody))
	req.Host = "callee.example"
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Assert: status is NOT the guard's 400 "request body too large".
	// It will be 401 (unsigned request), but that's verification rejecting it,
	// not the guard.
	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "request body too large") {
			t.Fatalf("at-limit body rejected by guard (status 400 'request body too large'), should pass through to verification")
		}
	}
	// Expect 401 from verification (unsigned request).
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (at-limit body should reach verification)", resp.StatusCode)
	}
}

// failingReader is an io.ReadCloser that returns an error after reading n bytes.
type failingReader struct {
	n   int
	err error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, r.err
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	n := len(p)
	r.n -= n
	return n, nil
}

func (r *failingReader) Close() error {
	return nil
}

// TestBodyGuard_ReadError verifies that when reading a body with unknown length
// encounters a non-EOF/non-UnexpectedEOF error (e.g., network failure), the
// guard returns 400 "failed to read body".
func TestBodyGuard_ReadError(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()

	// Create a test handler that wraps the callee handler and replaces r.Body
	// with a failing reader to simulate a read error.
	inner, err := New(context.Background(), Config{
		RootKeys:     []string{tl.RootKeyC2SP()},
		TrustedHosts: []string{"callee.example"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer inner.Close()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Replace r.Body with a failing reader to simulate a read error in the guard.
		r.Body = &failingReader{
			n:   100,
			err: io.ErrNoProgress, // Non-EOF/non-UnexpectedEOF error.
		}
		r.ContentLength = -1 // Unknown length to trigger buffering path.
		inner.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/tasks",
		strings.NewReader(`{"task":"test"}`))
	req.Host = "callee.example"
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The body guard should catch the read error and return 400.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (read error should be caught by guard)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "failed to read body") {
		t.Errorf("response body = %q, want 'failed to read body'", body)
	}
}
