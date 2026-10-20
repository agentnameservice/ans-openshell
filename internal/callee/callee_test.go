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
