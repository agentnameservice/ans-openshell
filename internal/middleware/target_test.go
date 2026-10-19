package middleware

import (
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

func target(scheme, host string, port uint32, path, query string) *middlewarev1.HttpRequestTarget {
	return &middlewarev1.HttpRequestTarget{Scheme: scheme, Host: host, Port: port, Method: http.MethodGet, Path: path, Query: query}
}

func TestTargetURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      *middlewarev1.HttpRequestTarget
		want    string
		wantErr bool
	}{
		{name: "https default port and query dropped", in: target("https", "tools.example.com", 443, "/v1/do", "a=1&b=2"),
			want: "https://tools.example.com/v1/do"},
		{name: "https custom port", in: target("https", "tools.example.com", 8443, "/v1/do", ""),
			want: "https://tools.example.com:8443/v1/do"},
		{name: "http default port", in: target("http", "tools.example.com", 80, "/x", ""), want: "http://tools.example.com/x"},
		{name: "http on 443 keeps the port", in: target("http", "tools.example.com", 443, "/x", ""),
			want: "http://tools.example.com:443/x"},
		{name: "https on 80 keeps the port", in: target("https", "tools.example.com", 80, "/x", ""),
			want: "https://tools.example.com:80/x"},
		{name: "ws maps to http", in: target("ws", "tools.example.com", 80, "/socket", ""), want: "http://tools.example.com/socket"},
		{name: "wss maps to https", in: target("wss", "tools.example.com", 8443, "/socket", ""),
			want: "https://tools.example.com:8443/socket"},
		{name: "empty path becomes slash", in: target("https", "tools.example.com", 443, "", ""), want: "https://tools.example.com/"},
		{name: "path without leading slash", in: target("https", "tools.example.com", 0, "v1", ""), want: "https://tools.example.com/v1"},
		{name: "zero port omitted", in: target("https", "tools.example.com", 0, "/", ""), want: "https://tools.example.com/"},
		{name: "scheme and host lowercased, path preserved", in: target(" HTTPS ", " Tools.Example.COM ", 0, "/A/B%20c", ""),
			want: "https://tools.example.com/A/B%20c"},
		{name: "ipv6 literal bracketed", in: target("https", "2001:db8::1", 8443, "/", ""), want: "https://[2001:db8::1]:8443/"},
		{name: "bracketed ipv6 kept", in: target("http", "[::1]", 8080, "/", ""), want: "http://[::1]:8080/"},
		{name: "unsupported scheme", in: target("ftp", "tools.example.com", 21, "/", ""), wantErr: true},
		{name: "empty scheme", in: target("", "tools.example.com", 443, "/", ""), wantErr: true},
		{name: "empty host", in: target("https", " ", 443, "/", ""), wantErr: true},
		{name: "nil target", in: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := TargetURL(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("TargetURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("TargetURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTargetURLMatchesVerifierNormalization proves a proof minted over
// TargetURL's output verifies against the URL a callee reconstructs from the
// wire request, including the query the proof must not bind.
func TestTargetURLMatchesVerifierNormalization(t *testing.T) {
	t.Parallel()
	id := testfixtures.MustNewIdentity("agent", "ans://v1.0.0.agent.example.com")
	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := TargetURL(target("wss", "Tools.Example.com", 443, "/v1/stream", "token=secret"))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signer.Sign(t.Context(), http.MethodGet, bound, pop.WithContentDigest(sha256.Sum256(nil)))
	if err != nil {
		t.Fatal(err)
	}
	replay := pop.NewMemoryReplayCache(t.Context(), 0)
	defer replay.Close()
	wire := "https://tools.example.com:443/v1/stream?token=secret"
	if _, err := pop.VerifyProof(t.Context(), proof, http.MethodGet, wire, time.Now(), 0, replay); err != nil {
		t.Fatalf("proof over %q does not verify against %q: %v", bound, wire, err)
	}
}
