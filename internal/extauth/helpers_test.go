package extauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const (
	testIssuer   = "openshell-gateway:test-gw"
	testAudience = "urn:openshell:extension:middleware:ans"
	testSubject  = "openshell-gateway"
)

type signer struct {
	kid  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return signer{kid: kid, pub: pub, priv: priv}
}

func (s signer) jwk() map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "x": b64(s.pub)}
}

// mint signs hdr and claims as a compact JWS.
func (s signer) mint(t *testing.T, hdr, claims map[string]any) string {
	t.Helper()
	return s.sign(b64(mustJSON(t, hdr)) + "." + b64(mustJSON(t, claims)))
}

func (s signer) sign(signingInput string) string {
	return signingInput + "." + b64(ed25519.Sign(s.priv, []byte(signingInput)))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func jwksJSON(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{"keys": keys})
}

func testHeader(kid string) map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": "openshell-ext+jwt", "kid": kid}
}

func testClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": testIssuer, "aud": testAudience, "sub": testSubject,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"jti": "jti-1", "caller_kind": "gateway",
	}
}

func gatewayToken(t *testing.T, s signer, now time.Time) string {
	t.Helper()
	return s.mint(t, testHeader(s.kid), testClaims(now))
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func fixedClock(now time.Time) func() time.Time { return func() time.Time { return now } }

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func fileAuth(t *testing.T, signers ...signer) config.Auth {
	t.Helper()
	keys := make([]map[string]any, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.jwk())
	}
	return config.Auth{
		GatewayIssuer: testIssuer,
		Audience:      testAudience,
		JWKSFile:      writeFile(t, "jwks.json", jwksJSON(t, keys...)),
	}
}

func fileVerifier(t *testing.T, now time.Time, signers ...signer) *Verifier {
	t.Helper()
	v, err := NewVerifier(fileAuth(t, signers...), discardLogger(), WithClock(fixedClock(now)))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}
