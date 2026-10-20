package extauth

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

func set(kv ...any) func(map[string]any) {
	return func(m map[string]any) {
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
	}
}

func del(keys ...string) func(map[string]any) {
	return func(m map[string]any) {
		for _, k := range keys {
			delete(m, k)
		}
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	unix := now.Unix()
	key := newSigner(t, "k1")
	other := newSigner(t, "k2")
	impostor := signer{kid: "k1", pub: other.pub, priv: other.priv}
	v := fileVerifier(t, now, key)

	gateway := Caller{Kind: CallerGateway, Issuer: testIssuer, Subject: testSubject}
	supervisor := Caller{Kind: CallerSupervisor, Issuer: testIssuer, Subject: "spiffe://openshell/sandbox/sb-1", SandboxID: "sb-1"}
	asSupervisor := set("caller_kind", "supervisor", "sandbox_id", "sb-1", "sub", supervisor.Subject)

	tests := []struct {
		name    string
		header  func(map[string]any)
		claims  func(map[string]any)
		signer  *signer
		mutate  func(string) string
		wantErr error
		want    Caller
	}{
		{name: "gateway", want: gateway},
		{name: "supervisor", claims: asSupervisor, want: supervisor},
		{name: "extra header members tolerated", header: set("cty", "json", "x-build", 7), want: gateway},
		{name: "extra claims tolerated", claims: set("nbf", unix, "scope", "x"), want: gateway},
		{name: "exp inside leeway", claims: set("iat", unix-600, "exp", unix-29), want: gateway},
		{name: "iat inside leeway", claims: set("iat", unix+29, "exp", unix+329), want: gateway},
		{name: "lifetime exactly one hour", claims: set("iat", unix, "exp", unix+3600), want: gateway},
		{name: "too large", mutate: func(tok string) string { return tok + strings.Repeat("a", maxTokenBytes) }, wantErr: ErrTokenTooLarge},
		{name: "two segments", mutate: func(tok string) string { return tok[:strings.LastIndex(tok, ".")] }, wantErr: ErrMalformedToken},
		{name: "four segments", mutate: func(tok string) string { return tok + ".extra" }, wantErr: ErrMalformedToken},
		{name: "padded header", mutate: func(tok string) string { return strings.Replace(tok, ".", "==.", 1) }, wantErr: ErrMalformedToken},
		{name: "header not json", mutate: replaceSegment(0, b64([]byte("not json"))), wantErr: ErrMalformedToken},
		{name: "header is array", mutate: replaceSegment(0, b64([]byte("[]"))), wantErr: ErrMalformedToken},
		{name: "alg RS256", header: set("alg", "RS256"), wantErr: ErrUnsupportedAlg},
		{name: "alg lowercase", header: set("alg", "eddsa"), wantErr: ErrUnsupportedAlg},
		{name: "alg none", header: set("alg", "none"), wantErr: ErrUnsupportedAlg},
		{name: "alg missing", header: del("alg"), wantErr: ErrUnsupportedAlg},
		{name: "typ JWT", header: set("typ", "JWT"), wantErr: ErrUnexpectedTokenType},
		{name: "typ missing", header: del("typ"), wantErr: ErrUnexpectedTokenType},
		{name: "kid missing", header: del("kid"), wantErr: ErrUnknownKey},
		{name: "kid unknown", signer: &other, wantErr: ErrUnknownKey},
		{name: "wrong key for kid", signer: &impostor, wantErr: ErrInvalidSignature},
		{name: "tampered payload", mutate: replaceSegment(1, b64([]byte(`{"iss":"x"}`))), wantErr: ErrInvalidSignature},
		{name: "signature not base64", mutate: replaceSegment(2, "!!!"), wantErr: ErrInvalidSignature},
		{name: "signature wrong length", mutate: replaceSegment(2, b64([]byte("short"))), wantErr: ErrInvalidSignature},
		{name: "payload not base64", mutate: resign(key, 1, "!!!"), wantErr: ErrMalformedToken},
		{name: "payload not an object", mutate: resign(key, 1, b64([]byte("[]"))), wantErr: ErrInvalidClaims},
		{name: "aud array", claims: set("aud", []string{testAudience}), wantErr: ErrInvalidClaims},
		{name: "aud number", claims: set("aud", 42), wantErr: ErrInvalidClaims},
		{name: "iat float", claims: set("iat", 1.5), wantErr: ErrInvalidClaims},
		{name: "iat string", claims: set("iat", "123"), wantErr: ErrInvalidClaims},
		{name: "iat missing", claims: del("iat"), wantErr: ErrInvalidClaims},
		{name: "exp missing", claims: del("exp"), wantErr: ErrInvalidClaims},
		{name: "iat negative", claims: set("iat", -5), wantErr: ErrInvalidClaims},
		{name: "sub missing", claims: del("sub"), wantErr: ErrInvalidClaims},
		{name: "sub empty", claims: set("sub", ""), wantErr: ErrInvalidClaims},
		{name: "jti missing", claims: del("jti"), wantErr: ErrInvalidClaims},
		{name: "jti empty", claims: set("jti", ""), wantErr: ErrInvalidClaims},
		{name: "issuer mismatch", claims: set("iss", "openshell-gateway:other"), wantErr: ErrIssuerMismatch},
		{name: "issuer missing", claims: del("iss"), wantErr: ErrIssuerMismatch},
		{name: "audience mismatch", claims: set("aud", "urn:openshell:extension:interceptor:ans"), wantErr: ErrAudienceMismatch},
		{name: "expired at leeway edge", claims: set("iat", unix-600, "exp", unix-30), wantErr: ErrTokenExpired},
		{name: "expired long ago", claims: set("iat", unix-7260, "exp", unix-7200), wantErr: ErrTokenExpired},
		{name: "exp overflows", claims: set("iat", unix, "exp", int64(math.MaxInt64)), wantErr: ErrTokenExpired},
		{name: "iat beyond leeway", claims: set("iat", unix+31, "exp", unix+331), wantErr: ErrTokenNotYetValid},
		{name: "lifetime over one hour", claims: set("iat", unix, "exp", unix+3601), wantErr: ErrTokenLifetime},
		{name: "exp before iat", claims: set("iat", unix, "exp", unix-1), wantErr: ErrTokenLifetime},
		{name: "exp equals iat", claims: set("iat", unix, "exp", unix), wantErr: ErrTokenLifetime},
		{name: "caller_kind missing", claims: del("caller_kind"), wantErr: ErrInvalidCaller},
		{name: "caller_kind unknown", claims: set("caller_kind", "admin"), wantErr: ErrInvalidCaller},
		{name: "supervisor without sandbox_id", claims: set("caller_kind", "supervisor"), wantErr: ErrInvalidCaller},
		{name: "gateway with sandbox_id", claims: set("sandbox_id", "sb-1"), wantErr: ErrInvalidCaller},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := key
			if tt.signer != nil {
				s = *tt.signer
			}
			hdr, claims := testHeader(s.kid), testClaims(now)
			if tt.header != nil {
				tt.header(hdr)
			}
			if tt.claims != nil {
				tt.claims(claims)
			}
			tok := s.mint(t, hdr, claims)
			if tt.mutate != nil {
				tok = tt.mutate(tok)
			}
			got, err := v.Verify(t.Context(), tok)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
				}
				if seg := strings.Split(tok, ".")[0]; strings.Contains(err.Error(), seg) {
					t.Fatalf("Verify() error echoes the token: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Verify() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func replaceSegment(i int, with string) func(string) string {
	return func(tok string) string {
		parts := strings.Split(tok, ".")
		parts[i] = with
		return strings.Join(parts, ".")
	}
}

// resign replaces segment i and signs the result so the signature is valid
// over the corrupted content.
func resign(s signer, i int, with string) func(string) string {
	return func(tok string) string {
		parts := strings.Split(tok, ".")
		parts[i] = with
		return s.sign(parts[0] + "." + parts[1])
	}
}

func TestNewVerifierErrors(t *testing.T) {
	t.Parallel()
	key := newSigner(t, "k1")
	rsa := map[string]any{"kty": "RSA", "kid": "r1", "n": "AQAB", "e": "AQAB"}
	tests := []struct {
		name    string
		cfg     config.Auth
		wantErr error
	}{
		{name: "invalid config", cfg: config.Auth{Audience: testAudience, JWKSFile: "x"}},
		{name: "missing file", cfg: config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSFile: "/nonexistent/jwks.json"}},
		{name: "file not json", cfg: config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSFile: writeFile(t, "bad.json", []byte("{"))}},
		{name: "file without usable keys", cfg: config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSFile: writeFile(t, "rsa.json", jwksJSON(t, rsa))}, wantErr: ErrNoUsableKeys},
		{name: "http jwks_url", cfg: config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSURL: "http://gateway/.well-known/jwks.json"}, wantErr: ErrInsecureJWKSURL},
		{name: "unparsable jwks_url", cfg: config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSURL: "https://[::1"}},
		{name: "jwks_url with bad file", cfg: config.Auth{GatewayIssuer: testIssuer, Audience: testAudience, JWKSURL: "https://gateway/jwks", JWKSFile: writeFile(t, "bad.json", []byte("{"))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := NewVerifier(tt.cfg, discardLogger())
			if err == nil {
				t.Fatalf("NewVerifier() = %+v, want error", v)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewVerifier() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
	if _, err := NewVerifier(fileAuth(t, key), nil); err != nil {
		t.Fatalf("NewVerifier(nil logger) error = %v", err)
	}
}

func TestNewVerifierInsecure(t *testing.T) {
	t.Parallel()
	logger, buf := bufferLogger()
	v, err := NewVerifier(config.Auth{AllowInsecureNoAuth: true}, logger)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 || !strings.Contains(buf.String(), "allow_insecure_no_auth") {
		t.Fatalf("expected exactly one WARN about allow_insecure_no_auth, got log:\n%s", buf.String())
	}
	now := time.Unix(1_800_000_000, 0)
	if _, err := v.Verify(t.Context(), gatewayToken(t, newSigner(t, "k1"), now)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Verify() error = %v, want %v (no trust anchor in insecure mode)", err, ErrUnknownKey)
	}
}

func TestNewVerifierSkipsUnusableFileKeys(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	good := newSigner(t, "good")
	noKid := newSigner(t, "").jwk()
	wrongAlg := newSigner(t, "wrong-alg").jwk()
	wrongAlg["alg"] = "ES256"
	wrongUse := newSigner(t, "wrong-use").jwk()
	wrongUse["use"] = "enc"
	dup := newSigner(t, "good").jwk()
	rsa := map[string]any{"kty": "RSA", "kid": "r1", "n": "AQAB", "e": "AQAB"}
	badX := map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "bad-x", "x": "AQAB"}

	logger, buf := bufferLogger()
	cfg := config.Auth{
		GatewayIssuer: testIssuer, Audience: testAudience,
		JWKSFile: writeFile(t, "jwks.json", jwksJSON(t, rsa, noKid, wrongAlg, wrongUse, badX, good.jwk(), dup)),
	}
	v, err := NewVerifier(cfg, logger, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, reason := range []string{"not an Ed25519 OKP key", "missing kid", "alg is not EdDSA", "use is not sig", "base64url Ed25519", "duplicate kid"} {
		if !strings.Contains(buf.String(), reason) {
			t.Errorf("missing warning %q in log:\n%s", reason, buf.String())
		}
	}
	if _, err := v.Verify(t.Context(), gatewayToken(t, good, now)); err != nil {
		t.Fatalf("Verify() with the usable key error = %v", err)
	}
	impostor := signer{kid: "good", priv: newSigner(t, "x").priv}
	if _, err := v.Verify(t.Context(), gatewayToken(t, impostor, now)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify() with the duplicate kid's key error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestRefreshIntervalPrecedence(t *testing.T) {
	t.Parallel()
	key := newSigner(t, "k1")
	tests := []struct {
		name string
		cfg  time.Duration
		opts []Option
		want time.Duration
	}{
		{name: "default", want: defaultRefreshInterval},
		{name: "config", cfg: time.Minute, want: time.Minute},
		{name: "option overrides config", cfg: time.Minute, opts: []Option{WithRefreshInterval(2 * time.Minute)}, want: 2 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := fileAuth(t, key)
			cfg.JWKSRefreshInterval = tt.cfg
			v, err := NewVerifier(cfg, discardLogger(), tt.opts...)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			if v.refreshInterval != tt.want {
				t.Fatalf("refreshInterval = %v, want %v", v.refreshInterval, tt.want)
			}
		})
	}
}
