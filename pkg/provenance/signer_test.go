package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

type testIdentity struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	keyPEM  []byte
	certPEM []byte
}

func selfSignedDER(t *testing.T, signer crypto.Signer) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ans-openshell test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return der
}

func newTestIdentity(t *testing.T, curve elliptic.Curve) testIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der := selfSignedDER(t, key)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return testIdentity{
		key:     key,
		cert:    cert,
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func ed25519PKCS8PEM(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// signParts builds a compact JWS from already-encoded header and payload
// segments, signed with key, so tests can present well-signed but otherwise
// bad tokens to Verify.
func signParts(t *testing.T, encodedHeader, encodedPayload string, key *ecdsa.PrivateKey) string {
	t.Helper()
	input := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign() error = %v", err)
	}
	sig := make([]byte, es256SignatureLen)
	r.FillBytes(sig[:es256CoordinateLen])
	s.FillBytes(sig[es256CoordinateLen:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64url(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func headerFor(cert *x509.Certificate) map[string]any {
	return map[string]any{"typ": BatchSignatureType, "alg": BatchSignatureAlg, "x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)}}
}

func TestNewPEMSigner(t *testing.T) {
	t.Parallel()
	p256 := newTestIdentity(t, elliptic.P256())
	p384 := newTestIdentity(t, elliptic.P384())
	other := newTestIdentity(t, elliptic.P256())
	tests := []struct {
		name    string
		keyPEM  []byte
		certPEM []byte
		wantErr string
	}{
		{name: "pkcs8", keyPEM: p256.keyPEM, certPEM: p256.certPEM},
		{name: "sec1", keyPEM: sec1PEM(t, p256.key), certPEM: p256.certPEM},
		{name: "no key pem", keyPEM: []byte("not pem"), certPEM: p256.certPEM, wantErr: "no PEM block"},
		{name: "unsupported key block", keyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}), certPEM: p256.certPEM, wantErr: `unsupported PEM block "RSA PRIVATE KEY"`},
		{name: "pkcs8 garbage", keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), certPEM: p256.certPEM, wantErr: "provenance: key:"},
		{name: "sec1 garbage", keyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), certPEM: p256.certPEM, wantErr: "provenance: key:"},
		{name: "ed25519 key", keyPEM: ed25519PKCS8PEM(t), certPEM: p256.certPEM, wantErr: "P-256"},
		{name: "p384 key", keyPEM: p384.keyPEM, certPEM: p384.certPEM, wantErr: "P-256"},
		{name: "no cert pem", keyPEM: p256.keyPEM, certPEM: nil, wantErr: "provenance: certificate"},
		{name: "wrong cert block", keyPEM: p256.keyPEM, certPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p256.cert.Raw}), wantErr: "provenance: certificate"},
		{name: "cert garbage", keyPEM: p256.keyPEM, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), wantErr: "provenance: certificate:"},
		{name: "cert for another key", keyPEM: p256.keyPEM, certPEM: other.certPEM, wantErr: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := NewPEMSigner(tt.keyPEM, tt.certPEM)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewPEMSigner() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPEMSigner() error = %v", err)
			}
			if !s.Certificate().Equal(p256.cert) {
				t.Fatal("Certificate() is not the configured certificate")
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	id := newTestIdentity(t, elliptic.P256())
	signer, err := NewPEMSigner(id.keyPEM, id.certPEM)
	if err != nil {
		t.Fatalf("NewPEMSigner() error = %v", err)
	}
	body := []byte(`{"observations":[{"agentId":"a"}]}`)
	iat := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

	jws, err := signer.Sign(body, iat, 1, "ans://v1.0.0.ops.example.com")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("jws has %d parts", len(parts))
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header is not base64url: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatalf("header is not JSON: %v", err)
	}
	x5c, _ := header["x5c"].([]any)
	if header["typ"] != "ans-observations+jws" || header["alg"] != "ES256" || len(header) != 3 || len(x5c) != 1 ||
		x5c[0] != base64.StdEncoding.EncodeToString(id.cert.Raw) {
		t.Fatalf("header = %v", header)
	}
	if sig, decodeErr := base64.RawURLEncoding.DecodeString(parts[2]); decodeErr != nil || len(sig) != 64 {
		t.Fatalf("signature = %d bytes, %v", len(sig), decodeErr)
	}

	claims, cert, err := Verify(jws, body)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	sum := sha256.Sum256(body)
	want := SignedBatchClaims{
		BodySHA256: base64.RawURLEncoding.EncodeToString(sum[:]),
		Count:      1,
		IssuedAt:   iat.Unix(),
		AIMID:      "ans://v1.0.0.ops.example.com",
	}
	if *claims != want {
		t.Fatalf("claims = %+v, want %+v", *claims, want)
	}
	if !cert.Equal(id.cert) {
		t.Fatal("Verify() returned a different certificate")
	}
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(rawClaims), `"body_sha256":"`) || !strings.Contains(string(rawClaims), `"aim_id":"`) || !strings.Contains(string(rawClaims), `"iat":`) {
		t.Fatalf("claims wire = %s", rawClaims)
	}
}

func TestVerifyRejects(t *testing.T) {
	t.Parallel()
	id := newTestIdentity(t, elliptic.P256())
	other := newTestIdentity(t, elliptic.P256())
	p384 := newTestIdentity(t, elliptic.P384())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edCert, err := x509.ParseCertificate(selfSignedDER(t, edKey))
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	signer, err := NewPEMSigner(id.keyPEM, id.certPEM)
	if err != nil {
		t.Fatalf("NewPEMSigner() error = %v", err)
	}
	body := []byte(`{"observations":[]}`)
	good, err := signer.Sign(body, time.Now(), 0, "aim")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	goodParts := strings.Split(good, ".")
	validClaims := b64url(SignedBatchClaims{BodySHA256: bodyDigest(body)})
	withHeader := func(h map[string]any) string { return signParts(t, b64url(h), validClaims, id.key) }
	tamperedClaims := func(h map[string]any) string {
		hdr := headerFor(id.cert)
		for k, v := range h {
			hdr[k] = v
		}
		return signParts(t, b64url(hdr), b64url(SignedBatchClaims{BodySHA256: bodyDigest(body), Count: 1}), id.key)
	}

	tests := []struct {
		name    string
		jws     string
		body    []byte
		wantErr error
		wantMsg string
	}{
		{name: "wrong body", jws: good, body: []byte("other"), wantErr: ErrBadSignature, wantMsg: "digest mismatch"},
		{name: "tampered claims", jws: goodParts[0] + "." + b64url(SignedBatchClaims{BodySHA256: bodyDigest(body), Count: 9}) + "." + goodParts[2], wantErr: ErrBadSignature},
		{name: "signed with another key", jws: signParts(t, b64url(headerFor(id.cert)), validClaims, other.key), wantErr: ErrBadSignature},
		{name: "x5c of another identity", jws: signParts(t, b64url(headerFor(other.cert)), validClaims, id.key), wantErr: ErrBadSignature},
		{name: "two parts", jws: goodParts[0] + "." + goodParts[1], wantErr: ErrMalformedSignature, wantMsg: "expected 3 parts"},
		{name: "header not base64url", jws: "!!!." + goodParts[1] + "." + goodParts[2], wantErr: ErrMalformedSignature, wantMsg: "header is not base64url"},
		{name: "header not json", jws: base64.RawURLEncoding.EncodeToString([]byte("{")) + "." + goodParts[1] + "." + goodParts[2], wantErr: ErrMalformedSignature, wantMsg: "header is not JSON"},
		{name: "bad alg", jws: withHeader(map[string]any{"typ": BatchSignatureType, "alg": "RS256", "x5c": []string{"x"}}), wantErr: ErrMalformedSignature, wantMsg: `alg "RS256"`},
		{name: "none alg", jws: withHeader(map[string]any{"typ": BatchSignatureType, "alg": "none", "x5c": []string{"x"}}), wantErr: ErrMalformedSignature, wantMsg: `alg "none"`},
		{name: "bad typ", jws: withHeader(map[string]any{"typ": "JWT", "alg": BatchSignatureAlg, "x5c": []string{"x"}}), wantErr: ErrMalformedSignature, wantMsg: `typ "JWT"`},
		{name: "missing x5c", jws: withHeader(map[string]any{"typ": BatchSignatureType, "alg": BatchSignatureAlg}), wantErr: ErrMalformedSignature, wantMsg: "x5c is empty"},
		{name: "empty x5c", jws: withHeader(map[string]any{"typ": BatchSignatureType, "alg": BatchSignatureAlg, "x5c": []string{}}), wantErr: ErrMalformedSignature, wantMsg: "x5c is empty"},
		{name: "x5c not base64", jws: withHeader(map[string]any{"typ": BatchSignatureType, "alg": BatchSignatureAlg, "x5c": []string{"%%%"}}), wantErr: ErrMalformedSignature, wantMsg: "x5c[0] is not base64"},
		{name: "x5c not a certificate", jws: withHeader(map[string]any{"typ": BatchSignatureType, "alg": BatchSignatureAlg, "x5c": []string{base64.StdEncoding.EncodeToString([]byte("junk"))}}), wantErr: ErrMalformedSignature, wantMsg: "x5c[0]:"},
		{name: "p384 certificate", jws: withHeader(headerFor(p384.cert)), wantErr: ErrMalformedSignature, wantMsg: "not ECDSA P-256"},
		{name: "ed25519 certificate", jws: withHeader(headerFor(edCert)), wantErr: ErrMalformedSignature, wantMsg: "not ECDSA P-256"},
		{name: "signature wrong length", jws: goodParts[0] + "." + goodParts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), wantErr: ErrMalformedSignature, wantMsg: "64 base64url bytes"},
		{name: "signature not base64url", jws: goodParts[0] + "." + goodParts[1] + ".%%%", wantErr: ErrMalformedSignature, wantMsg: "64 base64url bytes"},
		{name: "claims not base64url", jws: signParts(t, b64url(headerFor(id.cert)), "%%%", id.key), wantErr: ErrMalformedSignature, wantMsg: "claims are not base64url"},
		{name: "claims not json", jws: signParts(t, b64url(headerFor(id.cert)), base64.RawURLEncoding.EncodeToString([]byte("{")), id.key), wantErr: ErrMalformedSignature, wantMsg: "claims are not JSON"},
		{name: "count mismatch is not checked here", jws: tamperedClaims(nil), body: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			useBody := body
			if tt.body != nil {
				useBody = tt.body
			}
			claims, cert, err := Verify(tt.jws, useBody)
			if tt.wantErr == nil {
				if err != nil || claims == nil || cert == nil {
					t.Fatalf("Verify() = %v, %v, %v; want success", claims, cert, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("Verify() error = %q, want containing %q", err, tt.wantMsg)
			}
			if claims != nil || cert != nil {
				t.Fatalf("Verify() returned %v, %v alongside an error", claims, cert)
			}
		})
	}
}
