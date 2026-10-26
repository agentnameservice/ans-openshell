package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"

	"github.com/agentnameservice/ans-openshell/internal/pemkeys"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

const (
	testAgentID = "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
	testAnsName = "ans://v1.0.0.payments.example.com"
)

func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeSEC1, Bytes: der})
}

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: der})
}

func TestNewPEMSigner(t *testing.T) {
	t.Parallel()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	other := testfixtures.MustNewIdentity("other", testAnsName)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("P-384 key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}

	tests := []struct {
		name    string
		keyPEM  []byte
		certPEM []byte
		wantErr string
	}{
		{name: "pkcs8", keyPEM: id.KeyPEM, certPEM: id.CertPEM},
		{name: "sec1", keyPEM: sec1PEM(t, id.Key), certPEM: id.CertPEM},
		{name: "key not pem", keyPEM: []byte("not pem"), certPEM: id.CertPEM, wantErr: "private key: no PEM block"},
		{name: "key wrong block type", keyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}),
			certPEM: id.CertPEM, wantErr: `unsupported PEM block "RSA PRIVATE KEY"`},
		{name: "pkcs8 garbage", keyPEM: pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: []byte{1, 2}}),
			certPEM: id.CertPEM, wantErr: "parse PRIVATE KEY"},
		{name: "pkcs8 not ecdsa", keyPEM: pkcs8PEM(t, edKey), certPEM: id.CertPEM, wantErr: "want an ECDSA P-256 key"},
		{name: "sec1 wrong curve", keyPEM: sec1PEM(t, p384), certPEM: id.CertPEM, wantErr: "key curve is P-384"},
		{name: "cert not pem", keyPEM: id.KeyPEM, certPEM: []byte("nope"), wantErr: "certificate: no PEM block"},
		{name: "cert wrong block type", keyPEM: id.KeyPEM,
			certPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: id.CertDER}), wantErr: `unsupported PEM block "PUBLIC KEY"`},
		{name: "cert garbage", keyPEM: id.KeyPEM,
			certPEM: pem.EncodeToMemory(&pem.Block{Type: pemkeys.TypeCertificate, Bytes: []byte{1, 2, 3}}), wantErr: "parse certificate"},
		{name: "cert key mismatch", keyPEM: id.KeyPEM, certPEM: other.CertPEM, wantErr: "signer:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signer, cert, err := NewPEMSigner(tt.keyPEM, tt.certPEM)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewPEMSigner() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPEMSigner() error = %v", err)
			}
			if signer == nil || cert == nil || string(cert.Raw) != string(id.CertDER) {
				t.Fatal("NewPEMSigner() returned no signer or the wrong certificate")
			}
		})
	}
}

func TestSignerBindsMethodURLAndContent(t *testing.T) {
	t.Parallel()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	signer, _, err := NewPEMSigner(id.KeyPEM, id.CertPEM)
	if err != nil {
		t.Fatalf("NewPEMSigner: %v", err)
	}
	const method, target = http.MethodPost, "https://tools.example.com:443/v1/do"
	body := []byte(`{"a":1}`)
	proof, err := signer.Sign(t.Context(), method, target, sha256.Sum256(body))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	replay := pop.NewMemoryReplayCache(t.Context(), 0)
	defer replay.Close()
	content := func() ([]byte, error) { return body, nil }
	res, err := pop.VerifyProof(t.Context(), proof, method, "https://tools.example.com/v1/do", time.Now(), 0, replay,
		pop.WithReceivedContent(content))
	if err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	if res.Fingerprint != id.Fingerprint {
		t.Fatal("proof certificate is not the identity certificate")
	}
	tampered := func() ([]byte, error) { return []byte(`{"a":2}`), nil }
	if _, err := pop.VerifyProof(t.Context(), proof, method, target, time.Now(), 0, replay,
		pop.WithReceivedContent(tampered)); err == nil {
		t.Fatal("proof verified against different content")
	}
	if _, err := signer.Sign(t.Context(), method, "not a url", sha256.Sum256(nil)); err == nil {
		t.Fatal("Sign accepted a relative URL")
	}
}

func TestNewSelfSignedSigner(t *testing.T) {
	t.Parallel()
	const ansName = "ans://v9.9.9.rogue.example"

	signer, key, cert, err := NewSelfSignedSigner(ansName)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}

	// Check cert has exactly one URI SAN matching ansName
	if len(cert.URIs) != 1 {
		t.Fatalf("cert.URIs has %d entries, want 1", len(cert.URIs))
	}
	if cert.URIs[0].String() != ansName {
		t.Fatalf("cert.URIs[0] = %q, want %q", cert.URIs[0].String(), ansName)
	}

	// Check cert public key is ECDSA P-256
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if pubKey.Curve != elliptic.P256() {
		t.Fatalf("cert public key curve = %v, want P-256", pubKey.Curve)
	}

	// Check cert validity window
	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Fatalf("cert.NotBefore = %v is after now", cert.NotBefore)
	}
	if cert.NotAfter.Before(now) {
		t.Fatalf("cert.NotAfter = %v is before now", cert.NotAfter)
	}

	// Check that the returned key is the key that signed the cert
	if !key.PublicKey.Equal(pubKey) {
		t.Fatal("returned key does not match cert's public key")
	}

	// Sign twice and verify both proofs embed the same cert fingerprint
	const method, target = http.MethodGet, "https://example.com/test"
	contentDigest := sha256.Sum256(nil)

	proof1, err := signer.Sign(t.Context(), method, target, contentDigest)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	proof2, err := signer.Sign(t.Context(), method, target, contentDigest)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}

	// Parse and verify both proofs
	replay := pop.NewMemoryReplayCache(t.Context(), 0)
	defer replay.Close()

	res1, err := pop.VerifyProof(t.Context(), proof1, method, target, time.Now(), 0, replay)
	if err != nil {
		t.Fatalf("VerifyProof #1: %v", err)
	}
	res2, err := pop.VerifyProof(t.Context(), proof2, method, target, time.Now(), 0, replay)
	if err != nil {
		t.Fatalf("VerifyProof #2: %v", err)
	}

	if res1.Fingerprint != res2.Fingerprint {
		t.Fatalf("fingerprints differ: %x vs %x", res1.Fingerprint, res2.Fingerprint)
	}

	// Verify the fingerprint matches the cert
	expectedFingerprint := sha256.Sum256(cert.Raw)
	if res1.Fingerprint != expectedFingerprint {
		t.Fatalf("fingerprint = %x, want %x", res1.Fingerprint, expectedFingerprint)
	}
}

func TestNewSelfSignedSigner_BadName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ansName string
	}{
		{name: "not an ans name", ansName: "not-an-ans-name"},
		{name: "empty", ansName: ""},
		{name: "http scheme", ansName: "http://v1.0.0.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signer, key, cert, err := NewSelfSignedSigner(tt.ansName)
			if err == nil {
				t.Fatalf("NewSelfSignedSigner(%q) succeeded, want error", tt.ansName)
			}
			if signer != nil {
				t.Fatal("signer is not nil")
			}
			if key != nil {
				t.Fatal("key is not nil")
			}
			if cert != nil {
				t.Fatal("cert is not nil")
			}
		})
	}
}
