package selfsign_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/selfsign"
)

func TestStatusToken(t *testing.T) {
	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Create a test cert
	cert := mustCreateSelfSignedCert(t, key)
	certFP := sha256.Sum256(cert)

	// Mint a status token
	const (
		agentID = "test-agent-001"
		ansName = "ans://v1.0.0.test.example.com"
	)
	now := time.Now()
	iat := now.Add(-time.Minute).Unix()
	exp := now.Add(time.Hour).Unix()

	tokenBytes, err := selfsign.StatusToken(key, agentID, ansName, scitt.StatusActive, iat, exp, certFP)
	if err != nil {
		t.Fatalf("StatusToken: %v", err)
	}

	// Parse as COSE_Sign1
	parsed, err := scitt.ParseCoseSign1(tokenBytes)
	if err != nil {
		t.Fatalf("ParseCoseSign1: %v", err)
	}

	// Verify it has the expected structure
	if parsed.ProtectedBytes == nil {
		t.Error("ProtectedBytes is nil")
	}
	if parsed.Payload == nil {
		t.Error("Payload is nil")
	}
	if len(parsed.Signature) != 64 {
		t.Errorf("Signature length = %d, want 64 (P1363)", len(parsed.Signature))
	}

	// Verify the kid matches
	expectedKid := computeKid(t, key)
	if parsed.Protected.Kid != expectedKid {
		t.Errorf("kid = %x, want %x", parsed.Protected.Kid, expectedKid)
	}

	// Verify the algorithm
	if parsed.Protected.Alg != -7 { // ES256
		t.Errorf("alg = %d, want -7 (ES256)", parsed.Protected.Alg)
	}
}

func TestReceipt(t *testing.T) {
	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Mint a receipt
	const (
		agentID = "test-agent-002"
		ansName = "ans://v2.0.0.test.example.com"
	)

	receiptBytes, err := selfsign.Receipt(key, agentID, ansName)
	if err != nil {
		t.Fatalf("Receipt: %v", err)
	}

	// Parse as COSE_Sign1
	parsed, err := scitt.ParseCoseSign1(receiptBytes)
	if err != nil {
		t.Fatalf("ParseCoseSign1: %v", err)
	}

	// Verify it has the expected structure
	if parsed.ProtectedBytes == nil {
		t.Error("ProtectedBytes is nil")
	}
	if parsed.Payload == nil {
		t.Error("Payload is nil")
	}
	if len(parsed.Signature) != 64 {
		t.Errorf("Signature length = %d, want 64 (P1363)", len(parsed.Signature))
	}

	// Verify the kid matches
	expectedKid := computeKid(t, key)
	if parsed.Protected.Kid != expectedKid {
		t.Errorf("kid = %x, want %x", parsed.Protected.Kid, expectedKid)
	}

	// Verify the algorithm
	if parsed.Protected.Alg != -7 { // ES256
		t.Errorf("alg = %d, want -7 (ES256)", parsed.Protected.Alg)
	}

	// Verify VDS header is present (receipt-specific)
	if parsed.Protected.Vds == nil {
		t.Error("Vds header is nil, expected RFC9162 (1)")
	} else if *parsed.Protected.Vds != 1 {
		t.Errorf("Vds = %d, want 1 (RFC9162)", *parsed.Protected.Vds)
	}
}

func TestStatusToken_DifferentKeys(t *testing.T) {
	// Ensure different keys produce different kids
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}

	cert := mustCreateSelfSignedCert(t, key1)
	certFP := sha256.Sum256(cert)

	now := time.Now()
	iat := now.Add(-time.Minute).Unix()
	exp := now.Add(time.Hour).Unix()

	token1, err := selfsign.StatusToken(key1, "agent-1", "ans://v1.0.0.a.example.com", scitt.StatusActive, iat, exp, certFP)
	if err != nil {
		t.Fatalf("StatusToken key1: %v", err)
	}

	token2, err := selfsign.StatusToken(key2, "agent-1", "ans://v1.0.0.a.example.com", scitt.StatusActive, iat, exp, certFP)
	if err != nil {
		t.Fatalf("StatusToken key2: %v", err)
	}

	parsed1, err := scitt.ParseCoseSign1(token1)
	if err != nil {
		t.Fatalf("ParseCoseSign1 token1: %v", err)
	}
	parsed2, err := scitt.ParseCoseSign1(token2)
	if err != nil {
		t.Fatalf("ParseCoseSign1 token2: %v", err)
	}

	if parsed1.Protected.Kid == parsed2.Protected.Kid {
		t.Error("Expected different kids for different keys, got same")
	}
}

// Helper functions

func mustCreateSelfSignedCert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		URIs:         []*url.URL{{Scheme: "ans", Host: "v1.0.0.test.example.com"}},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return certDER
}

func computeKid(t *testing.T, key *ecdsa.PrivateKey) [4]byte {
	t.Helper()

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	h := sha256.Sum256(spki)
	var kid [4]byte
	copy(kid[:], h[:4])
	return kid
}
