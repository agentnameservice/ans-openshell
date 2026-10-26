package commercekey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-openshell/internal/commercekey"
)

func TestLoad_FileAndEnvShadow(t *testing.T) {
	// Generate a P-256 key, marshal PKCS#8 PEM, write to a temp file.
	fileKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fileKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(fileKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	fileKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: fileKeyPKCS8})

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")
	if err := os.WriteFile(keyPath, fileKeyPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Load from file (no env var set)
	k, err := commercekey.Load(keyPath)
	if err != nil {
		t.Fatalf("Load(file): %v", err)
	}

	jwk := k.PublicJWK()
	if jwk.Kty != "EC" {
		t.Errorf("PublicJWK().Kty = %q, want EC", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("PublicJWK().Crv = %q, want P-256", jwk.Crv)
	}
	if len(jwk.X) != 43 {
		t.Errorf("PublicJWK().X length = %d, want 43", len(jwk.X))
	}
	if len(jwk.Y) != 43 {
		t.Errorf("PublicJWK().Y length = %d, want 43", len(jwk.Y))
	}
	if strings.Contains(jwk.X, "=") {
		t.Errorf("PublicJWK().X contains padding '=', want no padding")
	}
	if strings.Contains(jwk.Y, "=") {
		t.Errorf("PublicJWK().Y contains padding '=', want no padding")
	}

	// Generate a different key for the env var
	envKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey (env): %v", err)
	}
	envKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(envKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (env): %v", err)
	}
	envKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: envKeyPKCS8})

	// Set COMMERCE_DPOP_KEY env var to the different key
	t.Setenv("COMMERCE_DPOP_KEY", string(envKeyPEM))

	// Load should now use env key, even with nonexistent path
	kEnv, err := commercekey.Load("/no/such/path")
	if err != nil {
		t.Fatalf("Load(env): %v", err)
	}

	// Verify the loaded key matches the env key, not the file key
	envJwk := kEnv.PublicJWK()
	// Compare the public key coordinates using elliptic.Marshal
	envPubBytes := elliptic.Marshal(envKey.Curve, envKey.PublicKey.X, envKey.PublicKey.Y) //nolint:staticcheck // Test needs to verify correct key loaded
	expectedEnvX := base64.RawURLEncoding.EncodeToString(envPubBytes[1:33])

	if envJwk.X != expectedEnvX {
		t.Errorf("env key X mismatch: got %q, want %q", envJwk.X, expectedEnvX)
	}
}

func TestJKT_CanonicalOrderAndLength(t *testing.T) {
	// Use a fixed scalar to create a deterministic key
	scalar := new(big.Int).SetBytes([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	})

	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(scalar.Bytes()) //nolint:staticcheck // Test needs deterministic key generation

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: scalar,
	}

	// Marshal to PKCS#8 PEM and create a temp file
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "fixed-key.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	k, err := commercekey.Load(keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	jwk := k.PublicJWK()
	jkt := k.JKT()

	// Compute JKT independently from PublicJWK().X / .Y
	// RFC 7638 requires lexicographic order: crv, kty, x, y
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	hash := sha256.Sum256([]byte(canonical))
	expectedJKT := base64.RawURLEncoding.EncodeToString(hash[:])

	if jkt != expectedJKT {
		t.Errorf("JKT() = %q, want %q", jkt, expectedJKT)
	}
	if len(jkt) != 43 {
		t.Errorf("JKT() length = %d, want 43", len(jkt))
	}
	if strings.Contains(jkt, "=") {
		t.Errorf("JKT() contains padding '=', want no padding")
	}
}

func TestLoad_MissingKeyErrors(t *testing.T) {
	// Ensure COMMERCE_DPOP_KEY is unset
	t.Setenv("COMMERCE_DPOP_KEY", "")

	_, err := commercekey.Load("/nonexistent/k.pem")
	if err == nil {
		t.Error("Load(/nonexistent/k.pem) succeeded, want error")
	}
}

func TestLoad_InvalidPEM(t *testing.T) {
	t.Setenv("COMMERCE_DPOP_KEY", "not a valid PEM")

	_, err := commercekey.Load("/no/such/path")
	if err == nil {
		t.Error("Load with invalid PEM succeeded, want error")
	}
	if !strings.Contains(err.Error(), "decode PEM") {
		t.Errorf("error = %v, want 'decode PEM' error", err)
	}
}

func TestLoad_NotECDSAKey(t *testing.T) {
	// Create an RSA key instead of ECDSA
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa-key.pem")

	// Write a simple invalid PKCS#8 structure (not a real key)
	badPKCS8 := []byte{0x01, 0x02, 0x03, 0x04}
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: badPKCS8})
	if err := os.WriteFile(keyPath, badPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := commercekey.Load(keyPath)
	if err == nil {
		t.Error("Load with invalid PKCS#8 succeeded, want error")
	}
	if !strings.Contains(err.Error(), "parse PKCS#8") {
		t.Errorf("error = %v, want 'parse PKCS#8' error", err)
	}
}

func TestSigner(t *testing.T) {
	// Generate a key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	keyPKCS8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPKCS8})

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	k, err := commercekey.Load(keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	signer := k.Signer()
	if signer == nil {
		t.Fatal("Signer() returned nil")
	}
	if signer.Curve != elliptic.P256() {
		t.Errorf("Signer().Curve = %v, want P-256", signer.Curve)
	}
}
