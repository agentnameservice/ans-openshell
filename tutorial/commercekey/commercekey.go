// Package commercekey provides P-256 commerce DPoP key management with RFC 7638 thumbprint support.
package commercekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// JwkPublic represents a P-256 public key in JWK format.
// Field order is critical for RFC 7638 thumbprint computation.
type JwkPublic struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Key wraps a P-256 ECDSA private key for commerce DPoP operations.
type Key struct {
	key *ecdsa.PrivateKey
}

// Load reads a P-256 commerce DPoP key from the COMMERCE_DPOP_KEY environment variable
// (if set) or from the file at the given path. The key must be in PKCS#8 PEM format.
// Environment variable takes precedence over file path.
func Load(path string) (*Key, error) {
	var pemData []byte

	// Check environment variable first
	if envPEM := os.Getenv("COMMERCE_DPOP_KEY"); envPEM != "" {
		pemData = []byte(envPEM)
	} else {
		// Read from file
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		pemData = data
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Parse PKCS#8 private key
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}

	// Assert *ecdsa.PrivateKey
	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not *ecdsa.PrivateKey")
	}

	// Assert P-256 curve
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, errors.New("key is not P-256")
	}

	return &Key{key: ecdsaKey}, nil
}

// PublicJWK returns the public key in JWK format.
// X and Y coordinates are base64url-encoded (no padding) 32-byte values.
func (k *Key) PublicJWK() JwkPublic {
	// Get uncompressed public key bytes (0x04 || X || Y)
	// For P-256: 1 byte prefix + 32 bytes X + 32 bytes Y = 65 bytes total
	ecdhPub, err := k.key.PublicKey.ECDH()
	if err != nil {
		panic(fmt.Sprintf("ECDH conversion: %v", err))
	}
	pubBytes := ecdhPub.Bytes()
	const p256UncompressedLen = 65 // 1 prefix + 32 X + 32 Y
	if len(pubBytes) != p256UncompressedLen {
		panic("unexpected public key length")
	}

	// Extract X and Y (skip the 0x04 prefix)
	xBytes := pubBytes[1:33]
	yBytes := pubBytes[33:p256UncompressedLen]

	return JwkPublic{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

// JKT returns the RFC 7638 thumbprint of the public key.
// The canonical JSON is built with exact field order: crv, kty, x, y (lexicographic).
// Returns base64url-encoded (no padding) SHA-256 hash.
func (k *Key) JKT() string {
	jwk := k.PublicJWK()

	// RFC 7638: canonical JSON with lexicographic key order
	// CRITICAL: Must use fmt.Sprintf, not encoding/json, to guarantee field order
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)

	// SHA-256 hash
	hash := sha256.Sum256([]byte(canonical))

	// Base64url-encode without padding
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Signer returns the underlying ECDSA private key for DPoP token signing (Task 2).
func (k *Key) Signer() *ecdsa.PrivateKey {
	return k.key
}
