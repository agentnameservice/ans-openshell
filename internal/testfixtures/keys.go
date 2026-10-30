// Package testfixtures mints the material an ANS deployment normally receives
// from a registration authority and a transparency log: P-256 identity keys and
// certificates, status tokens, receipts and root keys, plus a fake
// transparency-log HTTP server. It is a non-test package so the repository's
// tests and demo programs can share it. Constructors return errors and have
// Must variants that panic; minting functions panic only when the random
// source or an encoder fails on data the package produced itself, which no
// input can provoke.
package testfixtures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/agentnameservice/ans-openshell/internal/selfsign"
)

const (
	pemTypePKCS8       = "PRIVATE KEY"
	pemTypeCertificate = "CERTIFICATE"
)

// NewP256Key generates a fresh ECDSA P-256 private key.
func NewP256Key() (*ecdsa.PrivateKey, error) {
	return newP256Key(rand.Reader)
}

func newP256Key(random io.Reader) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	return key, nil
}

// PrivateKeyPEM encodes key as a PKCS#8 "PRIVATE KEY" PEM block.
func PrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: der}), nil
}

// CertificatePEM encodes a DER certificate as a "CERTIFICATE" PEM block.
func CertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// kidFor derives the SDK's 4-byte key identifier from DER-encoded SPKI.
// It delegates to selfsign.KidFromSPKI for the shared kid computation logic.
func kidFor(spkiDER []byte) [selfsign.KidLen]byte {
	return selfsign.KidFromSPKI(spkiDER)
}

// must panics on an error from encoding or signing data this package built
// itself; such a failure is a broken library, not bad input.
func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("testfixtures: %v", err))
	}
}
