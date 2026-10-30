// Package identity holds the ANS identities the middleware signs as: a private
// key and identity certificate behind a Signer, and the receipt and status
// token an ArtifactSource keeps current. A Registry loads them from
// configuration and fails closed on anything it cannot prove at startup.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify"

	"github.com/agentnameservice/ans-openshell/internal/pemkeys"
)

// Signer mints the DPoP proof for one outbound request. It is the seam for a
// key held outside the process (Vault Transit, an HSM).
type Signer interface {
	// Sign returns a compact DPoP proof binding the HTTP method, the target
	// URL (normalized to htu by the signer) and the SHA-256 digest of the
	// request content, which is the digest of the empty string for a bodyless
	// request.
	Sign(ctx context.Context, method, rawURL string, contentDigest [sha256.Size]byte) (string, error)
}

// popSigner adapts the SDK's pop.Signer to Signer.
type popSigner struct {
	signer *pop.Signer
}

func (p popSigner) Sign(ctx context.Context, method, rawURL string, contentDigest [sha256.Size]byte) (string, error) {
	return p.signer.Sign(ctx, method, rawURL, pop.WithContentDigest(contentDigest))
}

const (
	pemTypePKCS8 = "PRIVATE KEY"
	pemTypeSEC1  = "EC PRIVATE KEY"
)

// NewPEMSigner builds a Signer from a PEM-encoded P-256 private key (PKCS#8 or
// SEC1) and the PEM-encoded identity certificate that binds its public key. The
// parsed certificate is returned so the caller can check its ans:// URI SAN.
func NewPEMSigner(keyPEM, certPEM []byte) (Signer, *x509.Certificate, error) {
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("private key: %w", err)
	}
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate: %w", err)
	}
	signer, err := pop.NewSigner(key, cert.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("signer: %w", err)
	}
	return popSigner{signer: signer}, cert, nil
}

func parsePrivateKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	return pemkeys.ParseP256PrivateKey(b)
}

func parseCertificatePEM(b []byte) (*x509.Certificate, error) {
	return pemkeys.ParseCertificate(b)
}

// NewSelfSignedSigner generates an ephemeral P-256 key and a self-signed
// certificate with the ANS name as the sole URI SAN, returning a Signer that
// signs with that key. The certificate is valid for 24 hours. This is intended
// for dev-mode or demo scenarios where an identity does not have a real
// certificate from the ANS transparency log.
func NewSelfSignedSigner(ansName string) (Signer, *ecdsa.PrivateKey, *x509.Certificate, error) {
	// Validate ansName
	if _, err := verify.ParseAnsName(ansName); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid ANS name: %w", err)
	}

	// Parse ansName as a URL for the cert URI SAN
	parsedURL, err := url.Parse(ansName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse ANS name as URL: %w", err)
	}

	// Generate ephemeral P-256 key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	// Generate random serial number (128 bits)
	const serialBits = 128
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	// Build certificate template with 24h validity
	const validityHours = 24
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now.Add(-1 * time.Minute), // 1 minute skew tolerance
		NotAfter:              now.Add(validityHours * time.Hour),
		URIs:                  []*url.URL{parsedURL},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	// Create the signer
	popSgn, err := pop.NewSigner(key, certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create signer: %w", err)
	}

	return popSigner{signer: popSgn}, key, cert, nil
}
