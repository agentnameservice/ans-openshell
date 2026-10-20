// Package identity holds the ANS identities the middleware signs as: a private
// key and identity certificate behind a Signer, and the receipt and status
// token an ArtifactSource keeps current. A Registry loads them from
// configuration and fails closed on anything it cannot prove at startup.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/agentnameservice/ans-sdk-go/pop"

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
