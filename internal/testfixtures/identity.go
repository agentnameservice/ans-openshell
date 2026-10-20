package testfixtures

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"
)

const (
	certValidBefore = time.Hour
	certValidAfter  = 24 * time.Hour
)

// Identity is a registered agent's identity material: a P-256 key, the
// self-signed identity certificate carrying the agent's ans:// URI SAN, and the
// registration facts a status token vouches for. Trust in the certificate comes
// from the status token's fingerprint, not from a chain.
type Identity struct {
	Key         *ecdsa.PrivateKey
	CertDER     []byte
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint [sha256.Size]byte
	AgentID     string
	AnsName     string
}

// NewIdentity mints an identity for agentID registered under ansName with a
// certificate valid from one hour ago until 24 hours from now.
func NewIdentity(agentID, ansName string) (*Identity, error) {
	now := time.Now()
	return NewIdentityValid(agentID, ansName, now.Add(-certValidBefore), now.Add(certValidAfter))
}

// MustNewIdentity is NewIdentity that panics on error.
func MustNewIdentity(agentID, ansName string) *Identity {
	id, err := NewIdentity(agentID, ansName)
	if err != nil {
		panic(err)
	}
	return id
}

// NewIdentityValid is NewIdentity with an explicit certificate validity period.
// ansName becomes the certificate's URI SAN verbatim, so a test can mint a
// certificate whose SAN disagrees with the registration.
func NewIdentityValid(agentID, ansName string, notBefore, notAfter time.Time) (*Identity, error) {
	return newIdentityValid(rand.Reader, agentID, ansName, notBefore, notAfter)
}

func newIdentityValid(random io.Reader, agentID, ansName string, notBefore, notAfter time.Time) (*Identity, error) {
	if agentID == "" {
		return nil, errors.New("agent id must not be empty")
	}
	san, err := url.Parse(ansName)
	if err != nil {
		return nil, fmt.Errorf("parse ans name: %w", err)
	}
	key, err := newP256Key(random)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{san},
	}
	der, err := x509.CreateCertificate(random, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create identity certificate: %w", err)
	}
	keyPEM, err := PrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Key:         key,
		CertDER:     der,
		CertPEM:     CertificatePEM(der),
		KeyPEM:      keyPEM,
		Fingerprint: sha256.Sum256(der),
		AgentID:     agentID,
		AnsName:     ansName,
	}, nil
}
