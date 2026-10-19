// Package provenance defines the signed-batch format the ANS OpenShell
// hydrator attaches to Trust Index observation imports: a compact ES256 JWS
// whose claims bind the SHA-256 of the exact request body, the observation
// count, the signing time and the producer's identifier, with the signer's
// certificate in the x5c header. It is a proposal pending Trust Index support
// and lives outside internal/ so a Trust Index can import Verify as is.
package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/pemkeys"
)

// Protected header values of a signed batch.
const (
	BatchSignatureType = "ans-observations+jws"
	BatchSignatureAlg  = "ES256"
)

const (
	es256SignatureLen  = 64
	es256CoordinateLen = 32
	jwsPartCount       = 3
)

// ErrMalformedSignature reports a batch signature whose structure, header or
// claims cannot be used.
var ErrMalformedSignature = errors.New("provenance: malformed batch signature")

// ErrBadSignature reports a well-formed batch signature that does not verify
// or does not cover the given body.
var ErrBadSignature = errors.New("provenance: batch signature does not verify")

// SignedBatchClaims is the JWS payload: the base64url SHA-256 of the request
// body, the observation count, the signing time and the signer's identifier.
type SignedBatchClaims struct {
	BodySHA256 string `json:"body_sha256"`
	Count      int    `json:"count"`
	IssuedAt   int64  `json:"iat"`
	AIMID      string `json:"aim_id,omitempty"`
}

type jwsHeader struct {
	Typ string   `json:"typ"`
	Alg string   `json:"alg"`
	X5C []string `json:"x5c"`
}

// BatchSigner signs one import body. Signer implements it over an in-process
// or external P-256 key; a fake implements it in tests.
type BatchSigner interface {
	Sign(body []byte, iat time.Time, count int, aimID string) (string, error)
}

// Signer signs batches with a P-256 key reachable through crypto.Signer, so the
// key may live in a file, Vault Transit or an HSM, and the X.509 certificate
// that carries its public key.
type Signer struct {
	key    crypto.Signer
	cert   *x509.Certificate
	header string
}

// NewSigner binds key to cert. The key must be ECDSA on P-256 and must match
// the certificate's public key.
func NewSigner(key crypto.Signer, cert *x509.Certificate) (*Signer, error) {
	if key == nil || cert == nil {
		return nil, errors.New("provenance: key and certificate are required")
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("provenance: key: not an ECDSA P-256 key")
	}
	if !pub.Equal(cert.PublicKey) {
		return nil, errors.New("provenance: certificate public key does not match the signing key")
	}
	header, err := json.Marshal(jwsHeader{
		Typ: BatchSignatureType,
		Alg: BatchSignatureAlg,
		X5C: []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	})
	if err != nil {
		return nil, fmt.Errorf("provenance: encode jws header: %w", err)
	}
	return &Signer{key: key, cert: cert, header: base64.RawURLEncoding.EncodeToString(header)}, nil
}

// NewPEMSigner parses a PEM-encoded P-256 private key (PKCS#8 or SEC1) and the
// PEM-encoded certificate for it.
func NewPEMSigner(keyPEM, certPEM []byte) (*Signer, error) {
	key, err := pemkeys.ParseP256PrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("provenance: key: %w", err)
	}
	cert, err := pemkeys.ParseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("provenance: certificate: %w", err)
	}
	return NewSigner(key, cert)
}

// Certificate returns the certificate sent in the x5c header.
func (s *Signer) Certificate() *x509.Certificate {
	return s.cert
}

// Sign returns a compact JWS whose claims bind body, count and aimID at iat.
func (s *Signer) Sign(body []byte, iat time.Time, count int, aimID string) (string, error) {
	payload, err := json.Marshal(SignedBatchClaims{
		BodySHA256: bodyDigest(body),
		Count:      count,
		IssuedAt:   iat.Unix(),
		AIMID:      aimID,
	})
	if err != nil {
		return "", fmt.Errorf("provenance: encode jws claims: %w", err)
	}
	signingInput := s.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	der, err := s.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("provenance: sign batch: %w", err)
	}
	sig, err := derToP1363(der)
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// derToP1363 converts the ASN.1 signature a crypto.Signer returns into the
// fixed-width R||S form JWS uses.
func derToP1363(der []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, errors.New("provenance: signer returned a malformed ASN.1 signature")
	}
	if parsed.R.BitLen() > es256CoordinateLen*8 || parsed.S.BitLen() > es256CoordinateLen*8 {
		return nil, errors.New("provenance: signature coordinates exceed P-256")
	}
	sig := make([]byte, es256SignatureLen)
	parsed.R.FillBytes(sig[:es256CoordinateLen])
	parsed.S.FillBytes(sig[es256CoordinateLen:])
	return sig, nil
}

// Verify checks a compact JWS produced by Sign against body: the structure,
// typ and alg, the x5c leaf certificate's P-256 key, the signature and the
// body digest. It returns the claims and the leaf certificate. Trusting the
// certificate, binding aim_id to it and judging the claims' freshness are the
// caller's decisions.
func Verify(jws string, body []byte) (*SignedBatchClaims, *x509.Certificate, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != jwsPartCount {
		return nil, nil, fmt.Errorf("%w: expected %d parts, got %d", ErrMalformedSignature, jwsPartCount, len(parts))
	}
	cert, err := decodeHeader(parts[0])
	if err != nil {
		return nil, nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, fmt.Errorf("%w: x5c certificate key is not ECDSA P-256", ErrMalformedSignature)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != es256SignatureLen {
		return nil, nil, fmt.Errorf("%w: signature is not %d base64url bytes", ErrMalformedSignature, es256SignatureLen)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:es256CoordinateLen])
	sv := new(big.Int).SetBytes(sig[es256CoordinateLen:])
	if !ecdsa.Verify(pub, digest[:], r, sv) {
		return nil, nil, ErrBadSignature
	}
	claims, err := decodeClaims(parts[1])
	if err != nil {
		return nil, nil, err
	}
	if claims.BodySHA256 != bodyDigest(body) {
		return nil, nil, fmt.Errorf("%w: body digest mismatch", ErrBadSignature)
	}
	return claims, cert, nil
}

func decodeHeader(encoded string) (*x509.Certificate, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url", ErrMalformedSignature)
	}
	var header jwsHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON", ErrMalformedSignature)
	}
	if header.Alg != BatchSignatureAlg {
		return nil, fmt.Errorf("%w: alg %q, want %s", ErrMalformedSignature, header.Alg, BatchSignatureAlg)
	}
	if header.Typ != BatchSignatureType {
		return nil, fmt.Errorf("%w: typ %q, want %s", ErrMalformedSignature, header.Typ, BatchSignatureType)
	}
	if len(header.X5C) == 0 {
		return nil, fmt.Errorf("%w: x5c is empty", ErrMalformedSignature)
	}
	der, err := base64.StdEncoding.DecodeString(header.X5C[0])
	if err != nil {
		return nil, fmt.Errorf("%w: x5c[0] is not base64", ErrMalformedSignature)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: x5c[0]: %w", ErrMalformedSignature, err)
	}
	return cert, nil
}

func decodeClaims(encoded string) (*SignedBatchClaims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: claims are not base64url", ErrMalformedSignature)
	}
	var claims SignedBatchClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims are not JSON", ErrMalformedSignature)
	}
	return &claims, nil
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
