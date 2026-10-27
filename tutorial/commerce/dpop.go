// Package commerce provides commerce DPoP token minting for AP2 commerce protocol.
package commerce

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/ans-openshell/tutorial/commercekey"
)

const (
	// es256SignatureLen is the length of an ES256 signature in raw R‖S format (32 bytes each).
	es256SignatureLen = 64
)

// dpopHeader is the DPoP JWT header with exact field order: typ, alg, jwk.
// Field order is load-bearing for byte-exact commerce protocol compliance.
type dpopHeader struct {
	Typ string                `json:"typ"`
	Alg string                `json:"alg"`
	Jwk commercekey.JwkPublic `json:"jwk"`
}

// dpopClaims is the DPoP JWT claims with exact field order: htm, htu, jti, iat, ath.
// Field order is load-bearing for byte-exact commerce protocol compliance.
type dpopClaims struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Ath string `json:"ath"`
}

// MintDPoP creates a byte-exact RFC 9449 DPoP token for the AP2 commerce protocol.
// Returns a compact JWS in the form "header.payload.signature".
//
// Parameters:
//   - key: P-256 commerce DPoP key
//   - htu: HTTPs URI of the target resource (preserved verbatim, including trailing slash)
//   - quoteID: Commerce quote identifier for access token hash binding
//   - iat: Issued-at timestamp (Unix seconds)
//   - jti: Unique JWT ID for replay prevention
//
// The signature is ES256 (ECDSA P-256 SHA-256) over a SINGLE sha256 hash of the
// signing input, serialized as raw R‖S (64 bytes, NOT ASN.1 DER).
func MintDPoP(key *commercekey.Key, htu, quoteID string, iat int64, jti string) (string, error) {
	// Build header with exact field order: typ, alg, jwk
	header := dpopHeader{
		Typ: "dpop+jwt",
		Alg: "ES256",
		Jwk: key.PublicJWK(),
	}

	// Compute access token hash (ath): base64url(sha256(quoteID))
	quoteHash := sha256.Sum256([]byte(quoteID))
	ath := base64.RawURLEncoding.EncodeToString(quoteHash[:])

	// Build claims with exact field order: htm, htu, jti, iat, ath
	claims := dpopClaims{
		Htm: "POST",
		Htu: htu, // preserved verbatim (trailing slash, etc.)
		Jti: jti,
		Iat: iat,
		Ath: ath,
	}

	// Marshal header and claims to JSON
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	// Base64url-encode (no padding)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Construct signing input
	signingInput := headerB64 + "." + payloadB64

	// Sign with ECDSA P-256: SINGLE sha256 hash of signing input
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key.Signer(), digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// Serialize signature as raw R‖S (64 bytes): each coordinate big-endian, left-padded to 32 bytes
	// CRITICAL: NOT ASN.1 DER. The seller expects raw R‖S for ES256.
	sig := make([]byte, es256SignatureLen)
	r.FillBytes(sig[0:32]) // big-endian, left-padded
	s.FillBytes(sig[32:es256SignatureLen])
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Return compact JWS
	return signingInput + "." + sigB64, nil
}
