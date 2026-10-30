package commerce

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-openshell/tutorial/commercekey"
)

// loadTestKey loads a fixed test key for deterministic tests.
func loadTestKey(t *testing.T) *commercekey.Key {
	t.Helper()
	tempPEM := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEjRWeJA0VniQNFZ4
kDRWeJA0VniQNFZ4kDRWeJA0VnihRANCAAR7VJCMjvKZnHnHvS3xdKaPXM5pHvEJ
qxLJH8nppWLHVdJvxMlvmJNLcQh3PRe6mXF1wnTvzWFhZj0c+0/qrjPd
-----END PRIVATE KEY-----`

	tmpfile := t.TempDir() + "/test.pem"
	if err := os.WriteFile(tmpfile, []byte(tempPEM), 0600); err != nil {
		t.Fatal(err)
	}

	key, err := commercekey.Load(tmpfile)
	if err != nil {
		t.Fatalf("failed to load test key: %v", err)
	}
	return key
}

func TestMintDPoP_ExactHeaderAndClaims(t *testing.T) {
	key := loadTestKey(t)

	// Mint DPoP token
	jws, err := MintDPoP(key, "https://seller.skybound-travel.com/mcp/", "q-1", 1_000_000, "jti-1")
	if err != nil {
		t.Fatalf("MintDPoP failed: %v", err)
	}

	// Split into 3 parts
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	// Check raw header starts with exact string
	expectedPrefix := `{"typ":"dpop+jwt","alg":"ES256","jwk":{`
	if !strings.HasPrefix(string(headerJSON), expectedPrefix) {
		t.Errorf("header does not start with expected prefix\ngot:  %s\nwant: %s...", string(headerJSON)[:len(expectedPrefix)], expectedPrefix)
	}

	// Decode header into map to check keys
	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerJSON, &headerMap); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	// Check exactly 3 keys: typ, alg, jwk
	if len(headerMap) != 3 {
		t.Errorf("header has %d keys, want 3", len(headerMap))
	}
	if _, ok := headerMap["typ"]; !ok {
		t.Error("header missing 'typ' key")
	}
	if _, ok := headerMap["alg"]; !ok {
		t.Error("header missing 'alg' key")
	}
	if _, ok := headerMap["jwk"]; !ok {
		t.Error("header missing 'jwk' key")
	}

	// Check values
	if headerMap["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v, want 'dpop+jwt'", headerMap["typ"])
	}
	if headerMap["alg"] != "ES256" {
		t.Errorf("alg = %v, want 'ES256'", headerMap["alg"])
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	// Check claims
	if claims["htm"] != "POST" {
		t.Errorf("htm = %v, want 'POST'", claims["htm"])
	}
	if claims["htu"] != "https://seller.skybound-travel.com/mcp/" {
		t.Errorf("htu = %v, want 'https://seller.skybound-travel.com/mcp/'", claims["htu"])
	}
	// iat is float64 in JSON
	if iat, ok := claims["iat"].(float64); !ok || int64(iat) != 1_000_000 {
		t.Errorf("iat = %v, want 1000000", claims["iat"])
	}
	if claims["jti"] != "jti-1" {
		t.Errorf("jti = %v, want 'jti-1'", claims["jti"])
	}

	// Check ath = base64url(sha256("q-1"))
	h := sha256.Sum256([]byte("q-1"))
	expectedAth := base64.RawURLEncoding.EncodeToString(h[:])
	if claims["ath"] != expectedAth {
		t.Errorf("ath = %v, want %v", claims["ath"], expectedAth)
	}
}

func TestMintDPoP_SignatureVerifiesSingleHash(t *testing.T) {
	key := loadTestKey(t)

	// Mint DPoP token
	jws, err := MintDPoP(key, "https://seller.skybound-travel.com/mcp/", "q-1", 1_000_000, "jti-1")
	if err != nil {
		t.Fatalf("MintDPoP failed: %v", err)
	}

	// Split into parts
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Recompute signing input
	signingInput := parts[0] + "." + parts[1]

	// Hash once
	digest := sha256.Sum256([]byte(signingInput))

	// Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	// Check signature is 64 bytes
	if len(sigBytes) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sigBytes))
	}

	// Extract r and s (32 bytes each)
	r := new(big.Int).SetBytes(sigBytes[0:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	// Verify with public key
	pub := key.Signer().Public().(*ecdsa.PublicKey)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("signature verification failed (single hash)")
	}

	// Verify that double-hash would fail (to ensure we're doing single hash)
	doubleDigest := sha256.Sum256(digest[:])
	if ecdsa.Verify(pub, doubleDigest[:], r, s) {
		t.Error("signature verified with double hash - implementation is wrong!")
	}
}

func TestMintDPoP_DistinctQuoteIDsDistinctAth(t *testing.T) {
	key := loadTestKey(t)

	htu := "https://seller.skybound-travel.com/mcp/"

	// Mint with different quote IDs
	jws1, err := MintDPoP(key, htu, "quote-1", 1_000_000, "jti-1")
	if err != nil {
		t.Fatalf("MintDPoP(quote-1) failed: %v", err)
	}

	jws2, err := MintDPoP(key, htu, "quote-2", 1_000_000, "jti-2")
	if err != nil {
		t.Fatalf("MintDPoP(quote-2) failed: %v", err)
	}

	// Extract ath from both
	extractAth := func(jws string) string {
		parts := strings.Split(jws, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]interface{}
		json.Unmarshal(payloadJSON, &claims)
		return claims["ath"].(string)
	}

	ath1 := extractAth(jws1)
	ath2 := extractAth(jws2)

	if ath1 == ath2 {
		t.Error("distinct quote IDs produced identical ath values")
	}

	// Verify htu is identical
	extractHtu := func(jws string) string {
		parts := strings.Split(jws, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]interface{}
		json.Unmarshal(payloadJSON, &claims)
		return claims["htu"].(string)
	}

	if extractHtu(jws1) != htu || extractHtu(jws2) != htu {
		t.Error("htu not preserved verbatim")
	}
}
