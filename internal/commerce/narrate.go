package commerce

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// jwsSegments is the number of dot-separated parts in a compact JWS
// (header.payload.signature).
const jwsSegments = 3

// DPoPClaims is the decoded, display-facing view of a DPoP proof's claims.
type DPoPClaims struct {
	Htm string
	Htu string
	Jti string
	Iat int64
	Ath string
}

// DecodeDPoPClaims parses a compact DPoP JWS ("header.payload.signature") and
// returns its claims. It decodes ONLY (no signature verification) — it exists
// for observability/narration of a proof this process just minted, not for
// trust decisions. The payload is the middle base64url (RawURL) segment,
// unmarshaled into the same dpopClaims shape MintDPoP emits.
func DecodeDPoPClaims(proof string) (DPoPClaims, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != jwsSegments {
		return DPoPClaims{}, fmt.Errorf("malformed DPoP JWS: expected %d segments, got %d", jwsSegments, len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return DPoPClaims{}, fmt.Errorf("decode DPoP payload: %w", err)
	}
	var c dpopClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return DPoPClaims{}, fmt.Errorf("unmarshal DPoP claims: %w", err)
	}
	return DPoPClaims(c), nil
}

// SummarizeMandate unmarshals the authority's raw mandate JSON into the typed
// Mandate for display. It does not re-validate the mandate (GetOrFetch already
// did); it exists so a narrator can show the scope, max_amount, jkt binding,
// and parties of the mandate that was attached.
func SummarizeMandate(raw []byte) (Mandate, error) {
	var m Mandate
	if err := json.Unmarshal(raw, &m); err != nil {
		return Mandate{}, fmt.Errorf("unmarshal mandate: %w", err)
	}
	return m, nil
}
