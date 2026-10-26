package commerce

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrMandateInvalid is returned when mandate validation fails.
var ErrMandateInvalid = errors.New("mandate invalid")

// Mandate represents a commerce mandate with fields in the exact order
// matching the Rust commerce/types.rs:24-38. Field order is critical for
// byte-exact JSON reconstruction when validating seller-forwarded mandates.
type Mandate struct {
	MandateID    string  `json:"mandate_id"`
	QuoteID      string  `json:"quote_id"`
	SubjectANS   string  `json:"subject_ans"`
	AudienceANS  string  `json:"audience_ans"`
	Scope        string  `json:"scope"`
	MaxAmount    float64 `json:"max_amount"`
	Currency     string  `json:"currency"`
	NotBefore    string  `json:"not_before"`
	NotAfter     string  `json:"not_after"`
	JKT          string  `json:"jkt"`
	AuthorityANS string  `json:"authority_ans"`
	Signature    string  `json:"signature"`
}

// QuoteKey contains the quote-related fields used in validation.
type QuoteKey struct {
	QuoteID  string
	Amount   float64
	Currency string
}

// ANSHost strips the ans:// prefix (if present), removes version labels from
// the first label if it matches ^v\d, and drops all subsequent all-digit labels.
// Mirrors Rust mandate.rs:86-111.
//
// Examples:
//   - "ans://v1.0.8.seller.skybound-travel.com" -> "seller.skybound-travel.com"
//   - "ans://v2.1.authority.example.com"        -> "authority.example.com"
//   - "ans://seller.example.com"                -> "seller.example.com"
//   - "v1.0.8.seller.x.com"                     -> "seller.x.com"
func ANSHost(ansURI string) string {
	// Strip ans:// prefix if present
	s := strings.TrimPrefix(ansURI, "ans://")

	// Split on dots
	labels := strings.Split(s, ".")
	if len(labels) == 0 {
		return s
	}

	// Check if the first label starts with 'v' followed by a digit
	firstLabel := labels[0]
	if len(firstLabel) >= 2 && firstLabel[0] == 'v' && firstLabel[1] >= '0' && firstLabel[1] <= '9' {
		// Drop the first label and any subsequent all-digit labels
		i := 1
		for i < len(labels) {
			// Check if the label is all digits
			if !isAllDigits(labels[i]) {
				break
			}
			i++
		}
		labels = labels[i:]
	}

	return strings.Join(labels, ".")
}

// isAllDigits returns true if s is non-empty and contains only ASCII digits.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Validate performs six validation checks on the mandate against the quote key
// and caller context. Mirrors Rust mandate.rs:114-170.
//
// Checks:
//  1. ANSHost(m.AudienceANS) == ANSHost(sellerANS) and both non-empty
//  2. m.Scope starts with scopePrefix
//  3. m.JKT == ourJKT
//  4. m.QuoteID == qk.QuoteID
//  5. qk.Amount <= m.MaxAmount
//  6. m.NotBefore and m.NotAfter both parse as RFC3339
func Validate(m *Mandate, qk QuoteKey, ourJKT, sellerANS, scopePrefix string) error {
	// Check 1: audience host must match seller host
	audienceHost := ANSHost(m.AudienceANS)
	sellerHost := ANSHost(sellerANS)
	if audienceHost == "" || sellerHost == "" || audienceHost != sellerHost {
		return fmt.Errorf("%w: audience host %q does not match seller host %q",
			ErrMandateInvalid, audienceHost, sellerHost)
	}

	// Check 2: scope must start with the expected prefix
	if !strings.HasPrefix(m.Scope, scopePrefix) {
		return fmt.Errorf("%w: scope %q does not start with prefix %q",
			ErrMandateInvalid, m.Scope, scopePrefix)
	}

	// Check 3: jkt must match our jkt
	if m.JKT != ourJKT {
		return fmt.Errorf("%w: jkt %q does not match expected %q",
			ErrMandateInvalid, m.JKT, ourJKT)
	}

	// Check 4: quote_id must match
	if m.QuoteID != qk.QuoteID {
		return fmt.Errorf("%w: quote_id %q does not match expected %q",
			ErrMandateInvalid, m.QuoteID, qk.QuoteID)
	}

	// Check 5: amount must not exceed max_amount
	if qk.Amount > m.MaxAmount {
		return fmt.Errorf("%w: amount %v exceeds max_amount %v",
			ErrMandateInvalid, qk.Amount, m.MaxAmount)
	}

	// Check 6: not_before and not_after must be valid RFC3339 timestamps
	if _, err := time.Parse(time.RFC3339, m.NotBefore); err != nil {
		return fmt.Errorf("%w: not_before %q is not valid RFC3339: %w",
			ErrMandateInvalid, m.NotBefore, err)
	}

	if _, err := time.Parse(time.RFC3339, m.NotAfter); err != nil {
		return fmt.Errorf("%w: not_after %q is not valid RFC3339: %w",
			ErrMandateInvalid, m.NotAfter, err)
	}

	return nil
}
