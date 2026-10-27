package commerce

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestANSHost_StripsVersionLabels(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ans:// prefix with version labels",
			input: "ans://v1.0.8.seller.skybound-travel.com",
			want:  "seller.skybound-travel.com",
		},
		{
			name:  "ans:// prefix with v2 version",
			input: "ans://v2.1.authority.example.com",
			want:  "authority.example.com",
		},
		{
			name:  "ans:// prefix without version",
			input: "ans://seller.example.com",
			want:  "seller.example.com",
		},
		{
			name:  "no prefix with version labels",
			input: "v1.0.8.seller.x.com",
			want:  "seller.x.com",
		},
		{
			name:  "single label",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "version label only numeric segments",
			input: "v1.2.3.seller.example.com",
			want:  "seller.example.com",
		},
		{
			name:  "version with non-numeric stops stripping",
			input: "v1.2.foo.seller.example.com",
			want:  "foo.seller.example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "ans:// prefix only",
			input: "ans://",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ANSHost(tt.input)
			if got != tt.want {
				t.Errorf("ANSHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMandate_JSONFieldOrderAndFloatFormat(t *testing.T) {
	// CRITICAL: No captured live bytes exist (user-confirmed). Field order
	// reconstructed from Rust commerce/types.rs:24-38. The FIRST LIVE RUN is the
	// real validation of this wire-shape; a mismatch there is a wire-shape fix,
	// not a redesign.
	m := Mandate{
		MandateID:    "mandate-123",
		QuoteID:      "quote-456",
		SubjectANS:   "ans://buyer.example.com",
		AudienceANS:  "ans://v1.0.8.seller.example.com",
		Scope:        "commerce:purchase",
		MaxAmount:    1000,
		Currency:     "USD",
		NotBefore:    "2026-10-20T00:00:00Z",
		NotAfter:     "2026-10-20T23:59:59Z",
		JKT:          "jkt-abc",
		AuthorityANS: "ans://authority.example.com",
		Signature:    "sig-xyz",
	}

	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Golden string with fields in the exact order declared in the struct.
	// Go's json package renders integral float64 without trailing .0 (confirmed).
	want := `{"mandate_id":"mandate-123","quote_id":"quote-456","subject_ans":"ans://buyer.example.com","audience_ans":"ans://v1.0.8.seller.example.com","scope":"commerce:purchase","max_amount":1000,"currency":"USD","not_before":"2026-10-20T00:00:00Z","not_after":"2026-10-20T23:59:59Z","jkt":"jkt-abc","authority_ans":"ans://authority.example.com","signature":"sig-xyz"}`

	if string(got) != want {
		t.Errorf("JSON field order/format mismatch:\ngot:  %s\nwant: %s", string(got), want)
	}
}

func TestValidate_Rules(t *testing.T) {
	validMandate := &Mandate{
		MandateID:    "mandate-123",
		QuoteID:      "quote-456",
		SubjectANS:   "ans://buyer.example.com",
		AudienceANS:  "ans://v1.0.8.seller.example.com",
		Scope:        "commerce:purchase",
		MaxAmount:    1000,
		Currency:     "USD",
		NotBefore:    "2026-10-20T00:00:00Z",
		NotAfter:     "2026-10-20T23:59:59Z",
		JKT:          "jkt-abc",
		AuthorityANS: "ans://authority.example.com",
		Signature:    "sig-xyz",
	}

	validQuoteKey := QuoteKey{
		QuoteID:  "quote-456",
		Amount:   800,
		Currency: "USD",
	}

	tests := []struct {
		name          string
		mandate       *Mandate
		quoteKey      QuoteKey
		ourJKT        string
		sellerANS     string
		scopePrefix   string
		wantErrSubstr string
	}{
		{
			name:          "all valid",
			mandate:       validMandate,
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "",
		},
		{
			name: "audience host mismatch",
			mandate: &Mandate{
				AudienceANS: "ans://v1.different.com",
				Scope:       "commerce:purchase",
				JKT:         "jkt-abc",
				QuoteID:     "quote-456",
				MaxAmount:   1000,
				NotBefore:   "2026-10-20T00:00:00Z",
				NotAfter:    "2026-10-20T23:59:59Z",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "audience host",
		},
		{
			name: "scope not prefixed",
			mandate: &Mandate{
				AudienceANS: "ans://v1.seller.example.com",
				Scope:       "payment:purchase",
				JKT:         "jkt-abc",
				QuoteID:     "quote-456",
				MaxAmount:   1000,
				NotBefore:   "2026-10-20T00:00:00Z",
				NotAfter:    "2026-10-20T23:59:59Z",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "scope",
		},
		{
			name: "jkt mismatch",
			mandate: &Mandate{
				AudienceANS: "ans://v1.seller.example.com",
				Scope:       "commerce:purchase",
				JKT:         "wrong-jkt",
				QuoteID:     "quote-456",
				MaxAmount:   1000,
				NotBefore:   "2026-10-20T00:00:00Z",
				NotAfter:    "2026-10-20T23:59:59Z",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "jkt",
		},
		{
			name: "quote_id mismatch",
			mandate: &Mandate{
				AudienceANS: "ans://v1.seller.example.com",
				Scope:       "commerce:purchase",
				JKT:         "jkt-abc",
				QuoteID:     "wrong-quote",
				MaxAmount:   1000,
				NotBefore:   "2026-10-20T00:00:00Z",
				NotAfter:    "2026-10-20T23:59:59Z",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "quote_id",
		},
		{
			name: "amount exceeds max_amount",
			mandate: &Mandate{
				AudienceANS: "ans://v1.seller.example.com",
				Scope:       "commerce:purchase",
				JKT:         "jkt-abc",
				QuoteID:     "quote-456",
				MaxAmount:   500,
				NotBefore:   "2026-10-20T00:00:00Z",
				NotAfter:    "2026-10-20T23:59:59Z",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "exceeds max_amount",
		},
		{
			name: "malformed not_before",
			mandate: &Mandate{
				AudienceANS: "ans://v1.seller.example.com",
				Scope:       "commerce:purchase",
				JKT:         "jkt-abc",
				QuoteID:     "quote-456",
				MaxAmount:   1000,
				NotBefore:   "invalid-date",
				NotAfter:    "2026-10-20T23:59:59Z",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "not_before",
		},
		{
			name: "malformed not_after",
			mandate: &Mandate{
				AudienceANS: "ans://v1.seller.example.com",
				Scope:       "commerce:purchase",
				JKT:         "jkt-abc",
				QuoteID:     "quote-456",
				MaxAmount:   1000,
				NotBefore:   "2026-10-20T00:00:00Z",
				NotAfter:    "invalid-date",
			},
			quoteKey:      validQuoteKey,
			ourJKT:        "jkt-abc",
			sellerANS:     "ans://seller.example.com",
			scopePrefix:   "commerce:",
			wantErrSubstr: "not_after",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.mandate, tt.quoteKey, tt.ourJKT, tt.sellerANS, tt.scopePrefix)
			if tt.wantErrSubstr == "" {
				if err != nil {
					t.Errorf("Validate() returned error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() returned nil, want error containing %q", tt.wantErrSubstr)
				} else if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.wantErrSubstr)
				}
			}
		})
	}
}
