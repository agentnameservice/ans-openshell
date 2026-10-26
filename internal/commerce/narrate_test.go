package commerce

import (
	"encoding/json"
	"testing"
)

func TestDecodeDPoPClaims_RoundTrip(t *testing.T) {
	key := loadTestKey(t)
	const (
		htu     = "https://seller.skybound-travel.com/mcp/"
		quoteID = "demo-quote-001"
		jti     = "jti-abc"
		iat     = int64(1_700_000_000)
	)
	proof, err := MintDPoP(key, htu, quoteID, iat, jti)
	if err != nil {
		t.Fatalf("MintDPoP: %v", err)
	}

	claims, err := DecodeDPoPClaims(proof)
	if err != nil {
		t.Fatalf("DecodeDPoPClaims: %v", err)
	}
	if claims.Htm != "POST" {
		t.Errorf("htm = %q, want POST", claims.Htm)
	}
	if claims.Htu != htu {
		t.Errorf("htu = %q, want %q", claims.Htu, htu)
	}
	if claims.Jti != jti {
		t.Errorf("jti = %q, want %q", claims.Jti, jti)
	}
	if claims.Iat != iat {
		t.Errorf("iat = %d, want %d", claims.Iat, iat)
	}
	if claims.Ath == "" {
		t.Error("ath is empty; want base64url(sha256(quote_id))")
	}
}

func TestDecodeDPoPClaims_Malformed(t *testing.T) {
	if _, err := DecodeDPoPClaims("not-a-jws"); err == nil {
		t.Fatal("expected error for a non-3-segment proof")
	}
	if _, err := DecodeDPoPClaims("aaa.!!!notbase64.ccc"); err == nil {
		t.Fatal("expected error for an undecodable payload segment")
	}
}

func TestSummarizeMandate(t *testing.T) {
	m := Mandate{
		MandateID:    "mandate-1",
		QuoteID:      "demo-quote-001",
		SubjectANS:   "ans://v2.0.0.buyer.example.com",
		AudienceANS:  "ans://v1.0.8.seller.skybound-travel.com",
		Scope:        "purchase:flight:demo",
		MaxAmount:    500,
		Currency:     "USD",
		NotBefore:    "2026-10-13T15:16:21+00:00",
		NotAfter:     "2026-10-13T15:31:21+00:00",
		JKT:          "jkt-xyz",
		AuthorityANS: "ans://v1.0.0.authority.skybound-travel.com",
		Signature:    "sig",
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := SummarizeMandate(raw)
	if err != nil {
		t.Fatalf("SummarizeMandate: %v", err)
	}
	if got.Scope != m.Scope || got.MaxAmount != m.MaxAmount || got.Currency != m.Currency {
		t.Errorf("scope/max/currency = %q/%v/%q, want %q/%v/%q",
			got.Scope, got.MaxAmount, got.Currency, m.Scope, m.MaxAmount, m.Currency)
	}
	if got.JKT != m.JKT || got.SubjectANS != m.SubjectANS || got.AuthorityANS != m.AuthorityANS {
		t.Errorf("jkt/subject/authority = %q/%q/%q, want %q/%q/%q",
			got.JKT, got.SubjectANS, got.AuthorityANS, m.JKT, m.SubjectANS, m.AuthorityANS)
	}
}

func TestSummarizeMandate_Invalid(t *testing.T) {
	if _, err := SummarizeMandate([]byte("{not json")); err == nil {
		t.Fatal("expected error for invalid mandate JSON")
	}
}
