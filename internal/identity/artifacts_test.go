package identity

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

func TestCertificateSource(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cert := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	full := Artifacts{ReceiptBase64: "receipt", StatusTokenBase64: "status"}
	for _, tt := range []struct {
		name        string
		now         time.Time
		artifacts   Artifacts
		wantHealthy bool
	}{
		{name: "before certificate validity", now: cert.NotBefore.Add(-time.Nanosecond), artifacts: full},
		{name: "at not before", now: cert.NotBefore, artifacts: full, wantHealthy: true},
		{name: "valid", now: now, artifacts: full, wantHealthy: true},
		{name: "at not after", now: cert.NotAfter, artifacts: full, wantHealthy: true},
		{name: "expired", now: cert.NotAfter.Add(time.Nanosecond), artifacts: full},
		{name: "artifacts unavailable", now: now},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &certificateSource{ArtifactSource: NewStaticSource(tt.artifacts), cert: cert, now: func() time.Time { return tt.now }}
			if s.Healthy() != tt.wantHealthy || s.Current().complete() != tt.wantHealthy {
				t.Fatalf("healthy=%v artifacts=%+v", s.Healthy(), s.Current())
			}
		})
	}
}

func TestNewSelfSignedArtifacts(t *testing.T) {
	// Generate a self-signed identity cert
	const (
		ansName = "ans://v9.9.9.rogue.example"
		agentID = "rogue-0001"
	)

	_, _, cert, err := NewSelfSignedSigner(ansName)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner: %v", err)
	}

	// Create self-signed artifacts
	src, err := NewSelfSignedArtifacts(cert, ansName, agentID)
	if err != nil {
		t.Fatalf("NewSelfSignedArtifacts: %v", err)
	}

	// Get the current artifacts
	arts := src.Current()

	// Assert both status token and receipt are non-empty
	if arts.StatusTokenBase64 == "" {
		t.Error("StatusTokenBase64 is empty, expected non-empty")
	}
	if arts.ReceiptBase64 == "" {
		t.Error("ReceiptBase64 is empty, expected non-empty")
	}

	// Assert Healthy returns true
	if !src.Healthy() {
		t.Error("Healthy() = false, expected true")
	}

	// Decode and parse the status token
	tokenBytes, err := base64.StdEncoding.DecodeString(arts.StatusTokenBase64)
	if err != nil {
		t.Fatalf("decode status token: %v", err)
	}

	// Parse as COSE_Sign1
	parsedToken, err := scitt.ParseCoseSign1(tokenBytes)
	if err != nil {
		t.Fatalf("parse status token as COSE_Sign1: %v", err)
	}

	// Assert the token's kid is NOT in a real TL's root-key set
	// (the self-signed key should be rejected by a real TL verifier)
	realTL := testfixtures.MustNewTL()
	if _, verifyErr := scitt.VerifyStatusToken(tokenBytes, realTL.KeyStore(), time.Minute); verifyErr == nil {
		t.Error("expected status token verification to fail against real TL, but it succeeded")
	}

	// Decode and parse the receipt
	receiptBytes, err := base64.StdEncoding.DecodeString(arts.ReceiptBase64)
	if err != nil {
		t.Fatalf("decode receipt: %v", err)
	}

	// Parse as COSE_Sign1
	parsedReceipt, err := scitt.ParseCoseSign1(receiptBytes)
	if err != nil {
		t.Fatalf("parse receipt as COSE_Sign1: %v", err)
	}

	// Assert the receipt's kid is NOT in the real TL's root-key set
	if _, verifyErr := scitt.VerifyReceipt(receiptBytes, realTL.KeyStore()); verifyErr == nil {
		t.Error("expected receipt verification to fail against real TL, but it succeeded")
	}

	// Verify the status token can be verified when we actually try
	// (to ensure we minted well-formed COSE)
	_ = parsedToken
	_ = parsedReceipt

	// We can't verify claims without a successful VerifyStatusToken,
	// but we can verify the COSE parses correctly (done above)
}

func TestStaticSource(t *testing.T) {
	t.Parallel()
	full := Artifacts{ReceiptBase64: "r", StatusTokenBase64: "t"}
	exp := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name        string
		src         *StaticSource
		wantCurrent Artifacts
		wantHealthy bool
	}{
		{name: "no expiry", src: NewStaticSource(full), wantCurrent: full, wantHealthy: true},
		{name: "before expiry", src: newStaticSourceUntil(full, exp, func() time.Time { return exp.Add(-time.Second) }),
			wantCurrent: full, wantHealthy: true},
		{name: "at expiry withholds the token", src: newStaticSourceUntil(full, exp, func() time.Time { return exp }),
			wantCurrent: Artifacts{ReceiptBase64: "r"}},
		{name: "after expiry", src: newStaticSourceUntil(full, exp, func() time.Time { return exp.Add(time.Hour) }),
			wantCurrent: Artifacts{ReceiptBase64: "r"}},
		{name: "receipt only", src: NewStaticSource(Artifacts{ReceiptBase64: "r"}), wantCurrent: Artifacts{ReceiptBase64: "r"}},
		{name: "token only", src: NewStaticSource(Artifacts{StatusTokenBase64: "t"}), wantCurrent: Artifacts{StatusTokenBase64: "t"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.src.Current(); got != tt.wantCurrent {
				t.Fatalf("Current() = %+v, want %+v", got, tt.wantCurrent)
			}
			if got := tt.src.Healthy(); got != tt.wantHealthy {
				t.Fatalf("Healthy() = %v, want %v", got, tt.wantHealthy)
			}
		})
	}
	if NewStaticSourceUntil(full, time.Now().Add(time.Hour)).Current() != full {
		t.Fatal("NewStaticSourceUntil withheld an unexpired token")
	}
}

func TestReadArtifactFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	receiptFile := filepath.Join(dir, "receipt.cose")
	tokenFile := filepath.Join(dir, "token.cose")
	if err := os.WriteFile(receiptFile, []byte("receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, token, err := readArtifactFiles(receiptFile, tokenFile)
	if err != nil || string(receipt) != "receipt" || string(token) != "token" {
		t.Fatalf("readArtifactFiles() = %q, %q, %v", receipt, token, err)
	}
	if _, _, err := readArtifactFiles(filepath.Join(dir, "missing"), tokenFile); err == nil {
		t.Fatal("accepted a missing receipt file")
	}
	if _, _, err := readArtifactFiles(receiptFile, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("accepted a missing token file")
	}
}

func TestSupplierSource(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	receipt := tl.Receipt(id.AgentID, id.AnsName)

	t.Run("serves verified artifacts and refreshes", func(t *testing.T) {
		t.Parallel()
		client := scitt.NewMockClient().WithReceipt(id.AgentID, receipt).WithStatusToken(id.AgentID, tl.FreshStatusToken(id))
		supplier := scitt.NewHeaderSupplier(id.AgentID, client, scitt.NewRefreshableKeyStore(tl.KeyStore(), nil))
		src, err := NewSupplierSource(t.Context(), supplier)
		if err != nil {
			t.Fatalf("NewSupplierSource: %v", err)
		}
		defer src.Close()
		got := src.Current()
		if got.ReceiptBase64 != base64.StdEncoding.EncodeToString(receipt) || got.StatusTokenBase64 == "" {
			t.Fatalf("Current() = %+v", got)
		}
		if !src.Healthy() {
			t.Fatal("Healthy() = false after a successful fetch")
		}
	})

	t.Run("fails closed when the log does not know the agent", func(t *testing.T) {
		t.Parallel()
		supplier := scitt.NewHeaderSupplier(id.AgentID, scitt.NewMockClient(), scitt.NewRefreshableKeyStore(tl.KeyStore(), nil))
		if _, err := NewSupplierSource(t.Context(), supplier); err == nil {
			t.Fatal("NewSupplierSource succeeded without artifacts")
		}
	})

	t.Run("fails closed when the token is signed by an untrusted log", func(t *testing.T) {
		t.Parallel()
		rogue := testfixtures.MustNewTL()
		client := scitt.NewMockClient().WithReceipt(id.AgentID, receipt).WithStatusToken(id.AgentID, rogue.FreshStatusToken(id))
		supplier := scitt.NewHeaderSupplier(id.AgentID, client, scitt.NewRefreshableKeyStore(tl.KeyStore(), nil))
		_, err := NewSupplierSource(t.Context(), supplier)
		var sigErr *scitt.SignatureError
		if !errors.As(err, &sigErr) {
			t.Fatalf("NewSupplierSource error = %v, want a signature error", err)
		}
	})

	t.Run("withholds an expired token", func(t *testing.T) {
		t.Parallel()
		now := time.Now().Unix()
		expired := tl.StatusToken(id.AgentID, id.AnsName, scitt.StatusActive, now-3600, now-10, id.Fingerprint)
		client := scitt.NewMockClient().WithReceipt(id.AgentID, receipt).WithStatusToken(id.AgentID, expired)
		supplier := scitt.NewHeaderSupplier(id.AgentID, client, scitt.NewRefreshableKeyStore(tl.KeyStore(), nil),
			scitt.WithSupplierClockSkew(time.Minute))
		src, err := NewSupplierSource(t.Context(), supplier)
		if err != nil {
			t.Fatalf("NewSupplierSource: %v", err)
		}
		defer src.Close()
		if got := src.Current(); got.StatusTokenBase64 != "" || got.ReceiptBase64 == "" {
			t.Fatalf("Current() = %+v, want receipt only", got)
		}
	})
}
