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
