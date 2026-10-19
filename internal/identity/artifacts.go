package identity

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Artifacts are the SCITT headers a signed request carries, base64-encoded as
// they travel: the receipt (X-SCITT-Receipt) and the status token
// (X-ANS-Status-Token).
type Artifacts struct {
	ReceiptBase64     string
	StatusTokenBase64 string
}

// complete reports whether both artifacts are present.
func (a Artifacts) complete() bool { return a.ReceiptBase64 != "" && a.StatusTokenBase64 != "" }

// ArtifactSource supplies the current artifacts of one identity.
type ArtifactSource interface {
	// Current returns the artifacts to attach now. An empty field means that
	// artifact is unavailable, missing or expired, and the request must be
	// denied.
	Current() Artifacts
	// Healthy reports whether a complete, unexpired set of artifacts is held.
	// A failed background refresh does not make a source unhealthy while the
	// artifacts it holds are still valid.
	Healthy() bool
}

type certificateSource struct {
	ArtifactSource
	cert *x509.Certificate
	now  func() time.Time
}

func (s *certificateSource) Current() Artifacts {
	now := s.now()
	if now.Before(s.cert.NotBefore) || now.After(s.cert.NotAfter) {
		return Artifacts{}
	}
	return s.ArtifactSource.Current()
}

func (s *certificateSource) Healthy() bool { return s.Current().complete() }

// SupplierSource keeps artifacts fresh with the SDK's scitt.HeaderSupplier,
// which refreshes them in the background at half the status token's TTL and
// withholds an expired token.
type SupplierSource struct {
	supplier *scitt.HeaderSupplier
	cancel   context.CancelFunc
}

// NewSupplierSource primes supplier with one fetch and starts its background
// refresh, which runs until ctx is canceled or Close is called. The first fetch
// happens here so a log that is unreachable or does not vouch for the agent
// fails at startup rather than on the request path.
func NewSupplierSource(ctx context.Context, supplier *scitt.HeaderSupplier) (*SupplierSource, error) {
	supplier.CurrentHeaders()
	if !supplier.Healthy() {
		return nil, fmt.Errorf("fetch artifacts: %w", supplier.LastError())
	}
	return &SupplierSource{supplier: supplier, cancel: supplier.StartAutoRefresh(ctx)}, nil
}

// Current implements ArtifactSource.
func (s *SupplierSource) Current() Artifacts {
	h := s.supplier.CurrentHeaders()
	return Artifacts{ReceiptBase64: h.ReceiptBase64, StatusTokenBase64: h.StatusTokenBase64}
}

// Healthy implements ArtifactSource: the supplier withholds an expired token,
// so a complete set means the artifacts are usable now.
func (s *SupplierSource) Healthy() bool { return s.Current().complete() }

// Close stops the background refresh.
func (s *SupplierSource) Close() { s.cancel() }

// StaticSource serves one fixed set of artifacts, optionally until an expiry
// after which the status token is withheld the way the SDK supplier withholds
// an expired one.
type StaticSource struct {
	artifacts Artifacts
	expiresAt time.Time
	now       func() time.Time
}

// NewStaticSource returns a source that always serves a.
func NewStaticSource(a Artifacts) *StaticSource {
	return &StaticSource{artifacts: a, now: time.Now}
}

// NewStaticSourceUntil returns a source that serves a until exp, the status
// token's expiry, and only the receipt from then on.
func NewStaticSourceUntil(a Artifacts, exp time.Time) *StaticSource {
	return newStaticSourceUntil(a, exp, time.Now)
}

func newStaticSourceUntil(a Artifacts, exp time.Time, now func() time.Time) *StaticSource {
	return &StaticSource{artifacts: a, expiresAt: exp, now: now}
}

// Current implements ArtifactSource.
func (s *StaticSource) Current() Artifacts {
	if !s.expiresAt.IsZero() && !s.now().Before(s.expiresAt) {
		return Artifacts{ReceiptBase64: s.artifacts.ReceiptBase64}
	}
	return s.artifacts
}

// Healthy implements ArtifactSource.
func (s *StaticSource) Healthy() bool { return s.Current().complete() }

// readArtifactFiles loads a raw COSE_Sign1 receipt and status token.
func readArtifactFiles(receiptFile, statusTokenFile string) ([]byte, []byte, error) {
	receipt, err := os.ReadFile(receiptFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read receipt_file: %w", err)
	}
	token, err := os.ReadFile(statusTokenFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read status_token_file: %w", err)
	}
	return receipt, token, nil
}
