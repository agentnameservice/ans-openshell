package vetting

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const (
	trustedTL = "tl.example.com"
	testHost  = "agent.example.com"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingDNS counts LookupAnsBadge calls and, when gate is set, holds them
// until the gate is closed or the lookup context ends.
type countingDNS struct {
	inner verify.DNSResolver
	calls atomic.Int32
	gate  chan struct{}
}

func (d *countingDNS) LookupAnsBadge(ctx context.Context, fqdn models.Fqdn) (verify.DNSLookupResult, error) {
	d.calls.Add(1)
	if d.gate != nil {
		select {
		case <-d.gate:
		case <-ctx.Done():
			return verify.DNSLookupResult{}, ctx.Err()
		}
	}
	return d.inner.LookupAnsBadge(ctx, fqdn)
}

func (d *countingDNS) FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*verify.AnsBadgeRecord, error) {
	return d.inner.FindBadgeForVersion(ctx, fqdn, version)
}

func (d *countingDNS) FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*verify.AnsBadgeRecord, error) {
	return d.inner.FindPreferredBadge(ctx, fqdn)
}

// countingTL records every badge URL fetched.
type countingTL struct {
	inner verify.TransparencyLogClient
	mu    sync.Mutex
	urls  []string
}

func (c *countingTL) FetchBadge(ctx context.Context, rawURL string) (*models.Badge, error) {
	c.mu.Lock()
	c.urls = append(c.urls, rawURL)
	c.mu.Unlock()
	return c.inner.FetchBadge(ctx, rawURL)
}

func (c *countingTL) fetched() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.urls...)
}

type scoreFunc func(ctx context.Context, agentID string) (float64, error)

func (f scoreFunc) LowestDimension(ctx context.Context, agentID string) (float64, error) {
	return f(ctx, agentID)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func badgeURL(agentID string) string {
	return "https://" + trustedTL + "/v1/agents/" + agentID
}

func badgeFor(host string, status models.BadgeStatus) *models.Badge {
	b := &models.Badge{Status: status}
	b.Payload.Producer.Event.ANSID = "id-" + host
	b.Payload.Producer.Event.ANSName = "ans://v1.0.0." + host
	b.Payload.Producer.Event.Agent.Host = host
	return b
}

func record(version, rawURL string) verify.AnsBadgeRecord {
	rec := verify.AnsBadgeRecord{FormatVersion: "ans-badge1", URL: rawURL}
	if version != "" {
		v, err := models.ParseVersion(version)
		if err != nil {
			panic(err)
		}
		rec.Version = &v
	}
	return rec
}

type harness struct {
	dns   *verify.MockDNSResolver
	cdns  *countingDNS
	tl    *verify.MockTransparencyLogClient
	ctl   *countingTL
	clock *fakeClock
	logs  *syncBuffer
	cfg   config.Vetting
	deps  Deps
}

func newHarness() *harness {
	h := &harness{
		dns:   verify.NewMockDNSResolver(),
		tl:    verify.NewMockTransparencyLogClient(),
		clock: newFakeClock(),
		logs:  &syncBuffer{},
	}
	h.cdns = &countingDNS{inner: h.dns}
	h.ctl = &countingTL{inner: h.tl}
	h.cfg = config.Vetting{
		TrustedTLDomains: []string{trustedTL},
		ExemptHosts:      []string{"api.openai.com", "*.amazonaws.com"},
	}
	h.deps = Deps{DNS: h.cdns, TL: h.ctl, Clock: h.clock.Now}
	return h
}

// publish puts one record for host at the trusted log with a badge of the
// given status.
func (h *harness) publish(host string, status models.BadgeStatus) {
	u := badgeURL(host)
	h.dns.WithRecords(host, []verify.AnsBadgeRecord{record("v1.0.0", u)})
	h.tl.WithBadge(u, badgeFor(host, status))
}

func (h *harness) registered(host string) {
	h.publish(host, models.BadgeStatusActive)
}

func (h *harness) service(t *testing.T) *Service {
	t.Helper()
	svc, err := New(h.cfg, h.deps, slog.New(slog.NewTextHandler(h.logs, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(svc.Close)
	return svc
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
