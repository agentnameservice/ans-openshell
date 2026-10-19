package vetting

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()
	noScore := scoreFunc(func(context.Context, string) (float64, error) { return 0, nil })
	tests := []struct {
		name    string
		cfg     config.Vetting
		deps    Deps
		wantErr string
	}{
		{name: "minimal", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}}},
		{name: "trust index with threshold", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, TrustIndexURL: "https://ti.example.com", MinTrustScore: 50}},
		{name: "injected trust index with threshold", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, MinTrustScore: 50}, deps: Deps{TrustIndex: noScore}},
		{name: "no trusted domains", cfg: config.Vetting{}, wantErr: "trusted_tl_domains"},
		{name: "trusted domain with scheme", cfg: config.Vetting{TrustedTLDomains: []string{"https://tl.example.com"}}, wantErr: "not a hostname"},
		{name: "negative cache ttl", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, CacheTTL: -time.Second}, wantErr: "must not be negative"},
		{name: "negative request budget", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, RequestBudget: -time.Second}, wantErr: "must not be negative"},
		{name: "negative min score", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, MinTrustScore: -1}, wantErr: "must not be negative"},
		{name: "threshold without trust index", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, MinTrustScore: 50}, wantErr: "requires trust_index_url"},
		{name: "trust index without threshold", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, TrustIndexURL: "https://ti.example.com"}, wantErr: "positive min_trust_score"},
		{name: "injected trust index without threshold", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}}, deps: Deps{TrustIndex: noScore}, wantErr: "positive min_trust_score"},
		{name: "bad trust index url", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, TrustIndexURL: "ftp://ti.example.com", MinTrustScore: 50}, wantErr: "must be http(s)"},
		{name: "empty exempt entry", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, ExemptHosts: []string{""}}, wantErr: "empty entry"},
		{name: "unsupported exempt pattern", cfg: config.Vetting{TrustedTLDomains: []string{trustedTL}, ExemptHosts: []string{"api.*.example.com"}}, wantErr: "unsupported exempt_hosts pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, err := New(tt.cfg, tt.deps, nil)
			if svc != nil {
				defer svc.Close()
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	logs := &syncBuffer{}
	cfg := config.Vetting{TrustedTLDomains: []string{trustedTL}, TrustIndexURL: "http://ti.example.com", MinTrustScore: 10}
	svc, err := New(cfg, Deps{}, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer svc.Close()
	if svc.dns == nil || svc.tl == nil || svc.trustIndex == nil || svc.clock == nil || svc.logger == nil {
		t.Fatal("New() left a dependency nil")
	}
	if _, ok := svc.trustIndex.(*HTTPTrustIndexClient); !ok {
		t.Fatalf("trustIndex = %T, want *HTTPTrustIndexClient", svc.trustIndex)
	}
	if svc.cacheTTL != defaultCacheTTL || svc.errorTTL != defaultErrorTTL || svc.lookupTimeout != defaultLookupTimeout {
		t.Fatalf("defaults: cacheTTL %v errorTTL %v lookupTimeout %v", svc.cacheTTL, svc.errorTTL, svc.lookupTimeout)
	}
	if svc.clock().IsZero() {
		t.Fatal("default clock returned the zero time")
	}
	if !strings.Contains(logs.String(), "plaintext http") {
		t.Fatalf("expected a plaintext warning, got %q", logs.String())
	}

	short, err := New(config.Vetting{TrustedTLDomains: []string{trustedTL}, CacheTTL: 10 * time.Second}, Deps{LookupTimeout: time.Second}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer short.Close()
	if short.errorTTL != 10*time.Second || short.lookupTimeout != time.Second {
		t.Fatalf("errorTTL %v lookupTimeout %v", short.errorTTL, short.lookupTimeout)
	}
}

func TestLookupSettledWithoutLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		host   string
		status Status
		want   string
		detail string
	}{
		{name: "exempt exact", host: "API.OpenAI.com.", status: StatusExempt, want: "api.openai.com", detail: "exempt host"},
		{name: "exempt exact with port", host: "api.openai.com:443", status: StatusExempt, want: "api.openai.com", detail: "exempt host"},
		{name: "exempt suffix", host: "s3.amazonaws.com", status: StatusExempt, want: "s3.amazonaws.com", detail: "exempt host"},
		{name: "exempt pattern literal", host: "*.amazonaws.com", status: StatusExempt, want: "*.amazonaws.com", detail: "exempt host"},
		{name: "ipv4", host: "192.0.2.1", status: StatusUnregistered, want: "192.0.2.1", detail: "ip literal"},
		{name: "ipv4 with port", host: "192.0.2.1:8443", status: StatusUnregistered, want: "192.0.2.1", detail: "ip literal"},
		{name: "ipv6", host: "::1", status: StatusUnregistered, want: "::1", detail: "ip literal"},
		{name: "ipv6 bracketed with port", host: "[2001:db8::1]:443", status: StatusUnregistered, want: "2001:db8::1", detail: "ip literal"},
		{name: "wildcard", host: "*.example.com", status: StatusError, want: "*.example.com", detail: "wildcard host cannot be vetted"},
		{name: "empty", host: "", status: StatusError, want: "", detail: "empty host"},
		{name: "blank", host: "   ", status: StatusError, want: "", detail: "empty host"},
		{name: "underscore", host: "bad_host.example.com", status: StatusUnregistered, want: "bad_host.example.com", detail: "invalid hostname"},
		{name: "leading hyphen", host: "-bad.example.com", status: StatusUnregistered, want: "-bad.example.com", detail: "invalid hostname"},
	}
	h := newHarness()
	svc := h.service(t)
	for _, tt := range tests {
		got := svc.Lookup(t.Context(), tt.host, time.Second)
		if got.Status != tt.status || got.Host != tt.want || got.Detail != tt.detail {
			t.Errorf("%s: Lookup(%q) = %+v, want status %v host %q detail %q", tt.name, tt.host, got, tt.status, tt.want, tt.detail)
		}
	}
	if calls := h.cdns.calls.Load(); calls != 0 {
		t.Fatalf("DNS calls = %d, want 0", calls)
	}
	if st := svc.Stats(); st != (Stats{}) {
		t.Fatalf("Stats() = %+v, want all zero", st)
	}
}

func TestLookupStatuses(t *testing.T) {
	t.Parallel()
	evilURL := "https://evil.example.net/v1/agents/x"
	tests := []struct {
		name        string
		host        string
		setup       func(h *harness)
		status      Status
		badgeStatus string
		detail      string
		fetched     []string
	}{
		{
			name:        "active",
			setup:       func(h *harness) { h.publish(testHost, models.BadgeStatusActive) },
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name:        "warning",
			setup:       func(h *harness) { h.publish(testHost, models.BadgeStatusWarning) },
			status:      StatusRegistered,
			badgeStatus: "WARNING",
			detail:      "badge status WARNING",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name:        "deprecated only",
			setup:       func(h *harness) { h.publish(testHost, models.BadgeStatusDeprecated) },
			status:      StatusRegistered,
			badgeStatus: "DEPRECATED",
			detail:      "badge status DEPRECATED",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name: "deprecated newest with active sibling",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{
					record("v1.0.0", badgeURL("v1")),
					record("v2.0.0", badgeURL("v2")),
				})
				h.tl.WithBadge(badgeURL("v2"), badgeFor(testHost, models.BadgeStatusDeprecated))
				h.tl.WithBadge(badgeURL("v1"), badgeFor(testHost, models.BadgeStatusActive))
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL("v2"), badgeURL("v1")},
		},
		{
			name:        "revoked",
			setup:       func(h *harness) { h.publish(testHost, models.BadgeStatusRevoked) },
			status:      StatusRevoked,
			badgeStatus: "REVOKED",
			detail:      "badge status REVOKED",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name:        "expired",
			setup:       func(h *harness) { h.publish(testHost, models.BadgeStatusExpired) },
			status:      StatusRevoked,
			badgeStatus: "EXPIRED",
			detail:      "badge status EXPIRED",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name: "revoked newest with active sibling",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{
					record("v2.0.0", badgeURL("v2")),
					record("v1.0.0", badgeURL("v1")),
				})
				h.tl.WithBadge(badgeURL("v2"), badgeFor(testHost, models.BadgeStatusRevoked))
				h.tl.WithBadge(badgeURL("v1"), badgeFor(testHost, models.BadgeStatusActive))
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL("v2"), badgeURL("v1")},
		},
		{
			name: "revoked with sibling fetch error",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{
					record("v2.0.0", badgeURL("v2")),
					record("v1.0.0", badgeURL("v1")),
				})
				h.tl.WithBadge(badgeURL("v2"), badgeFor(testHost, models.BadgeStatusRevoked))
				h.tl.WithError(badgeURL("v1"), &verify.TlogError{Type: verify.TlogErrorServiceUnavailable})
			},
			status:  StatusError,
			detail:  "badge fetch failed",
			fetched: []string{badgeURL("v2"), badgeURL("v1")},
		},
		{
			name:    "unknown badge status",
			setup:   func(h *harness) { h.publish(testHost, models.BadgeStatus("UNKNOWN")) },
			status:  StatusError,
			detail:  "badge status unknown",
			fetched: []string{badgeURL(testHost)},
		},
		{
			name:   "no record",
			setup:  func(*harness) {},
			status: StatusUnregistered,
			detail: "no _ans-badge record",
		},
		{
			name:   "exempt apex is looked up",
			host:   "amazonaws.com",
			setup:  func(*harness) {},
			status: StatusUnregistered,
			detail: "no _ans-badge record",
		},
		{
			name: "dns error",
			setup: func(h *harness) {
				h.dns.WithError(testHost, &verify.DNSError{Type: verify.DNSErrorTimeout, Fqdn: testHost})
			},
			status: StatusError,
			detail: "dns lookup failed",
		},
		{
			name: "badge fetch error",
			setup: func(h *harness) {
				u := badgeURL(testHost)
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", u)})
				h.tl.WithError(u, &verify.TlogError{Type: verify.TlogErrorServiceUnavailable, URL: u})
			},
			status:  StatusError,
			detail:  "badge fetch failed",
			fetched: []string{badgeURL(testHost)},
		},
		{
			name: "badge missing at log",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", badgeURL(testHost))})
			},
			status:  StatusError,
			detail:  "badge fetch failed",
			fetched: []string{badgeURL(testHost)},
		},
		{
			name: "badge for a different host",
			setup: func(h *harness) {
				u := badgeURL(testHost)
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", u)})
				h.tl.WithBadge(u, badgeFor("other.example.com", models.BadgeStatusActive))
			},
			status:  StatusUnregistered,
			detail:  "badge names a different host",
			fetched: []string{badgeURL(testHost)},
		},
		{
			name: "badge host compared case-insensitively",
			setup: func(h *harness) {
				u := badgeURL(testHost)
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", u)})
				b := badgeFor(testHost, models.BadgeStatusActive)
				b.Payload.Producer.Event.Agent.Host = "Agent.Example.COM."
				h.tl.WithBadge(u, b)
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name: "untrusted log is never fetched",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", evilURL)})
				h.tl.WithBadge(evilURL, badgeFor(testHost, models.BadgeStatusActive))
			},
			status: StatusUntrustedTL,
			detail: "untrusted transparency log evil.example.net",
		},
		{
			name: "untrusted record skipped when a trusted one exists",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{
					record("v2.0.0", evilURL),
					record("v1.0.0", badgeURL(testHost)),
				})
				h.tl.WithBadge(evilURL, badgeFor(testHost, models.BadgeStatusActive))
				h.tl.WithBadge(badgeURL(testHost), badgeFor(testHost, models.BadgeStatusActive))
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL(testHost)},
		},
		{
			name: "plain http badge url",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", "http://tl.example.com/v1/agents/x")})
			},
			status: StatusUntrustedTL,
			detail: "badge url is not https",
		},
		{
			name: "non-standard port",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", "https://tl.example.com:8443/v1/agents/x")})
			},
			status: StatusUntrustedTL,
			detail: "badge url uses a non-standard port",
		},
		{
			name: "subdomain of a trusted log",
			setup: func(h *harness) {
				u := "https://EU.tl.example.com/v1/agents/x"
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{record("v1.0.0", u)})
				h.tl.WithBadge(u, badgeFor(testHost, models.BadgeStatusActive))
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{"https://EU.tl.example.com/v1/agents/x"},
		},
		{
			name: "versionless record is tried last",
			setup: func(h *harness) {
				h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{
					record("", badgeURL("latest")),
					record("v1.0.0", badgeURL("v1")),
				})
				h.tl.WithBadge(badgeURL("latest"), badgeFor(testHost, models.BadgeStatusActive))
				h.tl.WithBadge(badgeURL("v1"), badgeFor(testHost, models.BadgeStatusRevoked))
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL("v1"), badgeURL("latest")},
		},
		{
			name: "active fifth version is reached",
			setup: func(h *harness) {
				records := make([]verify.AnsBadgeRecord, 0, 5)
				for i := 1; i <= 5; i++ {
					id := "v" + string(rune('0'+i))
					records = append(records, record(id+".0.0", badgeURL(id)))
					status := models.BadgeStatusRevoked
					if i == 1 {
						status = models.BadgeStatusActive
					}
					h.tl.WithBadge(badgeURL(id), badgeFor(testHost, status))
				}
				h.dns.WithRecords(testHost, records)
			},
			status:      StatusRegistered,
			badgeStatus: "ACTIVE",
			detail:      "badge status ACTIVE",
			fetched:     []string{badgeURL("v5"), badgeURL("v4"), badgeURL("v3"), badgeURL("v2"), badgeURL("v1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			tt.setup(h)
			host := tt.host
			if host == "" {
				host = testHost
			}
			svc := h.service(t)
			got := svc.Lookup(t.Context(), host, 5*time.Second)
			if got.Host != host || got.Status != tt.status || got.BadgeStatus != tt.badgeStatus || got.Detail != tt.detail {
				t.Fatalf("Lookup() = %+v, want host %q status %v badge %q detail %q", got, host, tt.status, tt.badgeStatus, tt.detail)
			}
			if tt.badgeStatus != "" && (got.AnsName != "ans://v1.0.0."+host || got.AgentID != "id-"+host) {
				t.Fatalf("Lookup() identity = %q/%q", got.AnsName, got.AgentID)
			}
			if fetched := h.ctl.fetched(); !slices.Equal(fetched, tt.fetched) {
				t.Fatalf("fetched %v, want %v", fetched, tt.fetched)
			}
			if calls := h.cdns.calls.Load(); calls != 1 {
				t.Fatalf("DNS calls = %d, want 1", calls)
			}
		})
	}
}

func TestLookupTrustIndex(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		badge  models.BadgeStatus
		score  float64
		err    error
		status Status
		detail string
		calls  int32
	}{
		{name: "above", badge: models.BadgeStatusActive, score: 80, status: StatusRegistered, detail: "badge status ACTIVE", calls: 1},
		{name: "equal", badge: models.BadgeStatusActive, score: 60, status: StatusRegistered, detail: "badge status ACTIVE", calls: 1},
		{name: "below", badge: models.BadgeStatusActive, score: 40, status: StatusBelowThreshold, detail: "trust index score 40 below minimum 60", calls: 1},
		{name: "no record", badge: models.BadgeStatusActive, err: ErrNoTrustRecord, status: StatusBelowThreshold, detail: "no trust index record", calls: 1},
		{name: "unavailable", badge: models.BadgeStatusActive, err: errors.New("boom"), status: StatusError, detail: "trust index unavailable", calls: 1},
		{name: "skipped when revoked", badge: models.BadgeStatusRevoked, status: StatusRevoked, detail: "badge status REVOKED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			h.publish(testHost, tt.badge)
			var calls atomic.Int32
			h.cfg.MinTrustScore = 60
			h.deps.TrustIndex = scoreFunc(func(_ context.Context, agentID string) (float64, error) {
				calls.Add(1)
				if agentID != "id-"+testHost {
					t.Errorf("LowestDimension agentID = %q", agentID)
				}
				return tt.score, tt.err
			})
			svc := h.service(t)
			got := svc.Lookup(t.Context(), testHost, 5*time.Second)
			if got.Status != tt.status || got.Detail != tt.detail || got.AgentID != "id-"+testHost {
				t.Fatalf("Lookup() = %+v, want status %v detail %q", got, tt.status, tt.detail)
			}
			if calls.Load() != tt.calls {
				t.Fatalf("LowestDimension calls = %d, want %d", calls.Load(), tt.calls)
			}
		})
	}
}

func TestLookupCacheHitAndExpiry(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	svc := h.service(t)
	ctx := t.Context()

	if got := svc.Lookup(ctx, testHost, 5*time.Second); got.Status != StatusRegistered {
		t.Fatalf("first Lookup() = %+v", got)
	}
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusRegistered {
		t.Fatalf("cached Lookup() = %+v", got)
	}
	if st := svc.Stats(); st != (Stats{Entries: 1, Hits: 1, Misses: 1, Lookups: 1}) {
		t.Fatalf("Stats() = %+v", st)
	}

	h.clock.Advance(defaultCacheTTL)
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusUnknown || got.Detail != "lookup in progress" || got.Host != testHost {
		t.Fatalf("expired Lookup() = %+v, want unknown", got)
	}
	if got := svc.Lookup(ctx, testHost, 5*time.Second); got.Status != StatusRegistered {
		t.Fatalf("refreshed Lookup() = %+v", got)
	}
	if st := svc.Stats(); st.Lookups != 2 || st.Entries != 1 || st.Hits+st.Misses != 4 {
		t.Fatalf("Stats() = %+v, want 2 lookups, 1 entry, 4 cache reads", st)
	}
	if calls := h.cdns.calls.Load(); calls != 2 {
		t.Fatalf("DNS calls = %d, want 2", calls)
	}
}

func TestLookupRefreshAhead(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	svc := h.service(t)
	ctx := t.Context()

	svc.Lookup(ctx, testHost, 5*time.Second)
	h.clock.Advance(defaultCacheTTL - defaultCacheTTL/refreshAheadDivisor)
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusRegistered {
		t.Fatalf("Lookup() in the refresh window = %+v, want the cached verdict", got)
	}
	if st := svc.Stats(); st.Lookups != 2 || st.Hits != 1 {
		t.Fatalf("Stats() = %+v, want a second lookup started on a hit", st)
	}
	eventually(t, "refresh lookup", func() bool { return h.cdns.calls.Load() == 2 })
	svc.Lookup(ctx, testHost, 5*time.Second)
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusRegistered {
		t.Fatalf("Lookup() after refresh = %+v", got)
	}
	if st := svc.Stats(); st.Lookups != 2 {
		t.Fatalf("Stats() = %+v, want no further lookups", st)
	}
}

func TestLookupErrorTTL(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.dns.WithError(testHost, &verify.DNSError{Type: verify.DNSErrorLookupFailed, Fqdn: testHost, Reason: "servfail"})
	svc := h.service(t)
	ctx := t.Context()

	if got := svc.Lookup(ctx, testHost, 5*time.Second); got.Status != StatusError || got.Detail != "dns lookup failed" {
		t.Fatalf("Lookup() = %+v", got)
	}
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusError {
		t.Fatalf("cached error Lookup() = %+v", got)
	}
	h.clock.Advance(defaultErrorTTL)
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusUnknown {
		t.Fatalf("Lookup() after error TTL = %+v, want unknown", got)
	}
	if st := svc.Stats(); st.Errors != 1 || st.Lookups != 2 {
		t.Fatalf("Stats() = %+v", st)
	}
}

func TestLookupEviction(t *testing.T) {
	t.Parallel()
	h := newHarness()
	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	for _, host := range hosts {
		h.registered(host)
	}
	svc := h.service(t)
	svc.cache = newVerdictCache(2)
	ctx := t.Context()
	for _, host := range hosts {
		if got := svc.Lookup(ctx, host, 5*time.Second); got.Status != StatusRegistered {
			t.Fatalf("Lookup(%q) = %+v", host, got)
		}
	}
	if st := svc.Stats(); st.Entries != 2 {
		t.Fatalf("Stats() = %+v, want 2 entries", st)
	}
	if got := svc.Lookup(ctx, "a.example.com", 0); got.Status != StatusUnknown {
		t.Fatalf("Lookup(evicted) = %+v, want unknown", got)
	}
	if got := svc.Lookup(ctx, "c.example.com", 0); got.Status != StatusRegistered {
		t.Fatalf("Lookup(retained) = %+v", got)
	}
}

func TestLookupSingleFlight(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	h.cdns.gate = make(chan struct{})
	svc := h.service(t)
	ctx := t.Context()

	const n = 16
	results := make(chan Verdict, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- svc.Lookup(ctx, testHost, 5*time.Second)
		}()
	}
	eventually(t, "the lookup to reach DNS", func() bool { return h.cdns.calls.Load() == 1 })
	close(h.cdns.gate)
	wg.Wait()
	close(results)
	for got := range results {
		if got.Status != StatusRegistered {
			t.Fatalf("Lookup() = %+v", got)
		}
	}
	st := svc.Stats()
	if st.Lookups != 1 || st.Hits+st.Misses != n || h.cdns.calls.Load() != 1 {
		t.Fatalf("Stats() = %+v, DNS calls %d; want one lookup", st, h.cdns.calls.Load())
	}
}

func TestLookupWaitZeroThenCached(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	svc := h.service(t)
	ctx := t.Context()

	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusUnknown || got.Host != testHost {
		t.Fatalf("Lookup(wait 0) = %+v, want unknown", got)
	}
	if got := svc.Lookup(ctx, testHost, 5*time.Second); got.Status != StatusRegistered {
		t.Fatalf("Lookup(wait) = %+v", got)
	}
	if got := svc.Lookup(ctx, testHost, 0); got.Status != StatusRegistered {
		t.Fatalf("Lookup(cached) = %+v", got)
	}
	if st := svc.Stats(); st.Lookups != 1 {
		t.Fatalf("Stats() = %+v, want one lookup", st)
	}
}

func TestLookupWaitElapses(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	h.cdns.gate = make(chan struct{})
	svc := h.service(t)
	ctx := t.Context()

	if got := svc.Lookup(ctx, testHost, 20*time.Millisecond); got.Status != StatusUnknown {
		t.Fatalf("Lookup(short wait) = %+v, want unknown", got)
	}
	eventually(t, "the lookup to reach DNS", func() bool { return h.cdns.calls.Load() == 1 })
	close(h.cdns.gate)
	if got := svc.Lookup(ctx, testHost, 5*time.Second); got.Status != StatusRegistered {
		t.Fatalf("Lookup(after release) = %+v", got)
	}
}

func TestLookupContextCanceled(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	h.cdns.gate = make(chan struct{})
	svc := h.service(t)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan Verdict, 1)
	go func() { done <- svc.Lookup(ctx, testHost, 10*time.Second) }()
	eventually(t, "the lookup to reach DNS", func() bool { return h.cdns.calls.Load() == 1 })
	cancel()
	select {
	case got := <-done:
		if got.Status != StatusUnknown {
			t.Fatalf("Lookup(canceled) = %+v, want unknown", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lookup did not return after cancellation")
	}
	close(h.cdns.gate)
	if got := svc.Lookup(t.Context(), testHost, 5*time.Second); got.Status != StatusRegistered {
		t.Fatalf("Lookup(after cancellation) = %+v, want the background result", got)
	}
	if st := svc.Stats(); st.Lookups != 1 {
		t.Fatalf("Stats() = %+v, want one lookup", st)
	}
}

func TestPrewarm(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered("a.example.com")
	svc := h.service(t)
	ctx := t.Context()

	svc.Prewarm(ctx, "a.example.com", "b.example.com", "api.openai.com", "192.0.2.1", "A.example.com.")
	if st := svc.Stats(); st.Lookups != 2 {
		t.Fatalf("Stats() = %+v, want 2 lookups", st)
	}
	eventually(t, "prewarmed verdicts", func() bool {
		return svc.Lookup(ctx, "a.example.com", 0).Status == StatusRegistered &&
			svc.Lookup(ctx, "b.example.com", 0).Status == StatusUnregistered
	})
	if calls := h.cdns.calls.Load(); calls != 2 {
		t.Fatalf("DNS calls = %d, want 2", calls)
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered("a.example.com")
	h.registered("b.example.com")
	svc := h.service(t)
	ctx := t.Context()

	if got := svc.Lookup(ctx, "a.example.com", 5*time.Second); got.Status != StatusRegistered {
		t.Fatalf("Lookup(a) = %+v", got)
	}
	h.cdns.gate = make(chan struct{})
	if got := svc.Lookup(ctx, "b.example.com", 0); got.Status != StatusUnknown {
		t.Fatalf("Lookup(b) = %+v, want unknown", got)
	}
	eventually(t, "the lookup to reach DNS", func() bool { return h.cdns.calls.Load() == 2 })

	closed := make(chan struct{})
	go func() {
		svc.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return while a lookup was blocked")
	}

	if got := svc.Lookup(ctx, "b.example.com", 0); got.Status != StatusError || got.Detail != "dns lookup failed" {
		t.Fatalf("Lookup(b) after close = %+v, want the canceled lookup's error", got)
	}
	if got := svc.Lookup(ctx, "a.example.com", 0); got.Status != StatusRegistered {
		t.Fatalf("Lookup(a) after close = %+v, want the cached verdict", got)
	}
	if got := svc.Lookup(ctx, "c.example.com", time.Second); got.Status != StatusError || got.Detail != "vetting service closed" {
		t.Fatalf("Lookup(c) after close = %+v", got)
	}
	h.clock.Advance(defaultCacheTTL - defaultCacheTTL/refreshAheadDivisor)
	if got := svc.Lookup(ctx, "a.example.com", 0); got.Status != StatusRegistered {
		t.Fatalf("Lookup(a) in refresh window after close = %+v", got)
	}
	if st := svc.Stats(); st.Lookups != 2 || st.Errors != 1 {
		t.Fatalf("Stats() = %+v, want no lookups after close", st)
	}
	svc.Close()
}

func TestLookupLogsHostAndStatusOnly(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.registered(testHost)
	h.dns.WithError("down.example.com", &verify.DNSError{Type: verify.DNSErrorTimeout, Fqdn: "down.example.com"})
	svc := h.service(t)
	ctx := t.Context()

	svc.Lookup(ctx, testHost, 5*time.Second)
	svc.Lookup(ctx, "down.example.com", 5*time.Second)
	eventually(t, "log lines", func() bool {
		return strings.Count(h.logs.String(), "destination verdict") == 2
	})
	logs := h.logs.String()
	for _, want := range []string{
		`level=INFO msg="destination verdict" host=agent.example.com status=registered`,
		`level=WARN msg="dns lookup failed" host=down.example.com error=`,
		`level=INFO msg="destination verdict" host=down.example.com status=error`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "ans://") || strings.Contains(logs, "id-") {
		t.Fatalf("logs leak badge identity:\n%s", logs)
	}

	h.clock.Advance(defaultCacheTTL)
	svc.Lookup(ctx, testHost, 5*time.Second)
	eventually(t, "the refresh to finish", func() bool { return h.cdns.calls.Load() == 3 })
	svc.Lookup(ctx, testHost, 5*time.Second)
	if n := strings.Count(h.logs.String(), "host=agent.example.com status=registered"); n != 1 {
		t.Fatalf("unchanged verdict logged %d times, want once", n)
	}
}
