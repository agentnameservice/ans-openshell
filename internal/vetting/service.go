package vetting

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const (
	defaultCacheTTL      = 10 * time.Minute
	defaultErrorTTL      = 30 * time.Second
	defaultLookupTimeout = 5 * time.Second
	defaultHTTPTimeout   = 5 * time.Second
	maxCacheEntries      = 10_000
)

// Deps are the collaborators a Service uses. Zero fields take defaults: the
// SDK's system DNS resolver and HTTP transparency-log client, an HTTP Trust
// Index client for cfg.TrustIndexURL (none when it is empty), time.Now and a
// 5 s lookup timeout. TL is only ever handed URLs that passed the trusted-TL
// allowlist.
type Deps struct {
	DNS           verify.DNSResolver
	TL            verify.TransparencyLogClient
	TrustIndex    TrustIndexClient
	Clock         func() time.Time
	LookupTimeout time.Duration
}

// Stats is a snapshot of the cache and lookup counters for a health endpoint.
type Stats struct {
	// Entries is the number of cached verdicts, expired ones included.
	Entries int
	// Hits and Misses count Lookup calls that reached the cache; exempt, IP
	// literal and wildcard hosts are settled before it.
	Hits   uint64
	Misses uint64
	// Lookups counts background lookups started; Errors counts those that
	// ended in StatusError.
	Lookups uint64
	Errors  uint64
}

// Service implements Verifier with a bounded verdict cache and single-flight
// background lookups. Lookups are bounded by Deps.LookupTimeout and survive
// cancellation of the request that started them, so a result is cached for the
// callers that follow.
type Service struct {
	dns           verify.DNSResolver
	tl            verify.TransparencyLogClient
	trustIndex    TrustIndexClient
	clock         func() time.Time
	lookupTimeout time.Duration
	logger        *slog.Logger

	trusted       tlAllowlist
	exempt        exemptSet
	cacheTTL      time.Duration
	errorTTL      time.Duration
	minTrustScore float64

	mu       sync.Mutex
	cache    *verdictCache
	inflight map[string]*flight
	closed   bool
	stats    Stats

	closeCtx context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// New validates cfg and builds a Service. The trusted-TL allowlist must not be
// empty: it is the trust root of the badge tier. A Trust Index is consulted
// only together with a positive min_trust_score, so one without the other is
// rejected. A nil logger discards logs.
func New(cfg config.Vetting, deps Deps, logger *slog.Logger) (*Service, error) {
	trusted, err := parseTrustedDomains(cfg.TrustedTLDomains)
	if err != nil {
		return nil, err
	}
	exempt, err := parseExemptHosts(cfg.ExemptHosts)
	if err != nil {
		return nil, err
	}
	if cfg.CacheTTL < 0 || cfg.RequestBudget < 0 || cfg.MinTrustScore < 0 {
		return nil, errors.New("vetting: cache_ttl, request_budget and min_trust_score must not be negative")
	}
	trustIndex, err := trustIndexFor(cfg, deps)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if strings.HasPrefix(strings.ToLower(cfg.TrustIndexURL), "http://") {
		logger.Warn("trust index url uses plaintext http; scores can be tampered with in transit")
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = defaultCacheTTL
	}
	if deps.DNS == nil {
		deps.DNS = verify.NewStandardDNSResolver()
	}
	if deps.TL == nil {
		deps.TL = newHTTPBadgeClient(nil)
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.LookupTimeout <= 0 {
		deps.LookupTimeout = defaultLookupTimeout
	}
	closeCtx, cancel := context.WithCancel(context.Background())
	return &Service{
		dns:           deps.DNS,
		tl:            deps.TL,
		trustIndex:    trustIndex,
		clock:         deps.Clock,
		lookupTimeout: deps.LookupTimeout,
		logger:        logger,
		trusted:       trusted,
		exempt:        exempt,
		cacheTTL:      cacheTTL,
		errorTTL:      min(defaultErrorTTL, cacheTTL),
		minTrustScore: cfg.MinTrustScore,
		cache:         newVerdictCache(maxCacheEntries),
		inflight:      make(map[string]*flight),
		closeCtx:      closeCtx,
		cancel:        cancel,
	}, nil
}

func newHTTPBadgeClient(client *http.Client) verify.TransparencyLogClient {
	return verify.NewHTTPTransparencyLogClient().WithHTTPClient(withoutRedirects(client))
}

func withoutRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	configured := *client
	configured.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &configured
}

func trustIndexFor(cfg config.Vetting, deps Deps) (TrustIndexClient, error) {
	trustIndex := deps.TrustIndex
	if trustIndex == nil && cfg.TrustIndexURL != "" {
		client, err := NewHTTPTrustIndexClient(cfg.TrustIndexURL, nil)
		if err != nil {
			return nil, err
		}
		trustIndex = client
	}
	switch {
	case cfg.MinTrustScore > 0 && trustIndex == nil:
		return nil, errors.New("vetting: min_trust_score requires trust_index_url")
	case cfg.MinTrustScore == 0 && trustIndex != nil:
		return nil, errors.New("vetting: trust_index_url requires a positive min_trust_score")
	}
	return trustIndex, nil
}

// flight is one in-progress lookup shared by every caller waiting on a host.
type flight struct {
	done    chan struct{}
	verdict Verdict
}

// Lookup implements Verifier. Exempt hosts, IP literals, wildcard patterns and
// names that cannot be DNS names are settled without a lookup; everything else
// is served from the cache or looked up in the background, with Lookup
// blocking up to wait (bounded by ctx) for the result.
func (s *Service) Lookup(ctx context.Context, host string, wait time.Duration) Verdict {
	fqdn, v, settled := s.classify(normalizeHost(host))
	if settled {
		return v
	}
	v, f := s.lookupCached(ctx, fqdn)
	if f == nil {
		return v
	}
	return awaitFlight(ctx, fqdn.String(), f, wait)
}

// Prewarm starts lookups for hosts that are not cached without waiting for
// them.
func (s *Service) Prewarm(ctx context.Context, hosts ...string) {
	for _, h := range hosts {
		s.Lookup(ctx, h, 0)
	}
}

// Close stops starting lookups, cancels those in flight and waits for them to
// finish. Cached verdicts stay readable.
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

// Stats returns a snapshot of the counters.
func (s *Service) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Entries = s.cache.len()
	return st
}

func (s *Service) classify(host string) (models.Fqdn, Verdict, bool) {
	switch {
	case host == "":
		return models.Fqdn{}, Verdict{Status: StatusError, Detail: "empty host"}, true
	case s.exempt.contains(host):
		return models.Fqdn{}, Verdict{Host: host, Status: StatusExempt, Detail: "exempt host"}, true
	case strings.Contains(host, "*"):
		return models.Fqdn{}, Verdict{Host: host, Status: StatusError, Detail: "wildcard host cannot be vetted"}, true
	case isIPLiteral(host):
		return models.Fqdn{}, Verdict{Host: host, Status: StatusUnregistered, Detail: "ip literal"}, true
	case isIPRange(host):
		return models.Fqdn{}, Verdict{Host: host, Status: StatusUnregistered, Detail: "ip range"}, true
	}
	fqdn, err := models.NewFqdn(host)
	if err != nil {
		return models.Fqdn{}, Verdict{Host: host, Status: StatusUnregistered, Detail: "invalid hostname"}, true
	}
	return fqdn, Verdict{}, false
}

// lookupCached returns an unexpired cached verdict, or the flight to wait on.
// A cached verdict in the last tenth of its TTL also starts a refresh. When the
// service is closed and nothing is cached the verdict is StatusError.
func (s *Service) lookupCached(ctx context.Context, fqdn models.Fqdn) (Verdict, *flight) {
	host := fqdn.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if e, ok := s.cache.get(host); ok && now.Before(e.expiresAt) {
		s.stats.Hits++
		if !now.Before(e.refreshAt) {
			s.startLocked(ctx, fqdn)
		}
		return e.verdict, nil
	}
	s.stats.Misses++
	f := s.startLocked(ctx, fqdn)
	if f == nil {
		return Verdict{Host: host, Status: StatusError, Detail: "vetting service closed"}, nil
	}
	return Verdict{}, f
}

func (s *Service) startLocked(ctx context.Context, fqdn models.Fqdn) *flight {
	if s.closed {
		return nil
	}
	host := fqdn.String()
	if f, ok := s.inflight[host]; ok {
		return f
	}
	f := &flight{done: make(chan struct{})}
	s.inflight[host] = f
	s.stats.Lookups++
	s.wg.Add(1)
	go s.run(ctx, fqdn, f)
	return f
}

func (s *Service) run(ctx context.Context, fqdn models.Fqdn, f *flight) {
	defer s.wg.Done()
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.lookupTimeout)
	defer cancel()
	stop := context.AfterFunc(s.closeCtx, cancel)
	defer stop()

	v := s.resolve(lctx, fqdn)
	published, prev, had := s.store(fqdn.String(), v)
	f.verdict = published
	close(f.done)
	if !had || prev != published.Status {
		s.logger.LogAttrs(lctx, slog.LevelInfo, "destination verdict",
			slog.String("host", published.Host), slog.String("status", published.Status.String()),
			slog.String("detail", published.Detail))
	}
}

// store caches v, releases the flight and returns the verdict to publish with
// the status it replaced. A lookup that failed while a healthy verdict is still
// unexpired does not replace it: a dependency blip during refresh-ahead must
// not turn a registered host into a denial.
func (s *Service) store(host string, v Verdict) (Verdict, Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, host)
	var prev Status
	e, had := s.cache.get(host)
	if had {
		prev = e.verdict.Status
	}
	now := s.clock()
	if v.Status == StatusError {
		s.stats.Errors++
		if had && e.verdict.Status != StatusError && now.Before(e.expiresAt) {
			return e.verdict, prev, had
		}
		s.cache.put(host, v, now, s.errorTTL)
		return v, prev, had
	}
	s.cache.put(host, v, now, s.cacheTTL)
	return v, prev, had
}

func awaitFlight(ctx context.Context, host string, f *flight, wait time.Duration) Verdict {
	pending := Verdict{Host: host, Status: StatusUnknown, Detail: "lookup in progress"}
	if wait <= 0 {
		return pending
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-f.done:
		return f.verdict
	case <-timer.C:
		return pending
	case <-ctx.Done():
		return pending
	}
}
