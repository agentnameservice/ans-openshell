// Command ans-openshell-middleware serves the OpenShell supervisor middleware
// that signs a sandbox's outbound requests as its registered ANS agent.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/capability"
	"github.com/agentnameservice/ans-openshell/internal/commerce"
	"github.com/agentnameservice/ans-openshell/internal/commercekey"
	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/grpcserver"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	"github.com/agentnameservice/ans-openshell/internal/logging"
	"github.com/agentnameservice/ans-openshell/internal/middleware"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	defaultListen       = ":50051"
	defaultHealthListen = ":8081"
	healthCheckInterval = 5 * time.Second
	drainDelay          = 3 * time.Second
)

type fileConfig struct {
	Listen string `yaml:"listen"`
	// HealthListen serves plaintext HTTP /healthz and /readyz for probes.
	// Empty disables it; the default is :8081.
	HealthListen      string                     `yaml:"health_listen"`
	TLS               config.TLS                 `yaml:"tls"`
	Auth              config.Auth                `yaml:"auth"`
	TransparencyLog   config.TransparencyLog     `yaml:"transparency_log"`
	Identities        map[string]identity.Config `yaml:"identities"`
	SandboxIdentities map[string]string          `yaml:"sandbox_identities"`
	// Vetting enables destination vetting when present; policies may only set
	// destination_policy if it is.
	Vetting *config.Vetting `yaml:"vetting"`
	// MaxPayloadBytes and RequestTimeout are advertised in the manifest binding.
	MaxPayloadBytes uint64        `yaml:"max_payload_bytes"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	// Commerce enables commerce rewriting for Tier 2 demo.
	Commerce config.Commerce `yaml:"commerce"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ans-openshell-middleware:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "", "path to the YAML configuration (required)")
		listen     = flag.String("listen", "", "listen address; overrides the configuration file")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
		logFormat  = flag.String("log-format", "json", "json or text")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Fprintln(os.Stdout, version)
		return nil
	}
	if *configPath == "" {
		return errors.New("--config is required")
	}
	logger, err := logging.New(*logLevel, *logFormat, os.Stderr)
	if err != nil {
		return err
	}
	var cfg fileConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.HealthListen == "" {
		cfg.HealthListen = defaultHealthListen
	}
	if len(cfg.Identities) == 0 {
		return errors.New("identities: at least one identity is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, logger)
}

func serve(ctx context.Context, cfg fileConfig, logger *slog.Logger) error {
	auth, err := extauth.NewVerifier(cfg.Auth, logger)
	if err != nil {
		return err
	}
	go auth.Run(ctx)
	if !cfg.TLS.Enabled() && !cfg.Auth.AllowInsecureNoAuth {
		logger.WarnContext(ctx, "listening without TLS while extension authentication is on; gateway bearer tokens travel in the clear")
	}

	registry, err := identity.NewRegistry(ctx, cfg.Identities, cfg.TransparencyLog, logger)
	if err != nil {
		return err
	}
	defer registry.Close()
	authz, err := middleware.NewSandboxIdentities(cfg.SandboxIdentities, registry)
	if err != nil {
		return err
	}

	var vet vetting.Verifier
	if cfg.Vetting != nil {
		vetSvc, vetErr := vetting.New(*cfg.Vetting, vetting.Deps{}, logger)
		if vetErr != nil {
			return vetErr
		}
		defer vetSvc.Close()
		vet = vetSvc
	}

	srv, err := grpcserver.New(ctx, grpcserver.Options{
		Listen:       cfg.Listen,
		HealthListen: cfg.HealthListen,
		TLS:          cfg.TLS,
		Unary:        []grpc.UnaryServerInterceptor{auth.UnaryInterceptor()},
		Stream:       []grpc.StreamServerInterceptor{auth.StreamInterceptor()},
		DrainDelay:   drainDelay,
	}, logger)
	if err != nil {
		return err
	}
	svc := middleware.NewService(registry, authz, vet, serviceConfig(cfg), logger)

	// Wire commerce if enabled
	if cfg.Commerce.Enabled() {
		transform, startPrefetch, err := setupCommerce(cfg, logger)
		if err != nil {
			return err
		}

		// Wire the discoverer (no I/O at startup; discovery happens per-request)
		ttl := cfg.Commerce.DiscoveryTTL
		if ttl == 0 {
			ttl = 10 * time.Minute //nolint:mnd // default TTL for agent-card/tools-list discovery cache
		}
		client := &http.Client{Timeout: 10 * time.Second} //nolint:mnd // discovery fetch timeout
		svc.WithDiscoverer(capability.NewHTTPDiscoverer(client, ttl))

		svc.AddTransform(transform)
		if startPrefetch != nil {
			startPrefetch()
		}
		logger.InfoContext(ctx, "commerce rewriter enabled")
	}

	middlewarev1.RegisterSupervisorMiddlewareServer(srv.Registrar(), svc)
	middlewarev1.RegisterHttpResponsePreReturnServer(srv.Registrar(), middleware.NewPreReturnService(logger))
	logger.InfoContext(ctx, "http response pre-return stage enabled")
	go srv.WatchReadiness(ctx, healthCheckInterval, readinessProbe(ctx, registry, auth, logger))
	logger.InfoContext(ctx, "ans-openshell-middleware starting",
		"version", version, "identities", registry.Names(), "vetting", vet != nil, "commerce", cfg.Commerce.Enabled())
	return srv.Serve(ctx)
}

// setupCommerce builds the commerce transform and returns an optional demo-prefetch closure.
func setupCommerce(cfg fileConfig, logger *slog.Logger) (capability.Transform, func(), error) {
	if err := cfg.Commerce.Validate(); err != nil {
		return nil, nil, fmt.Errorf("commerce config: %w", err)
	}
	keyPath := cfg.Commerce.CommerceDPoPKeyPath
	if keyPath == "" {
		keyPath = os.Getenv("COMMERCE_DPOP_KEY")
	}
	key, err := commercekey.Load(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("commerce key: %w", err)
	}
	cache := commerce.NewMandateCache()
	authority := commerce.NewHTTPAuthority(cfg.Commerce.AuthorityMCPURL)
	clock := realClock{}
	nonce := &uuidNonce{}
	deps := commerce.Deps{
		Key:       key,
		Cache:     cache,
		Authority: authority,
		Clock:     clock,
		Nonce:     nonce,
	}
	commerceCfg := commerce.Config{
		SellerMCPURL: cfg.Commerce.SellerMCPURL,
		SellerANS:    cfg.Commerce.SellerANS,
		ScopePrefix:  cfg.Commerce.ScopeHint,
		SubjectANS:   cfg.Commerce.SubjectANS,
		MaxBodyBytes: cfg.Commerce.MaxBodyBytes,
	}
	sellerHost, err := middleware.ParseSellerHost(cfg.Commerce.SellerMCPURL)
	if err != nil {
		return nil, nil, fmt.Errorf("commerce seller host: %w", err)
	}
	rewriter := middleware.NewCommerceRewriter(deps, commerceCfg, sellerHost, logger)

	// Return optional demo-prefetch closure if demo fields are set
	var prefetch func()
	if cfg.Commerce.DemoQuoteID != "" && cfg.Commerce.DemoAmount > 0 && cfg.Commerce.DemoCurrency != "" {
		prefetch = func() {
			go prefetchDemoMandate(cache, key, cfg.Commerce, authority, clock, logger)
		}
	}
	return rewriter, prefetch, nil
}

// serviceConfig maps the file configuration onto the middleware service.
func serviceConfig(cfg fileConfig) middleware.Config {
	c := middleware.Config{
		Audience:                   cfg.Auth.Audience,
		MaxPayloadBytes:            cfg.MaxPayloadBytes,
		RequestTimeout:             cfg.RequestTimeout,
		ImplementationVersion:      version,
		RequireAuthenticatedCaller: !cfg.Auth.AllowInsecureNoAuth,
	}
	if cfg.Vetting != nil {
		c.VettingBudget = cfg.Vetting.RequestBudget
	}
	return c
}

// keyHolder reports whether a gateway verification key is held;
// extauth.Verifier satisfies it.
type keyHolder interface{ Ready() bool }

// identityHealth reports the configured identities and which of them lack
// usable artifacts; identity.Registry satisfies it.
type identityHealth interface {
	Names() []string
	Unhealthy() []string
}

// readinessProbe ties readiness to what the replica can actually do: it must
// hold a gateway verification key and at least one identity with usable
// artifacts. A single identity whose artifacts lapse is denied per request and
// logged here, but does not take the other identities out of service. Every
// change of state is logged, the first evaluation included.
func readinessProbe(ctx context.Context, registry identityHealth, auth keyHolder, logger *slog.Logger) func() bool {
	var last *healthState
	return func() bool {
		next := healthState{authReady: auth.Ready(), unhealthy: registry.Unhealthy(), total: len(registry.Names())}
		if last == nil || next.ready() != last.ready() || !slices.Equal(next.unhealthy, last.unhealthy) {
			logger.LogAttrs(ctx, next.level(), "readiness evaluated",
				slog.Bool("ready", next.ready()), slog.Bool("gateway_keys", next.authReady),
				slog.Any("unhealthy_identities", next.unhealthy))
		}
		last = &next
		return next.ready()
	}
}

type healthState struct {
	authReady bool
	unhealthy []string
	total     int
}

func (h healthState) ready() bool { return h.authReady && len(h.unhealthy) < h.total }

func (h healthState) level() slog.Level {
	if h.ready() && len(h.unhealthy) == 0 {
		return slog.LevelInfo
	}
	return slog.LevelWarn
}

// realClock implements commerce.Clock using time.Now().
type realClock struct{}

func (realClock) NowUnix() int64 { return time.Now().Unix() }

// uuidNonce implements commerce.Nonce using crypto/rand.
type uuidNonce struct{}

func (u *uuidNonce) JTI() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	// UUID v4 format: set version (4) and variant (10b)
	const (
		uuidVersion4    = 0x40
		uuidVariant     = 0x80
		uuidVersionMask = 0x0f
		uuidVariantMask = 0x3f
	)
	buf[6] = (buf[6] & uuidVersionMask) | uuidVersion4
	buf[8] = (buf[8] & uuidVariantMask) | uuidVariant
	return hex.EncodeToString(buf[:])
}

// prefetchDemoMandate warms the mandate cache with a demo quote in the background.
func prefetchDemoMandate(cache *commerce.MandateCache, key *commercekey.Key, cfg config.Commerce,
	authority commerce.AuthorityClient, clock commerce.Clock, logger *slog.Logger) {
	qk := commerce.QuoteKey{
		QuoteID:  cfg.DemoQuoteID,
		Amount:   cfg.DemoAmount,
		Currency: cfg.DemoCurrency,
	}
	_, _, err := cache.GetOrFetch(
		context.Background(), //nolint:contextcheck // Prefetch uses background context after server started
		qk,
		key.JKT(),
		cfg.SellerANS,
		cfg.ScopeHint,
		authority,
		clock,
		func(qk commerce.QuoteKey) commerce.MandateInput {
			return commerce.MandateInput{
				QuoteID:         qk.QuoteID,
				Total:           qk.Amount,
				Currency:        qk.Currency,
				MerchantANS:     cfg.SellerANS,
				ScopeHint:       cfg.ScopeHint,
				SubjectANS:      cfg.SubjectANS,
				TravelerDPoPJWK: key.PublicJWK(),
			}
		},
	)
	if err != nil {
		logger.WarnContext(context.Background(), "demo mandate prefetch failed", "error", err)
	} else {
		logger.InfoContext(context.Background(), "demo mandate prefetched", "quote_id", cfg.DemoQuoteID)
	}
}
