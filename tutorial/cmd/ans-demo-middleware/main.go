// Command ans-demo-middleware is the DEV-ONLY demo binary. It is the production
// middleware (app.Run) plus the commerce capability transform registered as a
// tutorial of how to extend the middleware. It is not shipped; the production
// binary (cmd/ans-openshell-middleware) contains no commerce code.
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
	"syscall"
	"time"

	"github.com/agentnameservice/ans-openshell/app"
	"github.com/agentnameservice/ans-openshell/internal/capability"
	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/logging"
	"github.com/agentnameservice/ans-openshell/internal/middleware"
	"github.com/agentnameservice/ans-openshell/tutorial/commerce"
	"github.com/agentnameservice/ans-openshell/tutorial/commercekey"
	tutorialcfg "github.com/agentnameservice/ans-openshell/tutorial/config"
	"github.com/agentnameservice/ans-openshell/tutorial/transform"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ans-demo-middleware:", err)
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
	var cfg tutorialcfg.FileConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if cfg.HealthListen == "" {
		cfg.HealthListen = app.DefaultHealthListen
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := []app.Option{app.WithVersion(version)}
	if cfg.Commerce.Enabled() {
		opts = append(opts, app.WithCustomize(commerceCustomizer(cfg.Commerce)))
	}
	return app.Run(ctx, cfg.Config, logger, opts...)
}

// commerceCustomizer registers the commerce transform + discoverer and starts
// the optional demo prefetch, via app.WithCustomize.
func commerceCustomizer(cc tutorialcfg.Commerce) func(context.Context, *middleware.Service, *slog.Logger) error {
	return func(ctx context.Context, svc *middleware.Service, logger *slog.Logger) error {
		rewriter, startPrefetch, err := setupCommerce(cc, logger)
		if err != nil {
			return err
		}
		ttl := cc.DiscoveryTTL
		if ttl == 0 {
			ttl = 10 * time.Minute //nolint:mnd // default TTL for agent-card/tools-list discovery cache
		}
		client := &http.Client{Timeout: 10 * time.Second} //nolint:mnd // discovery fetch timeout
		svc.WithDiscoverer(capability.NewHTTPDiscoverer(client, ttl))
		svc.AddTransform(rewriter)
		if startPrefetch != nil {
			startPrefetch()
		}
		logger.InfoContext(ctx, "commerce rewriter enabled")
		return nil
	}
}

// setupCommerce builds the commerce transform and an optional demo-prefetch closure.
func setupCommerce(cc tutorialcfg.Commerce, logger *slog.Logger) (capability.Transform, func(), error) {
	if err := cc.Validate(); err != nil {
		return nil, nil, fmt.Errorf("commerce config: %w", err)
	}
	keyPath := cc.CommerceDPoPKeyPath
	if keyPath == "" {
		keyPath = os.Getenv("COMMERCE_DPOP_KEY")
	}
	key, err := commercekey.Load(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("commerce key: %w", err)
	}
	cache := commerce.NewMandateCache()
	authority := commerce.NewHTTPAuthority(cc.AuthorityMCPURL)
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
		SellerMCPURL: cc.SellerMCPURL,
		SellerANS:    cc.SellerANS,
		ScopePrefix:  cc.ScopeHint,
		SubjectANS:   cc.SubjectANS,
		MaxBodyBytes: cc.MaxBodyBytes,
	}
	sellerHost, err := transform.ParseSellerHost(cc.SellerMCPURL)
	if err != nil {
		return nil, nil, fmt.Errorf("commerce seller host: %w", err)
	}
	rewriter := transform.NewCommerceRewriter(deps, commerceCfg, sellerHost, logger)

	var prefetch func()
	if cc.DemoQuoteID != "" && cc.DemoAmount > 0 && cc.DemoCurrency != "" {
		prefetch = func() {
			go prefetchDemoMandate(cache, key, cc, authority, clock, logger)
		}
	}
	return rewriter, prefetch, nil
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
func prefetchDemoMandate(cache *commerce.MandateCache, key *commercekey.Key, cc tutorialcfg.Commerce,
	authority commerce.AuthorityClient, clock commerce.Clock, logger *slog.Logger) {
	qk := commerce.QuoteKey{
		QuoteID:  cc.DemoQuoteID,
		Amount:   cc.DemoAmount,
		Currency: cc.DemoCurrency,
	}
	_, _, err := cache.GetOrFetch(
		context.Background(), //nolint:contextcheck // Prefetch uses background context after server started
		qk,
		key.JKT(),
		cc.SellerANS,
		cc.ScopeHint,
		authority,
		clock,
		func(qk commerce.QuoteKey) commerce.MandateInput {
			return commerce.MandateInput{
				QuoteID:         qk.QuoteID,
				Total:           qk.Amount,
				Currency:        qk.Currency,
				MerchantANS:     cc.SellerANS,
				ScopeHint:       cc.ScopeHint,
				SubjectANS:      cc.SubjectANS,
				TravelerDPoPJWK: key.PublicJWK(),
			}
		},
	)
	if err != nil {
		logger.WarnContext(context.Background(), "demo mandate prefetch failed", "error", err)
	} else {
		logger.InfoContext(context.Background(), "demo mandate prefetched", "quote_id", cc.DemoQuoteID)
	}
}
