// Command ans-openshell-interceptor serves the OpenShell gateway interceptor
// that vets destination hosts in proposed sandbox policies against ANS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/agentnameservice/ans-openshell/gen/openshell/interceptorv1"
	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/grpcserver"
	"github.com/agentnameservice/ans-openshell/internal/interceptor"
	"github.com/agentnameservice/ans-openshell/internal/logging"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	defaultListen       = ":50052"
	defaultHealthListen = ":8081"
	defaultPolicy       = "observe"
	drainDelay          = 3 * time.Second
	healthCheckInterval = 15 * time.Second
)

type fileConfig struct {
	Listen string `yaml:"listen"`
	// HealthListen serves plaintext HTTP /healthz and /readyz for probes.
	// Empty disables it; the default is :8081.
	HealthListen string      `yaml:"health_listen"`
	TLS          config.TLS  `yaml:"tls"`
	Auth         config.Auth `yaml:"auth"`
	// DestinationPolicy is observe (default) or require_registered; off
	// disables vetting.
	DestinationPolicy string `yaml:"destination_policy"`
	// LookupWait bounds how long one require_registered evaluation waits for
	// cold lookups. Keep it below the registration's timeout in the gateway
	// configuration: the gateway does not propagate its deadline.
	LookupWait time.Duration  `yaml:"lookup_wait"`
	Vetting    config.Vetting `yaml:"vetting"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ans-openshell-interceptor:", err)
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
	if cfg.DestinationPolicy == "" {
		cfg.DestinationPolicy = defaultPolicy
	}
	mode, err := vetting.ParseMode(cfg.DestinationPolicy)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	auth, err := extauth.NewVerifier(cfg.Auth, logger)
	if err != nil {
		return err
	}
	go auth.Run(ctx)
	if !cfg.TLS.Enabled() && !cfg.Auth.AllowInsecureNoAuth {
		logger.WarnContext(ctx, "listening without TLS while extension authentication is on; gateway bearer tokens travel in the clear")
	}

	vet, err := vetting.New(cfg.Vetting, vetting.Deps{}, logger)
	if err != nil {
		return err
	}
	defer vet.Close()

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
	svc := interceptor.NewService(vet, interceptor.Config{
		Audience:              cfg.Auth.Audience,
		Mode:                  mode,
		ImplementationVersion: version,
		LookupWait:            cfg.LookupWait,
	}, logger)
	interceptorv1.RegisterGatewayInterceptorServer(srv.Registrar(), svc)
	go watchHealth(ctx, srv, auth, logger)
	logger.InfoContext(ctx, "ans-openshell-interceptor starting", "version", version, "mode", mode.String())
	return srv.Serve(ctx)
}

// watchHealth keeps readiness tied to the verifier holding a gateway key.
func watchHealth(ctx context.Context, srv *grpcserver.Server, auth *extauth.Verifier, logger *slog.Logger) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	ready := auth.Ready()
	srv.SetHealthy(ready)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if now := auth.Ready(); now != ready {
				ready = now
				srv.SetHealthy(ready)
				logger.WarnContext(ctx, "readiness changed", "ready", ready, "reason", "gateway verification keys")
			}
		}
	}
}
