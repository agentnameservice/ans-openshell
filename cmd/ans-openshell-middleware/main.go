// Command ans-openshell-middleware serves the OpenShell supervisor middleware
// that signs a sandbox's outbound requests as its registered ANS agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
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
	healthCheckInterval = 30 * time.Second
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
	var vettingBudget time.Duration
	if cfg.Vetting != nil {
		vetSvc, vetErr := vetting.New(*cfg.Vetting, vetting.Deps{}, logger)
		if vetErr != nil {
			return vetErr
		}
		defer vetSvc.Close()
		vet = vetSvc
		vettingBudget = cfg.Vetting.RequestBudget
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
	svc := middleware.NewService(registry, authz, vet, middleware.Config{
		Audience:                   cfg.Auth.Audience,
		MaxPayloadBytes:            cfg.MaxPayloadBytes,
		RequestTimeout:             cfg.RequestTimeout,
		ImplementationVersion:      version,
		VettingBudget:              vettingBudget,
		RequireAuthenticatedCaller: !cfg.Auth.AllowInsecureNoAuth,
	}, logger)
	middlewarev1.RegisterSupervisorMiddlewareServer(srv.Registrar(), svc)
	go watchHealth(ctx, srv, registry, auth, logger)
	logger.InfoContext(ctx, "ans-openshell-middleware starting",
		"version", version, "identities", registry.Names(), "vetting", vet != nil)
	return srv.Serve(ctx)
}

// watchHealth keeps readiness tied to what the replica can actually do: it
// must hold a gateway verification key and at least one identity with usable
// artifacts. A single identity whose artifacts lapse is denied per request and
// logged here, but does not take the other identities out of service.
func watchHealth(ctx context.Context, srv *grpcserver.Server, registry *identity.Registry, auth *extauth.Verifier,
	logger *slog.Logger) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	state := healthState{}
	for {
		next := healthState{authReady: auth.Ready(), unhealthy: registry.Unhealthy(), total: len(registry.Names())}
		if next.ready() != state.ready() || !slices.Equal(next.unhealthy, state.unhealthy) {
			srv.SetHealthy(next.ready())
			logger.LogAttrs(ctx, next.level(), "readiness evaluated",
				slog.Bool("ready", next.ready()), slog.Bool("gateway_keys", next.authReady),
				slog.Any("unhealthy_identities", next.unhealthy))
		}
		state = next
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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
