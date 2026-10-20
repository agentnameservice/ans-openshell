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
	middlewarev1.RegisterSupervisorMiddlewareServer(srv.Registrar(), svc)
	go srv.WatchReadiness(ctx, healthCheckInterval, readinessProbe(ctx, registry, auth, logger))
	logger.InfoContext(ctx, "ans-openshell-middleware starting",
		"version", version, "identities", registry.Names(), "vetting", vet != nil)
	return srv.Serve(ctx)
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
