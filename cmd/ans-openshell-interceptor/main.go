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
	healthCheckInterval = 5 * time.Second
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, logger)
}

func serve(ctx context.Context, cfg fileConfig, logger *slog.Logger) error {
	svcCfg, err := serviceConfig(cfg)
	if err != nil {
		return err
	}
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
	svc := interceptor.NewService(vet, svcCfg, logger)
	interceptorv1.RegisterGatewayInterceptorServer(srv.Registrar(), svc)
	go srv.WatchReadiness(ctx, healthCheckInterval, readinessProbe(ctx, auth, logger))
	logger.InfoContext(ctx, "ans-openshell-interceptor starting", "version", version, "mode", svcCfg.Mode.String())
	return srv.Serve(ctx)
}

// serviceConfig maps the file configuration onto the interceptor service. The
// destination policy defaults to observe. vetting.request_budget is a
// middleware setting and is refused rather than silently ignored: the
// interceptor bounds lookups with lookup_wait.
func serviceConfig(cfg fileConfig) (interceptor.Config, error) {
	if cfg.Vetting.RequestBudget != 0 {
		return interceptor.Config{}, errors.New("vetting.request_budget applies to the middleware; the interceptor bounds lookups with lookup_wait")
	}
	if cfg.LookupWait < 0 {
		return interceptor.Config{}, errors.New("lookup_wait must not be negative")
	}
	policy := cfg.DestinationPolicy
	if policy == "" {
		policy = defaultPolicy
	}
	mode, err := vetting.ParseMode(policy)
	if err != nil {
		return interceptor.Config{}, err
	}
	return interceptor.Config{
		Audience:              cfg.Auth.Audience,
		Mode:                  mode,
		ImplementationVersion: version,
		LookupWait:            cfg.LookupWait,
	}, nil
}

// keyHolder reports whether a gateway verification key is held;
// extauth.Verifier satisfies it.
type keyHolder interface{ Ready() bool }

// readinessProbe ties readiness to the verifier holding a gateway key and logs
// every change of state, the first evaluation included.
func readinessProbe(ctx context.Context, auth keyHolder, logger *slog.Logger) func() bool {
	var last *bool
	return func() bool {
		ready := auth.Ready()
		if last == nil || *last != ready {
			level := slog.LevelWarn
			if ready {
				level = slog.LevelInfo
			}
			logger.LogAttrs(ctx, level, "readiness evaluated",
				slog.Bool("ready", ready), slog.String("reason", "gateway verification keys"))
		}
		last = &ready
		return ready
	}
}
