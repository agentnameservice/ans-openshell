// Package app assembles and serves the OpenShell supervisor middleware. It is
// the reusable core entrypoint: the production command calls Run with no
// customization, while a caller that wants to register additional capability
// transforms (for example the demo's commerce tutorial) passes options that
// receive the built *middleware.Service before it starts serving.
package app

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/grpc"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/grpcserver"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	"github.com/agentnameservice/ans-openshell/internal/middleware"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

const (
	// DefaultListen is the gRPC listen address when the config leaves it empty.
	DefaultListen = ":50051"
	// DefaultHealthListen serves plaintext HTTP /healthz and /readyz for probes.
	DefaultHealthListen = ":8081"
	healthCheckInterval = 5 * time.Second
	drainDelay          = 3 * time.Second
)

// Config is the generic middleware configuration. It is the YAML file shape the
// production binary loads; callers that layer extra capabilities keep their own
// (for example commerce) config separate and wire it through an Option.
type Config struct {
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

// options collects the optional customizations a caller may apply.
type options struct {
	version   string
	customize func(context.Context, *middleware.Service, *slog.Logger) error
}

// Option customizes a Run invocation.
type Option func(*options)

// WithVersion sets the implementation version advertised in the manifest and logs.
func WithVersion(v string) Option {
	return func(o *options) {
		if v != "" {
			o.version = v
		}
	}
}

// WithCustomize registers a hook that runs after the *middleware.Service is
// built and before the server starts, letting the caller register capability
// transforms and a discoverer (e.g. svc.AddTransform / svc.WithDiscoverer). The
// hook may start background work; returning an error aborts startup.
func WithCustomize(fn func(context.Context, *middleware.Service, *slog.Logger) error) Option {
	return func(o *options) { o.customize = fn }
}

// Run assembles the middleware from cfg and serves it until ctx is cancelled.
// It wires identity, caller authentication, optional destination vetting, the
// gRPC server and readiness, then applies any options (which may register
// capability transforms) before serving.
func Run(ctx context.Context, cfg Config, logger *slog.Logger, opts ...Option) error {
	o := options{version: "dev"}
	for _, apply := range opts {
		apply(&o)
	}
	return serve(ctx, cfg, o, logger)
}

func serve(ctx context.Context, cfg Config, o options, logger *slog.Logger) error {
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	// An empty HealthListen disables the health endpoints; callers that want the
	// default apply it before calling (see the production main). We do not
	// default it here so tests and embedders can opt out.
	if len(cfg.Identities) == 0 {
		return errors.New("identities: at least one identity is required")
	}

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
	svc := middleware.NewService(registry, authz, vet, serviceConfig(cfg, o.version), logger)

	// Apply caller customizations (e.g. register capability transforms).
	if o.customize != nil {
		if err := o.customize(ctx, svc, logger); err != nil {
			return err
		}
	}

	middlewarev1.RegisterSupervisorMiddlewareServer(srv.Registrar(), svc)
	middlewarev1.RegisterHttpResponsePreReturnServer(srv.Registrar(), middleware.NewPreReturnService(logger))
	logger.InfoContext(ctx, "http response pre-return stage enabled")
	go srv.WatchReadiness(ctx, healthCheckInterval, readinessProbe(ctx, registry, auth, logger))
	logger.InfoContext(ctx, "ans-openshell-middleware starting",
		"version", o.version, "identities", registry.Names(), "vetting", vet != nil)
	return srv.Serve(ctx)
}

// serviceConfig maps the generic configuration onto the middleware service.
func serviceConfig(cfg Config, version string) middleware.Config {
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
