// Package grpcserver starts the extension's gRPC listener with optional TLS,
// a standard health service and graceful shutdown.
package grpcserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const (
	defaultShutdownGrace = 10 * time.Second
	minClientPingPeriod  = 10 * time.Second
	defaultMaxRecvBytes  = 8 << 20
	healthReadTimeout    = 5 * time.Second
	keepaliveTime        = 2 * time.Minute
	keepaliveTimeout     = 20 * time.Second
	// serveErrorSlots buffers one error from each listener goroutine.
	serveErrorSlots = 2
)

// Options configure a Server.
type Options struct {
	Listen string
	TLS    config.TLS
	// Interceptors are installed on every RPC (authentication first).
	Unary  []grpc.UnaryServerInterceptor
	Stream []grpc.StreamServerInterceptor
	// MaxRecvBytes bounds inbound messages; OpenShell sends at most 4 MiB
	// bodies plus headers, so the default of 8 MiB leaves headroom.
	MaxRecvBytes int
	// ShutdownGrace bounds GracefulStop before Stop is forced.
	ShutdownGrace time.Duration
	// HealthListen, when set, serves plaintext HTTP GET /healthz (process is
	// serving) and /readyz (SetHealthy state) for orchestrator probes, which
	// cannot reach the authenticated, TLS gRPC health service.
	HealthListen string
	// DrainDelay is how long Serve reports not-ready before it stops accepting
	// RPCs, so load balancers and probes see the change first.
	DrainDelay time.Duration
}

// Server owns the listener, the gRPC server and its health service.
type Server struct {
	grpc      *grpc.Server
	health    *health.Server
	lis       net.Listener
	healthLis net.Listener
	ready     atomic.Bool
	mu        sync.Mutex
	draining  bool
	opts      Options
	logger    *slog.Logger
}

// New builds the server and binds the listener so configuration errors (bad
// address, unreadable certificate) surface before any service is registered.
func New(ctx context.Context, opts Options, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if err := opts.TLS.Validate(); err != nil {
		return nil, err
	}
	if opts.MaxRecvBytes <= 0 {
		opts.MaxRecvBytes = defaultMaxRecvBytes
	}
	if opts.ShutdownGrace <= 0 {
		opts.ShutdownGrace = defaultShutdownGrace
	}
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(opts.MaxRecvBytes),
		grpc.ChainUnaryInterceptor(opts.Unary...),
		grpc.ChainStreamInterceptor(opts.Stream...),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: minClientPingPeriod, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: keepaliveTime, Timeout: keepaliveTimeout}),
	}
	if opts.TLS.Enabled() {
		cert, err := tls.LoadX509KeyPair(opts.TLS.CertFile, opts.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load serving certificate: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})))
	}
	lc := &net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", opts.Listen, err)
	}
	s := &Server{grpc: grpc.NewServer(serverOpts...), health: health.NewServer(), lis: lis, opts: opts, logger: logger}
	if opts.HealthListen != "" {
		if s.healthLis, err = lc.Listen(ctx, "tcp", opts.HealthListen); err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("listen on health address %q: %w", opts.HealthListen, err)
		}
	}
	grpc_health_v1.RegisterHealthServer(s.grpc, s.health)
	s.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	return s, nil
}

// Registrar returns the underlying gRPC server for service registration.
func (s *Server) Registrar() grpc.ServiceRegistrar { return s.grpc }

// Addr is the bound gRPC listener address.
func (s *Server) Addr() net.Addr { return s.lis.Addr() }

// HealthAddr is the bound HTTP health listener address, or nil when
// HealthListen was not set.
func (s *Server) HealthAddr() net.Addr {
	if s.healthLis == nil {
		return nil
	}
	return s.healthLis.Addr()
}

// SetHealthy flips the gRPC health service between SERVING and NOT_SERVING and
// the HTTP /readyz endpoint between 200 and 503. A new server is not ready
// until its owner says so, and once Serve starts draining it stays not ready.
// Repeating the current state changes nothing, so health watchers only see
// transitions.
func (s *Server) SetHealthy(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if healthy && s.draining {
		return
	}
	if s.ready.Swap(healthy) == healthy {
		return
	}
	status := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if healthy {
		status = grpc_health_v1.HealthCheckResponse_SERVING
	}
	s.health.SetServingStatus("", status)
}

// drain takes readiness away for good: later SetHealthy(true) calls, such as
// a readiness tick racing the shutdown, are ignored.
func (s *Server) drain() {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
	s.SetHealthy(false)
}

// WatchReadiness applies probe's verdict immediately and then on every
// interval until ctx ends, so a server is never reported ready before its owner
// has checked that it can serve. A non-positive interval applies the probe once
// and returns.
func (s *Server) WatchReadiness(ctx context.Context, interval time.Duration, probe func() bool) {
	s.SetHealthy(probe())
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SetHealthy(probe())
		}
	}
}

func (s *Server) healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

// Serve runs until ctx is canceled or the listener fails, then stops
// gracefully. It returns once in-flight RPCs have drained or ShutdownGrace
// has passed, whichever comes first; a handler that ignores its context past
// the grace period is abandoned to process exit.
func (s *Server) Serve(ctx context.Context) error {
	errc := make(chan error, serveErrorSlots)
	go func() {
		s.logger.InfoContext(ctx, "grpc server listening", "addr", s.lis.Addr().String(), "tls", s.opts.TLS.Enabled())
		errc <- s.grpc.Serve(s.lis)
	}()
	var httpSrv *http.Server
	if s.healthLis != nil {
		httpSrv = &http.Server{Handler: s.healthHandler(), ReadHeaderTimeout: healthReadTimeout}
		go func() {
			s.logger.InfoContext(ctx, "health endpoints listening", "addr", s.healthLis.Addr().String())
			if err := httpSrv.Serve(s.healthLis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("health serve: %w", err)
			}
		}()
	}
	var err error
	select {
	case err = <-errc:
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		} else if err != nil {
			err = fmt.Errorf("grpc serve: %w", err)
		}
	case <-ctx.Done():
	}
	s.drain()
	s.health.Shutdown()
	if s.opts.DrainDelay > 0 {
		time.Sleep(s.opts.DrainDelay)
	}
	s.stop()
	if httpSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.opts.ShutdownGrace)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}
	return err
}

func (s *Server) stop() {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(s.opts.ShutdownGrace):
		// GracefulStop holds the server mutex while it waits for handlers, so
		// Stop can block behind it until they return; it must not hold up exit.
		go s.grpc.Stop()
		s.logger.Warn("grpc shutdown grace exceeded; abandoning in-flight handlers")
	}
}
