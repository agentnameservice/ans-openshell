package extauth

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const testMethod = "/svc/Method"

func assertUnauthenticated(t *testing.T, err error, token string) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("error = %v, want codes.Unauthenticated", err)
	}
	if st.Message() != unauthenticatedMessage {
		t.Fatalf("status message = %q, want %q", st.Message(), unauthenticatedMessage)
	}
	if token != "" && strings.Contains(st.Message(), token) {
		t.Fatalf("status message echoes the token: %q", st.Message())
	}
}

func TestUnaryInterceptor(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	key := newSigner(t, "k1")
	v := fileVerifier(t, now, key)
	tok := gatewayToken(t, key, now)
	gateway := Caller{Kind: CallerGateway, Issuer: testIssuer, Subject: testSubject}
	tests := []struct {
		name   string
		md     metadata.MD
		want   Caller
		denied bool
	}{
		{name: "no metadata", denied: true},
		{name: "no authorization", md: metadata.Pairs("x-other", "1"), denied: true},
		{name: "two values", md: metadata.Pairs("authorization", "Bearer "+tok, "authorization", "Bearer "+tok), denied: true},
		{name: "basic scheme", md: metadata.Pairs("authorization", "Basic abc"), denied: true},
		{name: "no scheme", md: metadata.Pairs("authorization", tok), denied: true},
		{name: "empty token", md: metadata.Pairs("authorization", "Bearer "), denied: true},
		{name: "invalid token", md: metadata.Pairs("authorization", "Bearer "+tok+"x"), denied: true},
		{name: "bearer", md: metadata.Pairs("authorization", "Bearer "+tok), want: gateway},
		{name: "lowercase scheme", md: metadata.Pairs("authorization", "bearer "+tok), want: gateway},
		{name: "uppercase scheme", md: metadata.Pairs("authorization", "BEARER "+tok), want: gateway},
		{name: "mixed-case key", md: metadata.Pairs("Authorization", "Bearer  "+tok), want: gateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tt.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tt.md)
			}
			var got Caller
			var authenticated, called bool
			handler := func(ctx context.Context, _ any) (any, error) {
				called = true
				got, authenticated = CallerFromContext(ctx)
				return "ok", nil
			}
			resp, err := v.UnaryInterceptor()(ctx, "req", &grpc.UnaryServerInfo{FullMethod: testMethod}, handler)
			if tt.denied {
				assertUnauthenticated(t, err, tok)
				if called || resp != nil {
					t.Fatalf("handler called = %v, resp = %v; want no handler call", called, resp)
				}
				return
			}
			if err != nil || resp != "ok" {
				t.Fatalf("interceptor = %v, %v; want ok, nil", resp, err)
			}
			if !authenticated || got != tt.want {
				t.Fatalf("CallerFromContext() = %+v, %v; want %+v, true", got, authenticated, tt.want)
			}
		})
	}
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeStream) Context() context.Context { return s.ctx }

func TestStreamInterceptor(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	key := newSigner(t, "k1")
	v := fileVerifier(t, now, key)
	claims := testClaims(now)
	set("caller_kind", "supervisor", "sandbox_id", "sb-1", "sub", "spiffe://openshell/sandbox/sb-1")(claims)
	tok := key.mint(t, testHeader(key.kid), claims)
	want := Caller{Kind: CallerSupervisor, Issuer: testIssuer, Subject: "spiffe://openshell/sandbox/sb-1", SandboxID: "sb-1"}

	t.Run("authenticated", func(t *testing.T) {
		t.Parallel()
		in := fakeStream{ctx: metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+tok))}
		var got Caller
		var ok bool
		handler := func(_ any, ss grpc.ServerStream) error {
			got, ok = CallerFromContext(ss.Context())
			return nil
		}
		if err := v.StreamInterceptor()("srv", in, &grpc.StreamServerInfo{FullMethod: testMethod}, handler); err != nil {
			t.Fatalf("interceptor error = %v", err)
		}
		if !ok || got != want {
			t.Fatalf("CallerFromContext() = %+v, %v; want %+v, true", got, ok, want)
		}
	})
	t.Run("denied", func(t *testing.T) {
		t.Parallel()
		in := fakeStream{ctx: metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer nope"))}
		called := false
		handler := func(_ any, _ grpc.ServerStream) error {
			called = true
			return nil
		}
		err := v.StreamInterceptor()("srv", in, &grpc.StreamServerInfo{FullMethod: testMethod}, handler)
		assertUnauthenticated(t, err, "nope")
		if called {
			t.Fatal("handler called for a denied stream")
		}
	})
}

func TestInsecurePassThrough(t *testing.T) {
	t.Parallel()
	v, err := NewVerifier(config.Auth{AllowInsecureNoAuth: true}, discardLogger())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for name, ctx := range map[string]context.Context{
		"no metadata":        t.Context(),
		"garbage credential": metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer garbage")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			unary := func(ctx context.Context, _ any) (any, error) {
				if _, ok := CallerFromContext(ctx); ok {
					t.Error("unary handler saw a caller in insecure mode")
				}
				return "ok", nil
			}
			if resp, err := v.UnaryInterceptor()(ctx, "req", &grpc.UnaryServerInfo{FullMethod: testMethod}, unary); err != nil || resp != "ok" {
				t.Fatalf("unary = %v, %v; want ok, nil", resp, err)
			}
			stream := func(_ any, ss grpc.ServerStream) error {
				if _, ok := CallerFromContext(ss.Context()); ok {
					t.Error("stream handler saw a caller in insecure mode")
				}
				return nil
			}
			if err := v.StreamInterceptor()("srv", fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: testMethod}, stream); err != nil {
				t.Fatalf("stream error = %v", err)
			}
		})
	}
}

func TestRejectedCallIsLogged(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	logger, buf := bufferLogger()
	v, err := NewVerifier(fileAuth(t, newSigner(t, "k1")), logger, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	const tok = "zzqq.zzqq"
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+tok))
	_, err = v.UnaryInterceptor()(ctx, "req", &grpc.UnaryServerInfo{FullMethod: testMethod}, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	assertUnauthenticated(t, err, tok)
	log := buf.String()
	if !strings.Contains(log, "rejected unauthenticated call") || !strings.Contains(log, "method="+testMethod) {
		t.Fatalf("missing rejection log entry:\n%s", log)
	}
	if strings.Contains(log, tok) {
		t.Fatalf("log echoes the token:\n%s", log)
	}
}

type recordingHealth struct {
	healthpb.UnimplementedHealthServer
	mu      sync.Mutex
	callers []Caller
}

func (h *recordingHealth) record(ctx context.Context) {
	c, _ := CallerFromContext(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callers = append(h.callers, c)
}

func (h *recordingHealth) Check(ctx context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	h.record(ctx)
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (h *recordingHealth) Watch(_ *healthpb.HealthCheckRequest, stream healthpb.Health_WatchServer) error {
	h.record(stream.Context())
	return stream.Send(&healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING})
}

func (h *recordingHealth) recorded() []Caller {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Caller(nil), h.callers...)
}

func startServer(t *testing.T, v *Verifier) (healthpb.HealthClient, *recordingHealth) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(v.UnaryInterceptor()), grpc.StreamInterceptor(v.StreamInterceptor()))
	rec := &recordingHealth{}
	healthpb.RegisterHealthServer(srv, rec)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return healthpb.NewHealthClient(conn), rec
}

func TestInterceptorsOverBufconn(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newSigner(t, "k1")
	v := fileVerifier(t, now, key)
	client, rec := startServer(t, v)
	gateway := Caller{Kind: CallerGateway, Issuer: testIssuer, Subject: testSubject}
	supervisorClaims := testClaims(now)
	set("caller_kind", "supervisor", "sandbox_id", "sb-1", "sub", "spiffe://openshell/sandbox/sb-1")(supervisorClaims)
	supervisor := Caller{Kind: CallerSupervisor, Issuer: testIssuer, Subject: "spiffe://openshell/sandbox/sb-1", SandboxID: "sb-1"}

	ctx := metadata.AppendToOutgoingContext(t.Context(), "authorization", "Bearer "+gatewayToken(t, key, now))
	if _, err := client.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	ctx = metadata.AppendToOutgoingContext(t.Context(), "authorization", "Bearer "+key.mint(t, testHeader(key.kid), supervisorClaims))
	stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("Recv() error = %v", err)
	}
	if got := rec.recorded(); len(got) != 2 || got[0] != gateway || got[1] != supervisor {
		t.Fatalf("recorded callers = %+v, want [%+v %+v]", got, gateway, supervisor)
	}

	_, err = client.Check(t.Context(), &healthpb.HealthCheckRequest{})
	assertUnauthenticated(t, err, "")
	stream, err = client.Watch(t.Context(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	_, err = stream.Recv()
	assertUnauthenticated(t, err, "")
	if got := rec.recorded(); len(got) != 2 {
		t.Fatalf("unauthenticated calls reached the handler: %+v", got)
	}
}
