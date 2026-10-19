package extauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ErrNoCredential reports a call without exactly one "Bearer" authorization
// metadata value.
var ErrNoCredential = errors.New("extauth: missing or malformed authorization metadata")

const unauthenticatedMessage = "invalid or missing credential"

// UnaryInterceptor authenticates unary calls and exposes the caller through
// CallerFromContext.
func (v *Verifier) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := v.authenticate(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor authenticates streaming calls; the handler's stream
// Context carries the caller.
func (v *Verifier) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := v.authenticate(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &callerStream{ServerStream: ss, ctx: ctx})
	}
}

func (v *Verifier) authenticate(ctx context.Context, method string) (context.Context, error) {
	if v.insecure {
		return ctx, nil
	}
	token, err := bearerToken(ctx)
	if err == nil {
		var caller Caller
		if caller, err = v.Verify(ctx, token); err == nil {
			return ContextWithCaller(ctx, caller), nil
		}
	}
	attrs := []any{"method", method, "err", err}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		attrs = append(attrs, "peer", p.Addr.String())
	}
	v.logger.WarnContext(ctx, "rejected unauthenticated call", attrs...)
	return nil, status.Error(codes.Unauthenticated, unauthenticatedMessage)
}

func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoCredential
	}
	values := md.Get("authorization")
	if len(values) != 1 {
		return "", fmt.Errorf("%w: got %d authorization values", ErrNoCredential, len(values))
	}
	scheme, token, found := strings.Cut(values[0], " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", fmt.Errorf("%w: expected a Bearer credential", ErrNoCredential)
	}
	return token, nil
}

type callerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *callerStream) Context() context.Context { return s.ctx }
