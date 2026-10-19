// Package extauth authenticates OpenShell's calls into an extension service.
// The gateway and sandbox supervisors present a short-lived Ed25519 JWT
// (typ "openshell-ext+jwt") whose audience names this registration; the
// package verifies it against the operator-provisioned JWKS and exposes the
// proven caller to request handlers through the context.
package extauth

import "context"

// CallerKind is the OpenShell component that made the call.
type CallerKind string

const (
	// CallerGateway is the gateway itself (Describe, ValidateConfig, Evaluate on
	// interceptors).
	CallerGateway CallerKind = "gateway"
	// CallerSupervisor is a sandbox supervisor (Describe, EvaluateHttpRequest).
	CallerSupervisor CallerKind = "supervisor"
)

// Caller is the authenticated identity of an OpenShell caller.
type Caller struct {
	Kind    CallerKind
	Issuer  string
	Subject string
	// SandboxID is set for supervisor callers and names the one sandbox the
	// credential was minted for.
	SandboxID string
}

type callerCtxKey struct{}

// ContextWithCaller stores the authenticated caller in ctx.
func ContextWithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, c)
}

// CallerFromContext returns the authenticated caller, or ok=false when the
// request was not authenticated (insecure transport mode).
func CallerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerCtxKey{}).(Caller)
	return c, ok
}
