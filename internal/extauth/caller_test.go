package extauth

import (
	"context"
	"testing"
)

func TestCallerContextRoundTrip(t *testing.T) {
	t.Parallel()
	if _, ok := CallerFromContext(context.Background()); ok {
		t.Fatal("CallerFromContext() = ok on an empty context")
	}
	want := Caller{Kind: CallerSupervisor, Issuer: "openshell-gateway:g1", Subject: "spiffe://openshell/sandbox/sb-1", SandboxID: "sb-1"}
	ctx := ContextWithCaller(context.Background(), want)
	got, ok := CallerFromContext(ctx)
	if !ok || got != want {
		t.Fatalf("CallerFromContext() = %+v, %v; want %+v, true", got, ok, want)
	}
}
