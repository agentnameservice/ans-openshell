package middleware

import (
	"strings"
	"testing"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
)

func TestNewSandboxIdentities(t *testing.T) {
	t.Parallel()
	ids := lookup{testIdentity: newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())}
	tests := []struct {
		name     string
		bindings map[string]string
		ids      IdentityLookup
		wantErr  string
	}{
		{name: "approved binding", bindings: map[string]string{testSandbox: testIdentity}, ids: ids},
		{name: "empty denies all", ids: ids},
		{name: "missing lookup", wantErr: "lookup is required"},
		{name: "empty sandbox", bindings: map[string]string{"": testIdentity}, ids: ids, wantErr: "invalid sandbox"},
		{name: "whitespace sandbox", bindings: map[string]string{" sb-1": testIdentity}, ids: ids, wantErr: "invalid sandbox"},
		{name: "wildcard sandbox", bindings: map[string]string{"*": testIdentity}, ids: ids, wantErr: "invalid sandbox"},
		{name: "unknown identity", bindings: map[string]string{testSandbox: "other"}, ids: ids, wantErr: "unknown identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authz, err := NewSandboxIdentities(tt.bindings, tt.ids)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewSandboxIdentities() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := authz.Allows(testSandbox, testIdentity); got != (len(tt.bindings) != 0) {
				t.Fatalf("Allows() = %v", got)
			}
			if authz.Allows("unapproved", testIdentity) || authz.Allows(testSandbox, "other") || authz.Allows("", "") {
				t.Fatal("unapproved binding was allowed")
			}
		})
	}
}

func TestSandboxIdentitiesCopiesApproval(t *testing.T) {
	t.Parallel()
	ids := lookup{testIdentity: newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())}
	bindings := map[string]string{testSandbox: testIdentity}
	authz, err := NewSandboxIdentities(bindings, ids)
	if err != nil {
		t.Fatal(err)
	}
	bindings[testSandbox] = "other"
	bindings["unapproved"] = testIdentity
	if !authz.Allows(testSandbox, testIdentity) || authz.Allows("unapproved", testIdentity) {
		t.Fatal("mutating the input map changed approved bindings")
	}
}

func TestNewServiceRequiresAuthorizer(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("NewService(nil authorizer) did not panic")
		}
	}()
	NewService(lookup{}, nil, nil, Config{}, nil)
}

func TestEvaluateIdentityAuthorization(t *testing.T) {
	t.Parallel()
	const otherIdentity = "other-agent"
	tests := []struct {
		name     string
		sandbox  string
		identity string
		bindings map[string]string
		wantCode string
	}{
		{name: "approved", sandbox: testSandbox, identity: testIdentity,
			bindings: map[string]string{testSandbox: testIdentity}},
		{name: "known but unapproved identity", sandbox: testSandbox, identity: otherIdentity,
			bindings: map[string]string{testSandbox: testIdentity}, wantCode: ReasonIdentityUnauthorized},
		{name: "unapproved sandbox", sandbox: "unapproved", identity: testIdentity,
			bindings: map[string]string{testSandbox: testIdentity}, wantCode: ReasonIdentityUnauthorized},
		{name: "no approvals", sandbox: testSandbox, identity: testIdentity, wantCode: ReasonIdentityUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signer := &fakeSigner{}
			ids := lookup{
				testIdentity:  newIdentity(t, testIdentity, signer, fullArtifacts()),
				otherIdentity: newIdentity(t, otherIdentity, signer, fullArtifacts()),
			}
			authz, err := NewSandboxIdentities(tt.bindings, ids)
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(ids, authz, nil, Config{RequireAuthenticatedCaller: true}, nil)
			req := evaluation(t, map[string]any{"identity": tt.identity}, nil)
			req.Context.SandboxId = tt.sandbox
			req.Context.Sandbox = testSandbox
			req.Context.Workspace = testSandbox
			validated, err := svc.ValidateConfig(t.Context(), &middlewarev1.ValidateConfigRequest{Config: req.GetConfig()})
			if err != nil || !validated.GetValid() {
				t.Fatalf("ValidateConfig() = %v, %v", validated, err)
			}
			ctx := extauth.ContextWithCaller(t.Context(), extauth.Caller{Kind: extauth.CallerSupervisor, SandboxID: tt.sandbox})
			res, err := svc.EvaluateHttpRequest(ctx, req)
			if err != nil || res.GetReasonCode() != tt.wantCode {
				t.Fatalf("EvaluateHttpRequest() = %v, %v", res, err)
			}
			if tt.wantCode != "" {
				if res.GetDecision() != deny || len(signer.calls) != 0 || len(res.GetHeaderMutations()) != 0 {
					t.Fatalf("unapproved identity signed: %v", res)
				}
			} else if res.GetDecision() != allow || len(signer.calls) != 1 {
				t.Fatalf("approved identity did not sign: %v", res)
			}
		})
	}
}
