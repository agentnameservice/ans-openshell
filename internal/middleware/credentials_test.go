package middleware

import (
	"fmt"
	"testing"
)

func TestContainsCredentialMarker(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty"},
		{name: "ordinary body", value: `{"task":"pay invoice"}`},
		{name: "raw canonical", value: `{"key":"openshell:resolve:env:KEY"}`, want: true},
		{name: "raw provider", value: "token=OPENSHELL-RESOLVE-ENV-KEY", want: true},
		{name: "encoded canonical", value: "token=openshell%3Aresolve%3aenv%3AKEY", want: true},
		{name: "encoded provider", value: "%4fPENSHELL%2dRESOLVE%2DENV-KEY", want: true},
		{name: "malformed prefix before marker", value: "%zz&token=%6fpenshell%3aresolve%3aenv%3aKEY", want: true},
		{name: "partial marker", value: "openshell:resolve:env"},
		{name: "different case", value: "OpenShell:resolve:env:KEY"},
		{name: "invalid percent", value: "%xz%3Zopenshel"},
		{name: "trailing percent", value: "o%"},
		{name: "nested encoding stays encoded", value: "%256fpenshell%253aresolve%253aenv%253aKEY"},
		{name: "binary payload", value: "\xff\x00openshell:resolve:env:KEY", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containsCredentialMarker([]byte(tt.value)); got != tt.want {
				t.Fatalf("containsCredentialMarker() = %v, want %v", got, tt.want)
			}
		})
	}
	for _, marker := range []string{"openshell:resolve:env:", "OPENSHELL-RESOLVE-ENV-"} {
		for i := range len(marker) {
			value := marker[:i] + fmt.Sprintf("%%%02x", marker[i]) + marker[i+1:]
			if !containsCredentialMarker([]byte(value)) {
				t.Errorf("encoded marker byte %d was missed", i)
			}
		}
	}
}

func TestEvaluateCredentialPlaceholders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		body  string
		path  string
		query string
		strip bool
		want  string
	}{
		{name: "ordinary request", body: `{"amount":42}`},
		{name: "raw body placeholder", body: `{"token":"openshell:resolve:env:KEY"}`, want: ReasonRequestRewriteUnsupported},
		{name: "form encoded placeholder", body: "token=openshell%3aresolve%3aenv%3aKEY", want: ReasonRequestRewriteUnsupported},
		{name: "provider placeholder", body: "OPENSHELL-RESOLVE-ENV-KEY", want: ReasonRequestRewriteUnsupported},
		{name: "path placeholder", path: "/bot/openshell:resolve:env:KEY", want: ReasonRequestRewriteUnsupported},
		{name: "encoded path placeholder", path: "/bot/%6fpenshell%3aresolve%3aenv%3aKEY", want: ReasonRequestRewriteUnsupported},
		{name: "query is not proof bound", query: "token=openshell:resolve:env:KEY"},
		{name: "strip does not sign", strip: true, body: "openshell:resolve:env:KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signer := &fakeSigner{}
			ids := lookup{testIdentity: newIdentity(t, testIdentity, signer, fullArtifacts())}
			svc := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
			policy := signPolicy()
			if tt.strip {
				policy = map[string]any{"mode": "strip"}
			}
			req := evaluation(t, policy, []byte(tt.body))
			if tt.path != "" {
				req.Target.Path = tt.path
			}
			req.Target.Query = tt.query
			res, err := svc.EvaluateHttpRequest(t.Context(), req)
			if err != nil || res.GetReasonCode() != tt.want {
				t.Fatalf("EvaluateHttpRequest() = %v, %v", res, err)
			}
			wantCalls := 1
			if tt.strip {
				wantCalls = 0
			}
			if tt.want != "" {
				if res.GetDecision() != deny || len(signer.calls) != 0 || len(res.GetHeaderMutations()) != 0 {
					t.Fatalf("unsupported request was signed: %v", res)
				}
			} else if res.GetDecision() != allow || len(signer.calls) != wantCalls {
				t.Fatalf("supported request failed: %v", res)
			}
		})
	}
}
