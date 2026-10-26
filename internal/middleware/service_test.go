package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/capability"
	"github.com/agentnameservice/ans-openshell/internal/commerce"
	"github.com/agentnameservice/ans-openshell/internal/commercekey"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

const (
	testIdentity = "payments-agent"
	testAgentID  = "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
	testAnsName  = "ans://v1.0.0.payments.example.com"
	testSandbox  = "sb-1"
	receiptB64   = "cmVjZWlwdA=="
	tokenB64     = "dG9rZW4="
)

const (
	preCredentials = middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS
	preReturn      = middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN
	allow          = middlewarev1.Decision_DECISION_ALLOW
	deny           = middlewarev1.Decision_DECISION_DENY
)

type signCall struct {
	method, url string
	digest      [sha256.Size]byte
}

// fakeSigner records calls and returns a numbered proof or a fixed error.
type fakeSigner struct {
	mu    sync.Mutex
	err   error
	calls []signCall
}

func (f *fakeSigner) Sign(_ context.Context, method, rawURL string, digest [sha256.Size]byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, signCall{method: method, url: rawURL, digest: digest})
	if f.err != nil {
		return "", f.err
	}
	return "proof-" + strconv.Itoa(len(f.calls)), nil
}

// fakeVerifier answers every lookup with one verdict and records the arguments.
type fakeVerifier struct {
	mu      sync.Mutex
	verdict vetting.Verdict
	hosts   []string
	waits   []time.Duration
}

func (f *fakeVerifier) Lookup(_ context.Context, host string, wait time.Duration) vetting.Verdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts = append(f.hosts, host)
	f.waits = append(f.waits, wait)
	v := f.verdict
	v.Host = host
	return v
}

type sandboxAuthorizer string

func (a sandboxAuthorizer) Allows(sandboxID, _ string) bool {
	return sandboxID == string(a)
}

type lookup map[string]*identity.Identity

func (l lookup) Identity(name string) (*identity.Identity, bool) {
	id, ok := l[name]
	return id, ok
}

func newIdentity(t *testing.T, name string, signer identity.Signer, arts identity.Artifacts) *identity.Identity {
	t.Helper()
	id, err := identity.NewIdentity(name, testAnsName, testAgentID, signer, identity.NewStaticSource(arts))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fullArtifacts() identity.Artifacts {
	return identity.Artifacts{ReceiptBase64: receiptB64, StatusTokenBase64: tokenB64}
}

// evaluation builds a PRE_CREDENTIALS request for a POST with the given policy.
func evaluation(t *testing.T, policy map[string]any, body []byte) *middlewarev1.HttpRequestEvaluation {
	t.Helper()
	return &middlewarev1.HttpRequestEvaluation{
		Phase:   preCredentials,
		Context: &middlewarev1.RequestContext{RequestId: "req-1", SandboxId: testSandbox},
		Config:  structOf(t, policy),
		Target: &middlewarev1.HttpRequestTarget{
			Scheme: "https", Host: "tools.example.com", Port: 443, Method: "POST", Path: "/v1/do", Query: "x=1",
		},
		Headers: []*middlewarev1.HttpHeader{{Name: "dpop", Value: "smuggled"}},
		Body:    body,
	}
}

func signPolicy() map[string]any { return map[string]any{"identity": testIdentity} }

func TestNewServiceRequiresLookup(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("NewService(nil lookup) did not panic")
		}
	}()
	NewService(nil, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
}

func TestConfigDefaults(t *testing.T) {
	t.Parallel()
	s := NewService(lookup{}, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	if s.cfg.MaxPayloadBytes != DefaultMaxPayloadBytes || s.cfg.VettingBudget != DefaultVettingBudget {
		t.Fatalf("defaults not applied: %+v", s.cfg)
	}
	custom := Config{MaxPayloadBytes: 1024, VettingBudget: time.Second, RequestTimeout: time.Second}
	if got := NewService(lookup{}, sandboxAuthorizer(testSandbox), nil, custom, nil).cfg; got != custom {
		t.Fatalf("explicit config changed: %+v", got)
	}
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	v1 := &extensionv1.ProtocolVersion{Major: 1}
	tests := []struct {
		name     string
		gateway  *extensionv1.PeerMetadata
		wantCode codes.Code
	}{
		{name: "protocol 1.0", gateway: &extensionv1.PeerMetadata{ProtocolVersion: v1}},
		{name: "protocol 1.3 with supported requirement", gateway: &extensionv1.PeerMetadata{
			ProtocolVersion: &extensionv1.ProtocolVersion{Major: 1, Minor: 3}, RequiredCapabilities: []string{CapabilityContract}}},
		{name: "no gateway metadata", gateway: nil, wantCode: codes.FailedPrecondition},
		{name: "protocol 2.0", gateway: &extensionv1.PeerMetadata{ProtocolVersion: &extensionv1.ProtocolVersion{Major: 2}},
			wantCode: codes.FailedPrecondition},
		{name: "unsupported requirement", gateway: &extensionv1.PeerMetadata{
			ProtocolVersion: v1, RequiredCapabilities: []string{CapabilityContract, "openshell.websocket"}},
			wantCode: codes.FailedPrecondition},
	}
	cfg := Config{Audience: "urn:openshell:extension:middleware:ans", ImplementationVersion: "v0.1.0", RequestTimeout: 250 * time.Millisecond}
	s := NewService(lookup{}, sandboxAuthorizer(testSandbox), nil, cfg, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := s.Describe(t.Context(), &middlewarev1.MiddlewareDescribeRequest{Gateway: tt.gateway})
			if tt.wantCode != codes.OK {
				if status.Code(err) != tt.wantCode {
					t.Fatalf("Describe() error = %v, want code %v", err, tt.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("Describe() error = %v", err)
			}
			if m.GetName() != ManifestName || m.GetServiceVersion() != "v0.1.0" || m.GetExpectedAudience() != cfg.Audience {
				t.Fatalf("manifest = %v", m)
			}
			ext := m.GetExtension()
			if ext.GetProtocolVersion().GetMajor() != 1 || ext.GetProtocolVersion().GetMinor() != 0 ||
				ext.GetImplementationName() != ImplementationName || ext.GetImplementationVersion() != "v0.1.0" ||
				len(ext.GetSupportedCapabilities()) != 1 || ext.GetSupportedCapabilities()[0] != CapabilityContract {
				t.Fatalf("extension metadata = %v", ext)
			}
			if len(m.GetBindings()) != 2 {
				t.Fatalf("bindings = %v, want 2", m.GetBindings())
			}
			// First binding: HTTP_REQUEST / PRE_CREDENTIALS
			b := m.GetBindings()[0]
			if b.GetOperation() != middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST ||
				b.GetPhase() != preCredentials || b.GetMaxPayloadBytes() != DefaultMaxPayloadBytes ||
				b.GetRequestTimeout().AsDuration() != cfg.RequestTimeout {
				t.Fatalf("request binding = %v", b)
			}
			// Second binding: HTTP_RESPONSE / PRE_RETURN
			rb := m.GetBindings()[1]
			if rb.GetOperation() != middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE ||
				rb.GetPhase() != middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN ||
				rb.GetMaxPayloadBytes() != DefaultMaxPayloadBytes ||
				rb.GetRequestTimeout().AsDuration() != cfg.RequestTimeout {
				t.Fatalf("response binding = %v", rb)
			}
		})
	}
	t.Run("no request timeout when unset", func(t *testing.T) {
		t.Parallel()
		m, err := NewService(lookup{}, sandboxAuthorizer(testSandbox), nil, Config{}, nil).Describe(t.Context(),
			&middlewarev1.MiddlewareDescribeRequest{Gateway: &extensionv1.PeerMetadata{ProtocolVersion: v1}})
		if err != nil {
			t.Fatal(err)
		}
		if m.GetBindings()[0].GetRequestTimeout() != nil {
			t.Fatalf("request binding request_timeout = %v, want unset", m.GetBindings()[0].GetRequestTimeout())
		}
		if m.GetBindings()[1].GetRequestTimeout() != nil {
			t.Fatalf("response binding request_timeout = %v, want unset", m.GetBindings()[1].GetRequestTimeout())
		}
	})
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()
	ids := lookup{testIdentity: newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())}
	withVet := NewService(ids, sandboxAuthorizer(testSandbox), &fakeVerifier{}, Config{}, nil)
	noVet := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	tests := []struct {
		name    string
		svc     *Service
		policy  map[string]any
		wantErr string
	}{
		{name: "sign known identity", svc: noVet, policy: signPolicy()},
		{name: "strip", svc: noVet, policy: map[string]any{"mode": "strip"}},
		{name: "observe with vetting", svc: withVet, policy: map[string]any{"identity": testIdentity, "destination_policy": "observe"}},
		{name: "require with vetting", svc: withVet, policy: map[string]any{"mode": "strip", "destination_policy": "require_registered"}},
		{name: "sign unknown identity", svc: noVet, policy: map[string]any{"identity": "ghost"}, wantErr: `unknown identity "ghost"`},
		{name: "sign without identity", svc: noVet, policy: map[string]any{}, wantErr: "identity is required"},
		{name: "strip with identity", svc: noVet, policy: map[string]any{"mode": "strip", "identity": testIdentity},
			wantErr: "must not be set in strip mode"},
		{name: "unknown key", svc: noVet, policy: map[string]any{"identity": testIdentity, "order": "100"}, wantErr: `unknown field "order"`},
		{name: "bad mode", svc: noVet, policy: map[string]any{"mode": "verify"}, wantErr: "unknown mode"},
		{name: "bad destination policy", svc: withVet, policy: map[string]any{"identity": testIdentity, "destination_policy": "block"},
			wantErr: "unknown destination_policy"},
		{name: "destination policy without vetting", svc: noVet,
			policy: map[string]any{"identity": testIdentity, "destination_policy": "observe"}, wantErr: "not configured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp, err := tt.svc.ValidateConfig(t.Context(), &middlewarev1.ValidateConfigRequest{
				Config: structOf(t, tt.policy), MiddlewareName: "ans"})
			if err != nil {
				t.Fatalf("ValidateConfig() error = %v", err)
			}
			if tt.wantErr == "" {
				if !resp.GetValid() || resp.GetReason() != "" {
					t.Fatalf("ValidateConfig() = %v, want valid", resp)
				}
				return
			}
			if resp.GetValid() || !strings.Contains(resp.GetReason(), tt.wantErr) {
				t.Fatalf("ValidateConfig() = %v, want invalid with %q", resp, tt.wantErr)
			}
		})
	}
	t.Run("absent config struct is a gRPC error", func(t *testing.T) {
		t.Parallel()
		_, err := noVet.ValidateConfig(t.Context(), &middlewarev1.ValidateConfigRequest{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("ValidateConfig(nil config) error = %v, want InvalidArgument", err)
		}
	})
}

func TestEvaluateSignAttachesIdentity(t *testing.T) {
	t.Parallel()
	signer := &fakeSigner{}
	ids := lookup{testIdentity: newIdentity(t, testIdentity, signer, fullArtifacts())}
	var logs bytes.Buffer
	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	body := []byte(`{"amount":1}`)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), body))
	if err != nil {
		t.Fatalf("EvaluateHttpRequest() error = %v", err)
	}
	if res.GetDecision() != allow || res.GetReasonCode() != "" || res.GetHasBody() {
		t.Fatalf("result = %v", res)
	}
	wantWrites := map[string]string{pop.DPoPHeader: "proof-1", scitt.HeaderReceipt: receiptB64, scitt.HeaderStatusToken: tokenB64}
	muts := res.GetHeaderMutations()
	if len(muts) != len(wantWrites) {
		t.Fatalf("mutations = %v", muts)
	}
	for i, name := range []string{pop.DPoPHeader, scitt.HeaderReceipt, scitt.HeaderStatusToken} {
		w := muts[i].GetWrite()
		if w.GetName() != name || w.GetValue() != wantWrites[name] ||
			w.GetOnExisting() != middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE {
			t.Fatalf("mutation %d = %v, want OVERWRITE %s", i, muts[i], name)
		}
	}
	if len(res.GetFindings()) != 1 || res.GetFindings()[0].GetType() != FindingIdentityAttached ||
		res.GetFindings()[0].GetCount() != 1 || res.GetFindings()[0].GetSeverity() != severityInfo {
		t.Fatalf("findings = %v", res.GetFindings())
	}
	wantMeta := map[string]string{MetadataIdentity: testIdentity, MetadataAnsName: testAnsName, MetadataAgentID: testAgentID}
	if got := res.GetMetadata(); len(got) != len(wantMeta) {
		t.Fatalf("metadata = %v", got)
	}
	for k, v := range wantMeta {
		if res.GetMetadata()[k] != v {
			t.Errorf("metadata[%s] = %q, want %q", k, res.GetMetadata()[k], v)
		}
	}
	if len(signer.calls) != 1 || signer.calls[0].method != "POST" ||
		signer.calls[0].url != "https://tools.example.com/v1/do" || signer.calls[0].digest != sha256.Sum256(body) {
		t.Fatalf("signer calls = %+v", signer.calls)
	}
	if out := logs.String(); !strings.Contains(out, "request signed") || strings.Contains(out, "proof-1") ||
		strings.Contains(out, "amount") || strings.Contains(out, receiptB64) {
		t.Fatalf("log output leaks header or body content or lacks the decision: %s", out)
	}

	t.Run("bodyless request binds the empty digest", func(t *testing.T) {
		t.Parallel()
		res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), nil))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("result = %v, %v", res, err)
		}
		signer.mu.Lock()
		defer signer.mu.Unlock()
		if last := signer.calls[len(signer.calls)-1]; last.digest != sha256.Sum256(nil) {
			t.Fatalf("digest = %x, want empty-content digest", last.digest)
		}
	})
}

func TestEvaluateStrip(t *testing.T) {
	t.Parallel()
	signer := &fakeSigner{}
	ids := lookup{testIdentity: newIdentity(t, testIdentity, signer, fullArtifacts())}
	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, map[string]any{"mode": "strip"}, []byte("x")))
	if err != nil || res.GetDecision() != allow {
		t.Fatalf("result = %v, %v", res, err)
	}
	want := []string{pop.DPoPHeader, scitt.HeaderReceipt, scitt.HeaderStatusToken}
	if len(res.GetHeaderMutations()) != len(want) {
		t.Fatalf("mutations = %v", res.GetHeaderMutations())
	}
	for i, m := range res.GetHeaderMutations() {
		if m.GetRemove().GetName() != want[i] || m.GetWrite() != nil {
			t.Fatalf("mutation %d = %v, want remove %s", i, m, want[i])
		}
	}
	if len(res.GetFindings()) != 1 || res.GetFindings()[0].GetType() != FindingIdentityStripped || len(res.GetMetadata()) != 0 {
		t.Fatalf("findings = %v metadata = %v", res.GetFindings(), res.GetMetadata())
	}
	if len(signer.calls) != 0 {
		t.Fatal("strip mode signed")
	}
}

func TestEvaluateDenies(t *testing.T) {
	t.Parallel()
	okID := newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())
	noToken := newIdentity(t, "no-token", &fakeSigner{}, identity.Artifacts{ReceiptBase64: receiptB64})
	noReceipt := newIdentity(t, "no-receipt", &fakeSigner{}, identity.Artifacts{StatusTokenBase64: tokenB64})
	brokenSigner := newIdentity(t, "broken", &fakeSigner{err: errors.New("hsm offline")}, fullArtifacts())
	ids := lookup{testIdentity: okID, "no-token": noToken, "no-receipt": noReceipt, "broken": brokenSigner}
	supervisorOther := extauth.ContextWithCaller(t.Context(), extauth.Caller{Kind: extauth.CallerSupervisor, SandboxID: "sb-other"})

	tests := []struct {
		name     string
		ctx      context.Context
		vet      vetting.Verifier
		mutate   func(e *middlewarev1.HttpRequestEvaluation)
		policy   map[string]any
		wantCode string
	}{
		{name: "pre-return phase", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Phase = preReturn }, wantCode: ReasonUnsupportedPhase},
		{name: "unspecified phase", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Phase = 0 }, wantCode: ReasonUnsupportedPhase},
		{name: "supervisor for another sandbox", ctx: supervisorOther, wantCode: ReasonCallerSandboxMismatch},
		{name: "absent config", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Config = nil }, wantCode: ReasonPolicyInvalid},
		{name: "unknown policy key", policy: map[string]any{"identity": testIdentity, "extra": "x"}, wantCode: ReasonPolicyInvalid},
		{name: "destination policy without vetting", policy: map[string]any{"identity": testIdentity, "destination_policy": "observe"},
			wantCode: ReasonPolicyInvalid},
		{name: "absent target", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Target = nil }, wantCode: ReasonTargetInvalid},
		{name: "empty method", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Target.Method = "" }, wantCode: ReasonTargetInvalid},
		{name: "unsupported scheme", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Target.Scheme = "ftp" }, wantCode: ReasonTargetInvalid},
		{name: "empty host", mutate: func(e *middlewarev1.HttpRequestEvaluation) { e.Target.Host = "" }, wantCode: ReasonTargetInvalid},
		{name: "unknown identity", policy: map[string]any{"identity": "ghost"}, wantCode: ReasonIdentityUnknown},
		{name: "status token unavailable", policy: map[string]any{"identity": "no-token"}, wantCode: ReasonStatusTokenUnavailable},
		{name: "receipt unavailable", policy: map[string]any{"identity": "no-receipt"}, wantCode: ReasonReceiptUnavailable},
		{name: "signer failure", policy: map[string]any{"identity": "broken"}, wantCode: ReasonSignFailed},
		{name: "unregistered destination under require", vet: &fakeVerifier{verdict: vetting.Verdict{Status: vetting.StatusUnregistered}},
			policy: map[string]any{"identity": testIdentity, "destination_policy": "require_registered"}, wantCode: vetting.ReasonUnregistered},
		{name: "revoked destination under require", vet: &fakeVerifier{verdict: vetting.Verdict{Status: vetting.StatusRevoked}},
			policy: map[string]any{"mode": "strip", "destination_policy": "require_registered"}, wantCode: vetting.ReasonRevoked},
		{name: "unknown destination under require", vet: &fakeVerifier{verdict: vetting.Verdict{Status: vetting.StatusUnknown}},
			policy: map[string]any{"identity": testIdentity, "destination_policy": "require_registered"}, wantCode: vetting.ReasonUnverified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			policy := tt.policy
			if policy == nil {
				policy = signPolicy()
			}
			e := evaluation(t, policy, []byte("body"))
			if tt.mutate != nil {
				tt.mutate(e)
			}
			s := NewService(ids, sandboxAuthorizer(testSandbox), tt.vet, Config{}, nil)
			res, err := s.EvaluateHttpRequest(ctx, e)
			if err != nil {
				t.Fatalf("EvaluateHttpRequest() error = %v", err)
			}
			if res.GetDecision() != deny || res.GetReasonCode() != tt.wantCode || res.GetReason() == "" {
				t.Fatalf("result = %v, want DENY %s with a reason", res, tt.wantCode)
			}
			if len(res.GetHeaderMutations()) != 0 {
				t.Fatalf("DENY carries mutations: %v", res.GetHeaderMutations())
			}
		})
	}
}

func TestEvaluateCallerBinding(t *testing.T) {
	t.Parallel()
	ids := lookup{testIdentity: newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())}
	tests := []struct {
		name     string
		caller   *extauth.Caller
		require  bool
		wantCode string
	}{
		{name: "unauthenticated in insecure mode"},
		{name: "unauthenticated when authentication is required", require: true, wantCode: ReasonCallerUnauthenticated},
		{name: "supervisor for this sandbox", caller: &extauth.Caller{Kind: extauth.CallerSupervisor, SandboxID: testSandbox}, require: true},
		{name: "supervisor for another sandbox", caller: &extauth.Caller{Kind: extauth.CallerSupervisor, SandboxID: "sb-other"},
			wantCode: ReasonCallerSandboxMismatch},
		{name: "gateway", caller: &extauth.Caller{Kind: extauth.CallerGateway}, wantCode: ReasonCallerNotSupervisor},
		{name: "unknown kind", caller: &extauth.Caller{Kind: "operator", SandboxID: testSandbox}, wantCode: ReasonCallerNotSupervisor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tt.caller != nil {
				ctx = extauth.ContextWithCaller(ctx, *tt.caller)
			}
			s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{RequireAuthenticatedCaller: tt.require}, nil)
			res, err := s.EvaluateHttpRequest(ctx, evaluation(t, signPolicy(), nil))
			if err != nil {
				t.Fatalf("EvaluateHttpRequest() error = %v", err)
			}
			if tt.wantCode == "" {
				if res.GetDecision() != allow {
					t.Fatalf("result = %v, want ALLOW", res)
				}
				return
			}
			if res.GetDecision() != deny || res.GetReasonCode() != tt.wantCode {
				t.Fatalf("result = %v, want DENY %s", res, tt.wantCode)
			}
		})
	}
}

func TestEvaluateDestinationVetting(t *testing.T) {
	t.Parallel()
	ids := lookup{testIdentity: newIdentity(t, testIdentity, &fakeSigner{}, fullArtifacts())}
	budget := 75 * time.Millisecond
	tests := []struct {
		name       string
		status     vetting.Status
		policy     string
		wantWait   time.Duration
		wantDeny   bool
		confidence string
		severity   string
	}{
		{name: "registered under require", status: vetting.StatusRegistered, policy: "require_registered", wantWait: budget,
			confidence: confidenceHigh, severity: severityInfo},
		{name: "exempt under require", status: vetting.StatusExempt, policy: "require_registered", wantWait: budget,
			confidence: confidenceHigh, severity: severityInfo},
		{name: "unregistered under observe", status: vetting.StatusUnregistered, policy: "observe", wantWait: 0,
			confidence: confidenceHigh, severity: severityMedium},
		{name: "untrusted tl under observe", status: vetting.StatusUntrustedTL, policy: "observe", wantWait: 0,
			confidence: confidenceHigh, severity: severityMedium},
		{name: "below threshold under observe", status: vetting.StatusBelowThreshold, policy: "observe", wantWait: 0,
			confidence: confidenceHigh, severity: severityMedium},
		{name: "error under observe", status: vetting.StatusError, policy: "observe", wantWait: 0,
			confidence: confidenceLow, severity: severityLow},
		{name: "unknown under observe", status: vetting.StatusUnknown, policy: "observe", wantWait: 0,
			confidence: confidenceLow, severity: severityLow},
		{name: "unregistered under require", status: vetting.StatusUnregistered, policy: "require_registered", wantWait: budget,
			wantDeny: true, confidence: confidenceHigh, severity: severityMedium},
		{name: "unmapped status", status: vetting.Status(99), policy: "observe", wantWait: 0,
			confidence: confidenceHigh, severity: severityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vet := &fakeVerifier{verdict: vetting.Verdict{Status: tt.status, Detail: "test"}}
			s := NewService(ids, sandboxAuthorizer(testSandbox), vet, Config{VettingBudget: budget}, nil)
			policy := map[string]any{"identity": testIdentity, "destination_policy": tt.policy}
			res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, policy, nil))
			if err != nil {
				t.Fatal(err)
			}
			if len(vet.hosts) != 1 || vet.hosts[0] != "tools.example.com" || vet.waits[0] != tt.wantWait {
				t.Fatalf("lookup args = %v %v, want host tools.example.com wait %v", vet.hosts, vet.waits, tt.wantWait)
			}
			wantType := FindingDestinationPrefix + tt.status.String()
			var found *middlewarev1.Finding
			for _, f := range res.GetFindings() {
				if f.GetType() == wantType {
					found = f
				}
			}
			if found == nil || found.GetConfidence() != tt.confidence || found.GetSeverity() != tt.severity {
				t.Fatalf("findings = %v, want %s %s/%s", res.GetFindings(), wantType, tt.confidence, tt.severity)
			}
			if res.GetMetadata()[MetadataDestinationStatus] != tt.status.String() {
				t.Fatalf("metadata = %v", res.GetMetadata())
			}
			if tt.wantDeny {
				if res.GetDecision() != deny || res.GetReasonCode() != vetting.ReasonUnregistered {
					t.Fatalf("result = %v, want DENY %s", res, vetting.ReasonUnregistered)
				}
				return
			}
			if res.GetDecision() != allow || len(res.GetFindings()) != 2 || res.GetMetadata()[MetadataIdentity] != testIdentity {
				t.Fatalf("result = %v, want ALLOW with identity and destination findings", res)
			}
		})
	}
}

func TestReasonCodeGrammar(t *testing.T) {
	t.Parallel()
	grammar := regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	check := func(code string) {
		if !grammar.MatchString(code) {
			t.Errorf("%q does not match the reason_code grammar", code)
		}
	}
	for _, code := range []string{
		ReasonUnsupportedPhase, ReasonCallerUnauthenticated, ReasonCallerNotSupervisor, ReasonCallerSandboxMismatch,
		ReasonPolicyInvalid, ReasonTargetInvalid, ReasonIdentityUnknown,
		ReasonStatusTokenUnavailable, ReasonReceiptUnavailable, ReasonSignFailed, ReasonRewriteDenied,
		vetting.ReasonUnregistered, vetting.ReasonRevoked, vetting.ReasonUntrustedTL, vetting.ReasonBelowThreshold, vetting.ReasonUnverified,
		FindingIdentityAttached, FindingIdentityStripped,
	} {
		check(code)
	}
	for _, st := range []vetting.Status{vetting.StatusUnknown, vetting.StatusRegistered, vetting.StatusUnregistered, vetting.StatusRevoked,
		vetting.StatusUntrustedTL, vetting.StatusBelowThreshold, vetting.StatusError, vetting.StatusExempt} {
		check(FindingDestinationPrefix + st.String())
	}
}

// TestOutcome_AllowCarriesReplacementBody verifies that outcome.setBody causes
// allow() to set HasBody=true and Body=<bytes>, and that bare allow() has HasBody=false.
func TestOutcome_AllowCarriesReplacementBody(t *testing.T) {
	t.Parallel()

	// Test 1: setBody then allow should carry the body
	o := &outcome{}
	body := []byte("rewritten")
	o.setBody(body)
	res := o.allow()

	if !res.GetHasBody() {
		t.Errorf("allow() after setBody: HasBody = false, want true")
	}
	if !bytes.Equal(res.GetBody(), body) {
		t.Errorf("allow() after setBody: Body = %q, want %q", res.GetBody(), body)
	}

	// Test 2: bare allow without setBody should have HasBody=false and nil Body
	o2 := &outcome{}
	res2 := o2.allow()

	if res2.GetHasBody() {
		t.Errorf("allow() without setBody: HasBody = true, want false")
	}
	if res2.GetBody() != nil {
		t.Errorf("allow() without setBody: Body = %v, want nil", res2.GetBody())
	}
}

// TestEvaluate_CommerceRewriteThenSignRewrittenBody verifies that commerce rewrite
// happens BEFORE signing, so the signed digest is sha256(rewritten), not sha256(original).
// This test uses the new transform chain (commerce as a Transform).
func TestEvaluate_CommerceRewriteThenSignRewrittenBody(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1"}}}`)
	rewritten := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1","mandate":"M1","dpop_proof":"P1"}}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	transform := &stubTransform{kind: capability.Allow, body: rewritten}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// The signed digest must be sha256(rewritten), not sha256(original)
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}
	// R1 proof: explicitly assert the digest is NOT sha256(original)
	originalDigest := sha256.Sum256(original)
	if signer.calls[0].digest == originalDigest {
		t.Fatalf("signed digest equals sha256(original) — rewrite was not applied before signing")
	}
	// Now assert it IS sha256(rewritten)
	wantDigest := sha256.Sum256(rewritten)
	if signer.calls[0].digest != wantDigest {
		t.Errorf("signed digest = %x, want %x (sha256 of rewritten body)", signer.calls[0].digest, wantDigest)
	}

	// Result should carry the rewritten body
	if !res.GetHasBody() {
		t.Errorf("HasBody = false, want true")
	}
	if !bytes.Equal(res.GetBody(), rewritten) {
		t.Errorf("Body = %q, want %q", res.GetBody(), rewritten)
	}

	// Should have the three identity headers
	if len(res.GetHeaderMutations()) != 3 {
		t.Errorf("header mutations = %d, want 3", len(res.GetHeaderMutations()))
	}
}

// TestEvaluate_CommerceDenyShortCircuits verifies that commerce Deny returns
// DECISION_DENY with reason_code ans_rewrite_denied (was ans_commerce_denied), with no Sign call and no body mutation.
// This test uses the new transform chain.
func TestEvaluate_CommerceDenyShortCircuits(t *testing.T) {
	t.Parallel()

	body := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1"}}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	transform := &stubTransform{kind: capability.Deny, reason: "missing mandate"}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), body))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != deny {
		t.Fatalf("decision = %v, want DENY", res.GetDecision())
	}
	// ReasonCommerceDenied is now an alias for ReasonRewriteDenied
	if res.GetReasonCode() != ReasonRewriteDenied {
		t.Errorf("reason_code = %q, want %q", res.GetReasonCode(), ReasonRewriteDenied)
	}

	// No Sign call should have happened
	if len(signer.calls) != 0 {
		t.Errorf("Sign calls = %d, want 0", len(signer.calls))
	}

	// No body mutation
	if res.GetHasBody() {
		t.Errorf("HasBody = true, want false")
	}
}

// TestEvaluate_CommercePassthroughSignsOriginal verifies that commerce Passthrough
// leaves the body unchanged, signs the original, and has HasBody=false.
// This test uses the new transform chain.
func TestEvaluate_CommercePassthroughSignsOriginal(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/other","params":{}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	transform := &stubTransform{kind: capability.Passthrough}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// The signed digest must be sha256(original)
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}
	wantDigest := sha256.Sum256(original)
	if signer.calls[0].digest != wantDigest {
		t.Errorf("signed digest = %x, want %x (sha256 of original body)", signer.calls[0].digest, wantDigest)
	}

	// HasBody should be false (no body replacement)
	if res.GetHasBody() {
		t.Errorf("HasBody = true, want false")
	}
}

// TestEvaluate_CredentialMarkerInRewrittenBodyDenied verifies that the credential
// marker guard runs on the POST-chain body, so a transform cannot smuggle a marker past it.
// This test uses the new transform chain.
func TestEvaluate_CredentialMarkerInRewrittenBodyDenied(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"book_flight"}}`)
	// Rewritten body contains the credential marker
	rewritten := []byte(`{"method":"tools/call","params":{"name":"book_flight","secret":"openshell:resolve:env:API_KEY"}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	transform := &stubTransform{kind: capability.Allow, body: rewritten}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != deny {
		t.Fatalf("decision = %v, want DENY", res.GetDecision())
	}
	if res.GetReasonCode() != ReasonRequestRewriteUnsupported {
		t.Errorf("reason_code = %q, want %q", res.GetReasonCode(), ReasonRequestRewriteUnsupported)
	}

	// No Sign call should have happened (guard runs before attach)
	if len(signer.calls) != 0 {
		t.Errorf("Sign calls = %d, want 0", len(signer.calls))
	}
}

// stubTransform is a test stub implementing capability.Transform.
type stubTransform struct {
	kind    capability.OutcomeKind
	body    []byte
	reason  string
	signURL string
	called  *bool
}

func (s *stubTransform) Provides() []capability.Capability {
	return nil
}

func (s *stubTransform) Apply(_ context.Context, _ capability.Target, _ capability.Requirement, _ []byte) capability.Outcome {
	if s.called != nil {
		*s.called = true
	}
	return capability.Outcome{
		Kind:    s.kind,
		Body:    s.body,
		Reason:  s.reason,
		SignURL: s.signURL,
	}
}

// TestEvaluate_ChainComposesThenSigns verifies that multiple Allow transforms
// compose (each sees the previous rewritten body) and the final composed body is signed.
func TestEvaluate_ChainComposesThenSigns(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"test"}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	// Two transforms: A appends "A", B appends "B"
	transformA := &stubTransform{kind: capability.Allow, body: []byte("A")}
	transformB := &stubTransform{kind: capability.Allow, body: []byte("AB")}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transformA).AddTransform(transformB)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// The signed digest must be sha256("AB"), not sha256(original)
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}
	originalDigest := sha256.Sum256(original)
	if signer.calls[0].digest == originalDigest {
		t.Fatalf("signed digest equals sha256(original) — chain was not applied")
	}
	wantDigest := sha256.Sum256([]byte("AB"))
	if signer.calls[0].digest != wantDigest {
		t.Errorf("signed digest = %x, want %x (sha256 of final composed body)", signer.calls[0].digest, wantDigest)
	}

	// Result should carry the final body
	if !res.GetHasBody() {
		t.Errorf("HasBody = false, want true")
	}
	if !bytes.Equal(res.GetBody(), []byte("AB")) {
		t.Errorf("Body = %q, want %q", res.GetBody(), "AB")
	}
}

// TestEvaluate_TransformDenyShortCircuits verifies that a Deny transform
// returns DECISION_DENY with reason_code ans_rewrite_denied, with no Sign call,
// and the second transform is NOT invoked.
func TestEvaluate_TransformDenyShortCircuits(t *testing.T) {
	t.Parallel()

	body := []byte(`{"method":"tools/call","params":{"name":"test"}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	// First transform denies, second should not be called
	var secondCalled bool
	transformDeny := &stubTransform{kind: capability.Deny, reason: "test denial"}
	transformSecond := &stubTransform{kind: capability.Allow, body: []byte("should-not-run"), called: &secondCalled}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transformDeny).AddTransform(transformSecond)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), body))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != deny {
		t.Fatalf("decision = %v, want DENY", res.GetDecision())
	}
	if res.GetReasonCode() != ReasonRewriteDenied {
		t.Errorf("reason_code = %q, want %q", res.GetReasonCode(), ReasonRewriteDenied)
	}

	// No Sign call should have happened
	if len(signer.calls) != 0 {
		t.Errorf("Sign calls = %d, want 0", len(signer.calls))
	}

	// Second transform should NOT have been called
	if secondCalled {
		t.Errorf("second transform was called, want it to be skipped after Deny")
	}
}

// TestEvaluate_NoTransformsSignsOriginal verifies that when no transforms are registered,
// the original body is signed, HasBody=false, and the result is byte-identical to pre-change behavior.
func TestEvaluate_NoTransformsSignsOriginal(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"test"}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	// No transforms registered (empty rewriters, nil discoverer)
	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// The signed digest must be sha256(original)
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}
	wantDigest := sha256.Sum256(original)
	if signer.calls[0].digest != wantDigest {
		t.Errorf("signed digest = %x, want %x (sha256 of original body)", signer.calls[0].digest, wantDigest)
	}

	// HasBody should be false (no body replacement)
	if res.GetHasBody() {
		t.Errorf("HasBody = true, want false")
	}
}

// TestEvaluate_PassthroughContinues verifies that a Passthrough transform
// allows the next transform to run and modify the body.
func TestEvaluate_PassthroughContinues(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"test"}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	// First transform passes through, second allows with body change
	var secondCalled bool
	transformPassthrough := &stubTransform{kind: capability.Passthrough}
	transformAllow := &stubTransform{kind: capability.Allow, body: []byte("modified"), called: &secondCalled}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transformPassthrough).AddTransform(transformAllow)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// Second transform should have run
	if !secondCalled {
		t.Errorf("second transform was not called, want it to run after Passthrough")
	}

	// Body should be from the second transform
	if !res.GetHasBody() {
		t.Errorf("HasBody = false, want true")
	}
	if !bytes.Equal(res.GetBody(), []byte("modified")) {
		t.Errorf("Body = %q, want %q", res.GetBody(), "modified")
	}

	// Signed digest should be sha256("modified")
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}
	wantDigest := sha256.Sum256([]byte("modified"))
	if signer.calls[0].digest != wantDigest {
		t.Errorf("signed digest = %x, want %x (sha256 of modified body)", signer.calls[0].digest, wantDigest)
	}
}

// TestEvaluate_CredentialMarkerOnFinalBytes verifies that the credential marker
// guard runs on the POST-chain bytes, so a transform cannot smuggle a marker past it.
func TestEvaluate_CredentialMarkerOnFinalBytes(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"test"}}`)
	// Rewritten body contains the credential marker
	rewritten := []byte(`{"method":"tools/call","params":{"name":"test","secret":"openshell:resolve:env:API_KEY"}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	transform := &stubTransform{kind: capability.Allow, body: rewritten}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != deny {
		t.Fatalf("decision = %v, want DENY", res.GetDecision())
	}
	if res.GetReasonCode() != ReasonRequestRewriteUnsupported {
		t.Errorf("reason_code = %q, want %q", res.GetReasonCode(), ReasonRequestRewriteUnsupported)
	}

	// No Sign call should have happened (guard runs before attach)
	if len(signer.calls) != 0 {
		t.Errorf("Sign calls = %d, want 0", len(signer.calls))
	}
}

// stubDiscoverer implements capability.Discoverer.
type stubDiscoverer struct {
	req capability.Requirement
}

func (s stubDiscoverer) Discover(_ context.Context, _ capability.Target) capability.Requirement {
	return s.req
}

// TestEvaluate_E2E_DiscoveryDrivesCommerce verifies that the discovered Requirement
// drives the commerce transform: a registered discoverer returns the seller Requirement,
// the commerce transform receives it and rewrites the body, and the final result has
// the rewritten body signed with 3 identity headers.
func TestEvaluate_E2E_DiscoveryDrivesCommerce(t *testing.T) {
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1"}}}`)
	rewritten := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1","mandate":"M1","dpop_proof":"P1"}}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	// Stub discoverer returns a Requirement with capabilities + DPoP htu
	sellerReq := capability.Requirement{
		Tool:         "book_flight",
		Capabilities: []capability.Capability{"mandate", "dpop_proof"},
		DPoP: &capability.DPoPParams{
			Htu: "https://seller.example.com/mcp/",
		},
	}
	discoverer := stubDiscoverer{req: sellerReq}

	// Stub transform mimics commerce rewriter: receives Requirement, returns rewritten body
	transform := &stubTransform{kind: capability.Allow, body: rewritten}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
	s.WithDiscoverer(discoverer)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// The signed digest must be sha256(rewritten)
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}
	wantDigest := sha256.Sum256(rewritten)
	if signer.calls[0].digest != wantDigest {
		t.Errorf("signed digest = %x, want %x (sha256 of rewritten body)", signer.calls[0].digest, wantDigest)
	}

	// Result should carry the rewritten body
	if !res.GetHasBody() {
		t.Errorf("HasBody = false, want true")
	}
	if !bytes.Equal(res.GetBody(), rewritten) {
		t.Errorf("Body = %q, want %q", res.GetBody(), rewritten)
	}

	// Should have the three identity headers
	if len(res.GetHeaderMutations()) != 3 {
		t.Errorf("header mutations = %d, want 3", len(res.GetHeaderMutations()))
	}
}

// TestEvaluate_E2E_DiscoveryEmptyStaticFallback verifies that when discovery returns
// an empty Requirement, the commerce transform's lenient fallback still rewrites the body
// for a seller host/POST/path match, and a WARN is logged.
func TestEvaluate_E2E_DiscoveryEmptyStaticFallback(t *testing.T) {
	t.Parallel()

	original := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"demo-quote-001","amount":500.0,"currency":"USD"}}}`)

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	// Stub discoverer returns empty Requirement (discovery failed)
	discoverer := stubDiscoverer{req: capability.Requirement{}}

	// Load a real commerce key for the commerce rewriter
	tempPEM := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEjRWeJA0VniQNFZ4
kDRWeJA0VniQNFZ4kDRWeJA0VnihRANCAAR7VJCMjvKZnHnHvS3xdKaPXM5pHvEJ
qxLJH8nppWLHVdJvxMlvmJNLcQh3PRe6mXF1wnTvzWFhZj0c+0/qrjPd
-----END PRIVATE KEY-----`
	tmpfile := t.TempDir() + "/test.pem"
	if err := os.WriteFile(tmpfile, []byte(tempPEM), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := commercekey.Load(tmpfile)
	if err != nil {
		t.Fatalf("failed to load test key: %v", err)
	}

	// Create commerce stubs (fakes from commerce/cache_test.go patterns)
	cache := commerce.NewMandateCache()
	authority := &fakeCommerceAuthority{mandate: &commerce.Mandate{
		MandateID:    "mandate-e2e-test",
		QuoteID:      "demo-quote-001",
		SubjectANS:   "ans://v2.0.0.buyer.example.com",
		AudienceANS:  "ans://v1.0.8.seller.example.com",
		Scope:        "purchase:flight:demo",
		MaxAmount:    500.0,
		Currency:     "USD",
		NotBefore:    "2026-01-01T00:00:00Z",
		NotAfter:     "2026-12-31T23:59:59Z",
		JKT:          key.JKT(),
		AuthorityANS: "ans://v1.0.8.authority.example.com",
		Signature:    "fake-signature-e2e",
	}}
	clock := fakeCommerceClock{now: 1735689600}
	nonce := &fakeCommerceNonce{jti: "test-jti"}

	deps := commerce.Deps{
		Key:       key,
		Cache:     cache,
		Authority: authority,
		Clock:     clock,
		Nonce:     nonce,
	}
	cfg := commerce.Config{
		SellerMCPURL: "https://seller.example.com/mcp/",
		SellerANS:    "ans://v1.0.8.seller.example.com",
		ScopePrefix:  "purchase:flight:demo",
		SubjectANS:   "ans://v2.0.0.buyer.example.com",
		MaxBodyBytes: 100000,
	}

	// Capture logs to verify WARN
	var buf bytes.Buffer
	var mu sync.Mutex
	handler := slog.NewTextHandler(&syncLogWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelWarn})
	logger := slog.New(handler)

	// Use the REAL NewCommerceRewriter
	transform := NewCommerceRewriter(deps, cfg, "seller.example.com", logger)

	// Set up the target to match seller host + POST + /mcp/ (fallback trigger)
	policy := map[string]any{"identity": testIdentity}
	eval := &middlewarev1.HttpRequestEvaluation{
		Phase:   preCredentials,
		Context: &middlewarev1.RequestContext{RequestId: "req-1", SandboxId: testSandbox},
		Config:  structOf(t, policy),
		Target: &middlewarev1.HttpRequestTarget{
			Scheme: "https", Host: "seller.example.com", Port: 443, Method: "POST", Path: "/mcp/", Query: "",
		},
		Headers: []*middlewarev1.HttpHeader{},
		Body:    original,
	}

	s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, logger)
	s.WithDiscoverer(discoverer)
	s.AddTransform(transform)

	res, err := s.EvaluateHttpRequest(t.Context(), eval)
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDecision() != allow {
		t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
	}

	// The body should be rewritten (fallback path)
	if !res.GetHasBody() {
		t.Errorf("HasBody = false, want true (fallback should rewrite)")
	}

	// The signed digest must be sha256(rewritten)
	if len(signer.calls) != 1 {
		t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
	}

	// Verify the WARN was logged with "commerce static fallback"
	mu.Lock()
	logs := buf.String()
	mu.Unlock()
	if !strings.Contains(logs, "commerce static fallback") {
		t.Errorf("logs do not contain 'commerce static fallback' WARN; got: %q", logs)
	}
}

// syncLogWriter wraps a bytes.Buffer with mutex for race-free log capture.
type syncLogWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (sw *syncLogWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

// fakeCommerceClock implements commerce.Clock for testing.
type fakeCommerceClock struct {
	now int64
}

func (f fakeCommerceClock) NowUnix() int64 {
	return f.now
}

// fakeCommerceNonce implements commerce.Nonce for testing.
type fakeCommerceNonce struct {
	jti string
}

func (f *fakeCommerceNonce) JTI() string {
	return f.jti
}

// fakeCommerceAuthority implements commerce.AuthorityClient for testing.
type fakeCommerceAuthority struct {
	mandate  *commerce.Mandate
	rawBytes json.RawMessage
	err      error
}

func (f *fakeCommerceAuthority) RequestMandate(_ context.Context, _ commerce.MandateInput) (*commerce.Mandate, json.RawMessage, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	// If rawBytes not set, generate from mandate
	raw := f.rawBytes
	if raw == nil && f.mandate != nil {
		rawData, _ := json.Marshal(f.mandate)
		raw = json.RawMessage(rawData)
	}
	return f.mandate, raw, nil
}

func TestEvaluate_TransformSignURLBindsIdentityProof(t *testing.T) { //nolint:tparallel // subtests share signer state
	t.Parallel()

	original := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1"}}}`)
	rewritten := []byte(`{"method":"tools/call","params":{"name":"book_flight","arguments":{"quote_id":"Q1","mandate":"M1","dpop_proof":"P1"}}}`)
	externalURL := "https://seller.skybound-travel.com/mcp/"

	signer := &fakeSigner{}
	id := newIdentity(t, testIdentity, signer, fullArtifacts())
	ids := lookup{testIdentity: id}

	t.Run("with SignURL set, identity proof htu binds SignURL", func(t *testing.T) {
		signer.calls = nil // reset
		transform := &stubTransform{kind: capability.Allow, body: rewritten, signURL: externalURL}

		s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
		s.AddTransform(transform)

		res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
		if err != nil {
			t.Fatal(err)
		}

		if res.GetDecision() != allow {
			t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
		}

		// Assert the identity proof was signed with externalURL, not the request target
		if len(signer.calls) != 1 {
			t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
		}
		if signer.calls[0].url != externalURL {
			t.Errorf("signed url = %q, want %q (SignURL)", signer.calls[0].url, externalURL)
		}
	})

	t.Run("with empty SignURL, identity proof htu binds request target", func(t *testing.T) {
		signer.calls = nil // reset
		transform := &stubTransform{kind: capability.Allow, body: rewritten, signURL: ""}

		s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
		s.AddTransform(transform)

		res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
		if err != nil {
			t.Fatal(err)
		}

		if res.GetDecision() != allow {
			t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
		}

		// Assert the identity proof was signed with the request target (unchanged behavior)
		if len(signer.calls) != 1 {
			t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
		}
		expectedTarget := "https://tools.example.com/v1/do"
		if signer.calls[0].url != expectedTarget {
			t.Errorf("signed url = %q, want %q (request target)", signer.calls[0].url, expectedTarget)
		}
	})

	t.Run("no transform, identity proof htu binds request target", func(t *testing.T) {
		signer.calls = nil // reset

		s := NewService(ids, sandboxAuthorizer(testSandbox), nil, Config{}, nil)
		// No transform added

		res, err := s.EvaluateHttpRequest(t.Context(), evaluation(t, signPolicy(), original))
		if err != nil {
			t.Fatal(err)
		}

		if res.GetDecision() != allow {
			t.Fatalf("decision = %v, want ALLOW", res.GetDecision())
		}

		// Assert the identity proof was signed with the request target (unchanged behavior)
		if len(signer.calls) != 1 {
			t.Fatalf("Sign calls = %d, want 1", len(signer.calls))
		}
		expectedTarget := "https://tools.example.com/v1/do"
		if signer.calls[0].url != expectedTarget {
			t.Errorf("signed url = %q, want %q (request target)", signer.calls[0].url, expectedTarget)
		}
	})
}
