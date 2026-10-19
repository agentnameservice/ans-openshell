package interceptor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/interceptorv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/sandboxv1"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

func TestDescribe(t *testing.T) {
	t.Parallel()
	svc := NewService(&fakeVerifier{}, Config{Audience: testAudience, ImplementationVersion: "v0.1.0-test"}, discardLogger())
	tests := []struct {
		name     string
		gateway  *extensionv1.PeerMetadata
		wantCode codes.Code
	}{
		{name: "protocol 1.0", gateway: gatewayPeer(1, 0)},
		{name: "protocol 1.3", gateway: gatewayPeer(1, 3)},
		{name: "requires the contract capability", gateway: gatewayPeer(1, 0, contractCapability)},
		{name: "missing metadata", gateway: nil, wantCode: codes.FailedPrecondition},
		{name: "missing protocol version", gateway: &extensionv1.PeerMetadata{ImplementationName: "openshell/test"}, wantCode: codes.FailedPrecondition},
		{name: "major 2", gateway: gatewayPeer(2, 0), wantCode: codes.FailedPrecondition},
		{name: "requires unsupported capability", gateway: gatewayPeer(1, 0, contractCapability, "openshell.gateway-interceptor.provider-profiles"), wantCode: codes.FailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := svc.Describe(t.Context(), &interceptorv1.DescribeRequest{Gateway: tt.gateway})
			if tt.wantCode != codes.OK {
				if status.Code(err) != tt.wantCode || m != nil {
					t.Fatalf("Describe() = %v, %v; want code %v", m, err, tt.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("Describe() error = %v", err)
			}
			checkManifest(t, m)
		})
	}
}

func checkManifest(t *testing.T, m *interceptorv1.InterceptorManifest) {
	t.Helper()
	if m.GetName() != "ans-openshell-interceptor" || m.GetFailurePolicy() != "fail_closed" || m.GetProviderProfiles() {
		t.Fatalf("manifest header = %q/%q/%v", m.GetName(), m.GetFailurePolicy(), m.GetProviderProfiles())
	}
	if m.GetExpectedAudience() != testAudience {
		t.Fatalf("expected_audience = %q, want %q", m.GetExpectedAudience(), testAudience)
	}
	ext := m.GetExtension()
	if ext.GetProtocolVersion().GetMajor() != 1 || ext.GetProtocolVersion().GetMinor() != 0 {
		t.Fatalf("protocol_version = %v, want 1.0", ext.GetProtocolVersion())
	}
	if ext.GetImplementationName() != "agentnameservice/ans-openshell" || ext.GetImplementationVersion() != "v0.1.0-test" {
		t.Fatalf("implementation = %q %q", ext.GetImplementationName(), ext.GetImplementationVersion())
	}
	if !slices.Equal(ext.GetSupportedCapabilities(), []string{"openshell.gateway-interceptor.contract"}) || len(ext.GetRequiredCapabilities()) != 0 {
		t.Fatalf("capabilities = %v / %v", ext.GetSupportedCapabilities(), ext.GetRequiredCapabilities())
	}
	want := map[string]string{
		"create-sandbox":           "openshell.v1.OpenShell/CreateSandbox",
		"update-config":            "openshell.v1.OpenShell/UpdateConfig",
		"submit-policy-analysis":   "openshell.v1.OpenShell/SubmitPolicyAnalysis",
		"edit-draft-chunk":         "openshell.v1.OpenShell/EditDraftChunk",
		"import-provider-profiles": "openshell.v1.OpenShell/ImportProviderProfiles",
		"update-provider-profiles": "openshell.v1.OpenShell/UpdateProviderProfiles",
	}
	if len(m.GetBindings()) != len(want) {
		t.Fatalf("bindings = %v, want %d", m.GetBindings(), len(want))
	}
	for _, b := range m.GetBindings() {
		if rpc, ok := want[b.GetId()]; !ok || b.GetSelector().GetRpc() != rpc {
			t.Errorf("binding %q selects %q, want %q", b.GetId(), b.GetSelector().GetRpc(), rpc)
		}
		if phases := b.GetPhases(); len(phases) != 1 || phases[0] != interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE {
			t.Errorf("binding %q phases = %v, want [VALIDATE]", b.GetId(), phases)
		}
		if b.GetFailurePolicy() != "" {
			t.Errorf("binding %q sets failure_policy %q; the manifest default applies", b.GetId(), b.GetFailurePolicy())
		}
	}
}

func TestEvaluate(t *testing.T) {
	t.Parallel()
	policy := func(hosts ...string) *structpb.Struct {
		return toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{"tools": rule(hosts...)}))
	}
	malformed := mustStruct(t, map[string]any{"spec": map[string]any{"policy": map[string]any{"networkPolicies": "nope"}}})
	unknownFields := mustStruct(t, map[string]any{
		"futureField": 1,
		"spec": map[string]any{"policy": map[string]any{"networkPolicies": map[string]any{
			"tools": map[string]any{"endpoints": []any{map[string]any{"host": "api.example.com", "port": 443, "futureOption": true}}},
		}}},
	})
	manyHosts := make([]string, 0, 12)
	for i := range 12 {
		manyHosts = append(manyHosts, fmt.Sprintf("h%02d.example.com", i+1))
	}
	tests := []struct {
		name        string
		mode        vetting.Mode
		verdicts    map[string]vetting.Verdict
		eval        *interceptorv1.InterceptorEvaluation
		wantAllowed bool
		wantStatus  string
		wantReason  string
		wantAnn     map[string]string
		wantLookups []string
	}{
		{
			name: "create sandbox all registered", mode: vetting.ModeRequire,
			verdicts:    map[string]vetting.Verdict{"api.example.com": registered(), "tools.example.com": registered()},
			eval:        validateEval(methodCreate, policy("api.example.com", "Tools.Example.COM.")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting.mode": "require_registered", "ans.vetting.verdicts": "api.example.com=registered,tools.example.com=registered", "ans.vetting.denied": "false"},
			wantLookups: []string{"api.example.com", "tools.example.com"},
		},
		{
			name: "create sandbox one unregistered", mode: vetting.ModeRequire,
			verdicts:   map[string]vetting.Verdict{"api.example.com": registered(), "evil.example.com": withStatus(vetting.StatusUnregistered)},
			eval:       validateEval(methodCreate, policy("evil.example.com", "api.example.com")),
			wantStatus: "PERMISSION_DENIED",
			wantReason: "ans destination vetting: evil.example.com ans_destination_unregistered",
			wantAnn:    map[string]string{"ans.vetting.verdicts": "api.example.com=registered,evil.example.com=unregistered", "ans.vetting.denied": "true"},
		},
		{
			name: "submit policy analysis revoked", mode: vetting.ModeRequire,
			verdicts:    map[string]vetting.Verdict{"a.example.com": registered(), "b.example.com": withStatus(vetting.StatusRevoked)},
			eval:        validateEval(methodSubmit, toStruct(t, submitPolicyAnalysis(rule("a.example.com"), rule("b.example.com")))),
			wantStatus:  "PERMISSION_DENIED",
			wantReason:  "ans destination vetting: b.example.com ans_destination_revoked",
			wantLookups: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "edit draft chunk unknown host", mode: vetting.ModeRequire,
			eval:       validateEval(methodEdit, toStruct(t, editDraftChunk(rule("new.example.com")))),
			wantStatus: "PERMISSION_DENIED",
			wantReason: "ans destination vetting: new.example.com ans_destination_unverified",
			wantAnn:    map[string]string{"ans.vetting.verdicts": "new.example.com=unknown"},
		},
		{
			name: "untrusted tl and below threshold", mode: vetting.ModeRequire,
			verdicts:   map[string]vetting.Verdict{"a.example.com": withStatus(vetting.StatusUntrustedTL), "b.example.com": withStatus(vetting.StatusBelowThreshold)},
			eval:       validateEval(methodCreate, policy("a.example.com", "b.example.com")),
			wantStatus: "PERMISSION_DENIED",
			wantReason: "ans destination vetting: a.example.com ans_destination_untrusted_tl, b.example.com ans_destination_below_threshold",
		},
		{
			name: "observe never denies", mode: vetting.ModeObserve,
			verdicts:    map[string]vetting.Verdict{"a.example.com": withStatus(vetting.StatusUnregistered), "b.example.com": withStatus(vetting.StatusRevoked)},
			eval:        validateEval(methodCreate, policy("a.example.com", "b.example.com")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting.mode": "observe", "ans.vetting.verdicts": "a.example.com=unregistered,b.example.com=revoked", "ans.vetting.denied": "false"},
		},
		{
			name: "off skips lookups", mode: vetting.ModeOff,
			verdicts:    map[string]vetting.Verdict{"a.example.com": withStatus(vetting.StatusUnregistered)},
			eval:        validateEval(methodCreate, policy("a.example.com")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "vetting_off"},
			wantLookups: []string{},
		},
		{
			name: "exempt hosts are never denied", mode: vetting.ModeRequire,
			verdicts:    map[string]vetting.Verdict{"api.openai.com": withStatus(vetting.StatusExempt), "s3.us-east-1.amazonaws.com": withStatus(vetting.StatusExempt)},
			eval:        validateEval(methodCreate, policy("api.openai.com", "s3.us-east-1.amazonaws.com", "amazonaws.com")),
			wantStatus:  "PERMISSION_DENIED",
			wantReason:  "ans destination vetting: amazonaws.com ans_destination_unverified",
			wantAnn:     map[string]string{"ans.vetting.verdicts": "amazonaws.com=unknown,api.openai.com=exempt,s3.us-east-1.amazonaws.com=exempt"},
			wantLookups: []string{"amazonaws.com", "api.openai.com", "s3.us-east-1.amazonaws.com"},
		},
		{
			name: "exempt in observe", mode: vetting.ModeObserve,
			verdicts:    map[string]vetting.Verdict{"api.openai.com": withStatus(vetting.StatusExempt)},
			eval:        validateEval(methodCreate, policy("api.openai.com")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting.verdicts": "api.openai.com=exempt"},
			wantLookups: []string{"api.openai.com"},
		},
		{
			name: "ip literals settled by the verifier", mode: vetting.ModeRequire,
			verdicts: map[string]vetting.Verdict{
				"192.0.2.5": withStatus(vetting.StatusUnregistered), "2001:db8::1": withStatus(vetting.StatusUnregistered), "[::1]": withStatus(vetting.StatusUnregistered),
			},
			eval:        validateEval(methodCreate, policy("192.0.2.5", "2001:db8::1", "[::1]")),
			wantStatus:  "PERMISSION_DENIED",
			wantReason:  "ans destination vetting: 192.0.2.5 ans_destination_unregistered, 2001:db8::1 ans_destination_unregistered, [::1] ans_destination_unregistered",
			wantLookups: []string{"192.0.2.5", "2001:db8::1", "[::1]"},
		},
		{
			name: "wildcard host errored by the verifier", mode: vetting.ModeRequire,
			verdicts:    map[string]vetting.Verdict{"*.example.com": withStatus(vetting.StatusError)},
			eval:        validateEval(methodCreate, policy("*.example.com")),
			wantStatus:  "PERMISSION_DENIED",
			wantReason:  "ans destination vetting: *.example.com ans_destination_unverified",
			wantAnn:     map[string]string{"ans.vetting.verdicts": "*.example.com=error"},
			wantLookups: []string{"*.example.com"},
		},
		{
			name: "wildcard host observed", mode: vetting.ModeObserve,
			verdicts:    map[string]vetting.Verdict{"**.example.com": withStatus(vetting.StatusError)},
			eval:        validateEval(methodCreate, policy("**.example.com")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting.verdicts": "**.example.com=error", "ans.vetting.denied": "false"},
		},
		{
			name: "dedupe and normalization", mode: vetting.ModeRequire,
			verdicts:    map[string]vetting.Verdict{"api.example.com": registered()},
			eval:        validateEval(methodCreate, policy(" API.Example.com. ", "api.example.com", "")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting.verdicts": "api.example.com=registered"},
			wantLookups: []string{"api.example.com"},
		},
		{
			name: "empty policy", mode: vetting.ModeRequire,
			eval:        validateEval(methodCreate, toStruct(t, createSandbox(nil))),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting.mode": "require_registered", "ans.vetting.verdicts": "", "ans.vetting.denied": "false"},
			wantLookups: []string{},
		},
		{
			name: "unknown fields tolerated", mode: vetting.ModeRequire,
			verdicts:    map[string]vetting.Verdict{"api.example.com": registered()},
			eval:        validateEval(methodCreate, unknownFields),
			wantAllowed: true,
			wantLookups: []string{"api.example.com"},
		},
		{
			name: "unbound method", mode: vetting.ModeRequire,
			eval:        validateEval("DeleteSandbox", policy("evil.example.com")),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "unbound_method"},
			wantLookups: []string{},
		},
		{
			name: "service mismatch is unbound", mode: vetting.ModeRequire,
			eval:        withService(validateEval(methodCreate, policy("evil.example.com")), "openshell.v1.Other"),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "unbound_method"},
			wantLookups: []string{},
		},
		{
			name: "missing service is unbound", mode: vetting.ModeRequire,
			eval:        withService(validateEval(methodCreate, policy("evil.example.com")), ""),
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "unbound_method"},
			wantLookups: []string{},
		},
		{
			name: "modify_operation phase", mode: vetting.ModeRequire,
			eval: &interceptorv1.InterceptorEvaluation{Method: methodCreate, Phase: &interceptorv1.InterceptorEvaluation_ModifyOperation{
				ModifyOperation: &interceptorv1.ModifyOperationEvaluation{ProposedOperation: policy("evil.example.com")}}},
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "skipped_phase"},
			wantLookups: []string{},
		},
		{
			name: "post_commit phase", mode: vetting.ModeRequire,
			eval: &interceptorv1.InterceptorEvaluation{Method: methodCreate, Phase: &interceptorv1.InterceptorEvaluation_PostCommit{
				PostCommit: &interceptorv1.PostCommitEvaluation{CommittedResponse: policy("evil.example.com")}}},
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "skipped_phase"},
		},
		{
			name: "no phase", mode: vetting.ModeRequire,
			eval:        &interceptorv1.InterceptorEvaluation{Method: methodCreate},
			wantAllowed: true,
			wantAnn:     map[string]string{"ans.vetting": "skipped_phase"},
		},
		{
			name: "malformed operation", mode: vetting.ModeRequire,
			eval:        validateEval(methodCreate, malformed),
			wantStatus:  "FAILED_PRECONDITION",
			wantReason:  "ans destination vetting: proposed CreateSandbox operation could not be decoded",
			wantAnn:     map[string]string{"ans.vetting": "decode_error"},
			wantLookups: []string{},
		},
		{
			name: "nil operation", mode: vetting.ModeObserve,
			eval:       validateEval(methodSubmit, nil),
			wantStatus: "FAILED_PRECONDITION",
			wantReason: "ans destination vetting: proposed SubmitPolicyAnalysis operation could not be decoded",
			wantAnn:    map[string]string{"ans.vetting": "decode_error"},
		},
		{
			name: "reason capped at ten hosts", mode: vetting.ModeRequire,
			eval:       validateEval(methodCreate, policy(manyHosts...)),
			wantStatus: "PERMISSION_DENIED",
			wantReason: "ans destination vetting: " + strings.Join(suffixed(manyHosts[:10], " ans_destination_unverified"), ", ") + " (+2 more)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeVerifier{verdicts: tt.verdicts}
			svc := NewService(fake, Config{Audience: testAudience, Mode: tt.mode}, discardLogger())
			res, err := svc.Evaluate(t.Context(), tt.eval)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if res.GetAllowed() != tt.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", res.GetAllowed(), tt.wantAllowed, res.GetReason())
			}
			if res.GetStatusCode() != tt.wantStatus {
				t.Fatalf("status_code = %q, want %q", res.GetStatusCode(), tt.wantStatus)
			}
			if res.GetReason() != tt.wantReason {
				t.Fatalf("reason = %q, want %q", res.GetReason(), tt.wantReason)
			}
			if len(res.GetPatches()) != 0 {
				t.Fatalf("patches = %v, want none in validate", res.GetPatches())
			}
			for k, want := range tt.wantAnn {
				if got, ok := res.GetLogAnnotations()[k]; !ok || got != want {
					t.Errorf("annotation %q = %q (present %v), want %q", k, got, ok, want)
				}
			}
			_, skip := res.GetLogAnnotations()["ans.vetting"]
			if skip && len(res.GetLogAnnotations()) != 1 {
				t.Errorf("skip result carries extra annotations: %v", res.GetLogAnnotations())
			}
			if _, ok := res.GetLogAnnotations()["ans.vetting.mode"]; !skip && !ok {
				t.Errorf("annotations = %v, want ans.vetting.mode/verdicts/denied", res.GetLogAnnotations())
			}
			if tt.wantLookups != nil {
				if got := fake.hosts(); !slices.Equal(got, tt.wantLookups) {
					t.Errorf("looked up %v, want %v", got, tt.wantLookups)
				}
			}
		})
	}
}

func suffixed(hosts []string, suffix string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h+suffix)
	}
	return out
}

func TestEvaluateLookupWait(t *testing.T) {
	t.Parallel()
	eval := func() *interceptorv1.InterceptorEvaluation {
		return validateEval(methodCreate, toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{"r": rule("cold.example.com")})))
	}
	tests := []struct {
		name       string
		wait       time.Duration
		ctx        func(t *testing.T) context.Context
		wantSecond bool
		minWait    time.Duration
		maxWait    time.Duration
	}{
		{name: "default without deadline", ctx: func(t *testing.T) context.Context { return t.Context() },
			wantSecond: true, minWait: defaultLookupWait - 50*time.Millisecond, maxWait: defaultLookupWait},
		{name: "configured without deadline", wait: 200 * time.Millisecond, ctx: func(t *testing.T) context.Context { return t.Context() },
			wantSecond: true, minWait: 150 * time.Millisecond, maxWait: 200 * time.Millisecond},
		{name: "bounded by deadline", ctx: func(t *testing.T) context.Context {
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			t.Cleanup(cancel)
			return ctx
		}, wantSecond: true, minWait: time.Millisecond, maxWait: 150 * time.Millisecond},
		{name: "expired deadline skips the wait", ctx: func(t *testing.T) context.Context {
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			t.Cleanup(cancel)
			return ctx
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeVerifier{}
			svc := NewService(fake, Config{Mode: vetting.ModeRequire, LookupWait: tt.wait}, discardLogger())
			if _, err := svc.Evaluate(tt.ctx(t), eval()); err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			calls := fake.recorded()
			if len(calls) == 0 || calls[0].wait != 0 {
				t.Fatalf("calls = %v, want a zero-wait pass first", calls)
			}
			if !tt.wantSecond {
				if len(calls) != 1 {
					t.Fatalf("calls = %v, want no bounded wait when the deadline has passed", calls)
				}
				return
			}
			if len(calls) != 2 {
				t.Fatalf("calls = %v, want a zero-wait pass then a bounded wait", calls)
			}
			if w := calls[1].wait; w < tt.minWait || w > tt.maxWait {
				t.Fatalf("bounded wait = %v, want within [%v, %v]", w, tt.minWait, tt.maxWait)
			}
		})
	}
}

func TestEvaluateTwoPassLookups(t *testing.T) {
	t.Parallel()
	op := toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{"r": rule("a.example.com", "b.example.com", "c.example.com")}))
	verdicts := map[string]vetting.Verdict{"a.example.com": registered(), "b.example.com": registered()}

	t.Run("warm cache answers in the first pass", func(t *testing.T) {
		t.Parallel()
		fake := &fakeVerifier{verdicts: verdicts}
		svc := NewService(fake, Config{Mode: vetting.ModeRequire, LookupWait: time.Second}, discardLogger())
		res, err := svc.Evaluate(t.Context(), validateEval(methodCreate, op))
		if err != nil || res.GetAllowed() {
			t.Fatalf("Evaluate() = %v, %v; want denied for c.example.com", res, err)
		}
		want := []lookupCall{{"a.example.com", 0}, {"b.example.com", 0}, {"c.example.com", 0}, {"c.example.com", time.Second}}
		if got := fake.recorded(); !callsWithin(got, want, 50*time.Millisecond) {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	})
	t.Run("cold cache waits once per host after starting all", func(t *testing.T) {
		t.Parallel()
		fake := &fakeVerifier{verdicts: verdicts, coldFirst: true}
		svc := NewService(fake, Config{Mode: vetting.ModeRequire, LookupWait: time.Second}, discardLogger())
		res, err := svc.Evaluate(t.Context(), validateEval(methodCreate, op))
		if err != nil || res.GetAllowed() {
			t.Fatalf("Evaluate() = %v, %v; want denied for c.example.com", res, err)
		}
		if res.GetReason() != "ans destination vetting: c.example.com ans_destination_unverified" {
			t.Fatalf("reason = %q", res.GetReason())
		}
		got := fake.recorded()
		if len(got) != 6 {
			t.Fatalf("calls = %v, want 3 zero-wait then 3 bounded", got)
		}
		for i, c := range got {
			if (i < 3) != (c.wait == 0) {
				t.Fatalf("call %d = %v, want zero-wait pass first", i, c)
			}
		}
	})
}

func TestVerdictsAnnotationCap(t *testing.T) {
	t.Parallel()
	const n = 60
	hosts := make([]string, 0, n)
	verdicts := make(map[string]vetting.Verdict, n)
	for i := range n {
		h := fmt.Sprintf("service-%02d.very-long-subdomain.example.com", i)
		hosts = append(hosts, h)
		verdicts[h] = registered()
	}
	svc := NewService(&fakeVerifier{verdicts: verdicts}, Config{Mode: vetting.ModeObserve}, discardLogger())
	op := toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{"r": rule(hosts...)}))
	res, err := svc.Evaluate(t.Context(), validateEval(methodCreate, op))
	if err != nil || !res.GetAllowed() {
		t.Fatalf("Evaluate() = %v, %v", res, err)
	}
	ann := res.GetLogAnnotations()["ans.vetting.verdicts"]
	if len(ann) > maxVerdictsBytes+16 {
		t.Fatalf("verdicts annotation is %d bytes, want about %d", len(ann), maxVerdictsBytes)
	}
	entries := strings.Split(ann, ",")
	var more int
	if _, err := fmt.Sscanf(entries[len(entries)-1], "+%d more", &more); err != nil {
		t.Fatalf("annotation does not end with the overflow marker: %q", ann)
	}
	if shown := len(entries) - 1; shown+more != n || shown == 0 {
		t.Fatalf("shown %d + more %d != %d", shown, more, n)
	}
}

func TestVerdictsAnnotationSingleOversizeEntry(t *testing.T) {
	t.Parallel()
	host := strings.Repeat("a", maxVerdictsBytes)
	got := verdictsAnnotation([]string{host}, []vetting.Verdict{{Status: vetting.StatusRegistered}})
	want := strings.Repeat("a", maxHostLogBytes) + "...=registered"
	if got != want {
		t.Fatalf("verdictsAnnotation() = %q, want %q", got, want)
	}
}

func TestNewServiceDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero", in: 0, want: defaultLookupWait},
		{name: "negative", in: -time.Second, want: defaultLookupWait},
		{name: "set", in: 250 * time.Millisecond, want: 250 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := NewService(&fakeVerifier{}, Config{LookupWait: tt.in}, nil)
			if svc.cfg.LookupWait != tt.want {
				t.Fatalf("LookupWait = %v, want %v", svc.cfg.LookupWait, tt.want)
			}
			if svc.logger == nil {
				t.Fatal("nil logger was not replaced")
			}
		})
	}
}

func TestEvaluateLogs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	svc := NewService(&fakeVerifier{}, Config{Mode: vetting.ModeRequire}, logger)
	bad := mustStruct(t, map[string]any{"proposedRule": "nope"})
	if _, err := svc.Evaluate(t.Context(), validateEval(methodEdit, bad)); err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !strings.Contains(buf.String(), "denied undecodable operation") || !strings.Contains(buf.String(), "method=EditDraftChunk") {
		t.Fatalf("missing decode warning in log:\n%s", buf.String())
	}
	buf.Reset()
	op := toStruct(t, editDraftChunk(rule("x.example.com")))
	if _, err := svc.Evaluate(t.Context(), validateEval(methodEdit, op)); err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !strings.Contains(buf.String(), "destination vetting evaluated") || !strings.Contains(buf.String(), "denied=1") {
		t.Fatalf("missing evaluation log entry:\n%s", buf.String())
	}
	if _, err := svc.Describe(t.Context(), &interceptorv1.DescribeRequest{Gateway: gatewayPeer(1, 2)}); err != nil {
		t.Fatalf("Describe() error = %v", err)
	}
	if !strings.Contains(buf.String(), "gateway negotiated") || !strings.Contains(buf.String(), "protocol=1.2") {
		t.Fatalf("missing negotiation log entry:\n%s", buf.String())
	}
}
