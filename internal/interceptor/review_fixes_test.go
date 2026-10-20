package interceptor

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/openshellv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/sandboxv1"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// policyOf builds a CreateSandbox operation whose single rule admits hosts.
func policyOf(t *testing.T, hosts ...string) *structpb.Struct {
	t.Helper()
	return toStruct(t, createSandbox(map[string]*sandboxv1.NetworkPolicyRule{"r": rule(hosts...)}))
}

func TestUpdateConfigHosts(t *testing.T) {
	t.Parallel()
	req := &openshellv1.UpdateConfigRequest{
		Sandbox: "sb-1",
		Policy:  &sandboxv1.SandboxPolicy{NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{"r": rule("policy.example.com")}},
		MergeOperations: []*openshellv1.PolicyMergeOperation{
			{Operation: &openshellv1.PolicyMergeOperation_AddRule{AddRule: &openshellv1.AddNetworkRule{RuleName: "added", Rule: rule("added.example.com")}}},
			{Operation: &openshellv1.PolicyMergeOperation_AddAllowRules{AddAllowRules: &openshellv1.AddAllowRules{
				Target: &openshellv1.L7RuleTarget{RuleName: "r", Host: "allow.example.com"}}}},
			{Operation: &openshellv1.PolicyMergeOperation_AddDenyRules{AddDenyRules: &openshellv1.AddDenyRules{
				Target: &openshellv1.L7RuleTarget{RuleName: "r", Host: "deny.example.com"}}}},
			{Operation: &openshellv1.PolicyMergeOperation_RemoveRule{RemoveRule: &openshellv1.RemoveNetworkRule{RuleName: "old"}}},
		},
	}
	hosts, err := updateConfigHosts(toStruct(t, req), nil)
	if err != nil {
		t.Fatalf("updateConfigHosts() error = %v", err)
	}
	want := []string{"policy.example.com", "added.example.com", "allow.example.com"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") {
		t.Fatalf("updateConfigHosts() = %v, want %v", hosts, want)
	}
	if _, err := updateConfigHosts(nil, nil); err == nil {
		t.Fatal("updateConfigHosts(nil) = nil error")
	}
}

func TestRuleHostsIncludesAllowedIPs(t *testing.T) {
	t.Parallel()
	r := &sandboxv1.NetworkPolicyRule{Endpoints: []*sandboxv1.NetworkEndpoint{
		{Host: "named.example.com", AllowedIps: []string{"192.0.2.1"}},
		{AllowedIps: []string{"203.0.113.5", "198.51.100.0/24"}},
		{Host: "", AllowedIps: nil},
	}}
	got := ruleHosts(r)
	want := []string{"named.example.com", "203.0.113.5", "198.51.100.0/24"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ruleHosts() = %v, want %v", got, want)
	}
}

func TestEvaluateUpdateConfigIsVetted(t *testing.T) {
	t.Parallel()
	fake := &fakeVerifier{verdicts: map[string]vetting.Verdict{"evil.example.com": withStatus(vetting.StatusUnregistered)}}
	svc := NewService(fake, Config{Mode: vetting.ModeRequire}, discardLogger())
	req := &openshellv1.UpdateConfigRequest{Sandbox: "sb-1", MergeOperations: []*openshellv1.PolicyMergeOperation{
		{Operation: &openshellv1.PolicyMergeOperation_AddRule{AddRule: &openshellv1.AddNetworkRule{Rule: rule("evil.example.com")}}},
	}}
	res, err := svc.Evaluate(t.Context(), validateEval("UpdateConfig", toStruct(t, req)))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if res.GetAllowed() || res.GetStatusCode() != statusPermissionDenied || !strings.Contains(res.GetReason(), "evil.example.com") {
		t.Fatalf("UpdateConfig with an unregistered host = %v, want a denial naming it", res)
	}
}

func TestEvaluateCallerKind(t *testing.T) {
	t.Parallel()
	fake := &fakeVerifier{verdicts: map[string]vetting.Verdict{"api.example.com": registered()}}
	svc := NewService(fake, Config{Mode: vetting.ModeRequire}, discardLogger())
	eval := validateEval(methodCreate, policyOf(t, "api.example.com"))

	gateway := extauth.ContextWithCaller(t.Context(), extauth.Caller{Kind: extauth.CallerGateway})
	res, err := svc.Evaluate(gateway, eval)
	if err != nil || !res.GetAllowed() {
		t.Fatalf("gateway caller = %v, %v; want allowed", res, err)
	}
	supervisor := extauth.ContextWithCaller(t.Context(), extauth.Caller{Kind: extauth.CallerSupervisor, SandboxID: "sb-1"})
	res, err = svc.Evaluate(supervisor, eval)
	if err != nil || res.GetAllowed() || res.GetLogAnnotations()["ans.vetting"] != "caller_denied" {
		t.Fatalf("supervisor caller = %v, %v; want denied with caller_denied", res, err)
	}
}

func TestEvaluateModeOffSkipsDecoding(t *testing.T) {
	t.Parallel()
	fake := &fakeVerifier{}
	svc := NewService(fake, Config{Mode: vetting.ModeOff}, discardLogger())
	garbage, _ := structpb.NewStruct(map[string]any{"spec": "not an object"})
	res, err := svc.Evaluate(t.Context(), validateEval(methodCreate, garbage))
	if err != nil || !res.GetAllowed() || res.GetLogAnnotations()["ans.vetting"] != "vetting_off" {
		t.Fatalf("mode off = %v, %v; want allowed with vetting_off", res, err)
	}
	if len(fake.recorded()) != 0 {
		t.Fatalf("mode off performed lookups: %v", fake.recorded())
	}
}

func TestEvaluateTooManyHosts(t *testing.T) {
	t.Parallel()
	hosts := make([]string, 0, maxHosts+1)
	for i := range maxHosts + 1 {
		hosts = append(hosts, "h"+strconv.Itoa(i)+".example.com")
	}
	verdicts := make(map[string]vetting.Verdict, len(hosts))
	for _, h := range hosts {
		verdicts[h] = registered()
	}
	for _, tt := range []struct {
		mode        vetting.Mode
		wantAllowed bool
	}{{mode: vetting.ModeRequire, wantAllowed: false}, {mode: vetting.ModeObserve, wantAllowed: true}} {
		fake := &fakeVerifier{verdicts: verdicts}
		svc := NewService(fake, Config{Mode: tt.mode}, discardLogger())
		res, err := svc.Evaluate(t.Context(), validateEval(methodCreate, policyOf(t, hosts...)))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if res.GetAllowed() != tt.wantAllowed || res.GetLogAnnotations()["ans.vetting"] != "too_many_hosts" {
			t.Fatalf("%s: result = %v, want allowed=%v with too_many_hosts", tt.mode, res, tt.wantAllowed)
		}
		if n := len(fake.hosts()); n != maxHosts {
			t.Fatalf("%s: looked up %d hosts, want %d", tt.mode, n, maxHosts)
		}
		if !tt.wantAllowed && !strings.Contains(res.GetReason(), "more than") {
			t.Fatalf("%s: reason %q does not explain the cap", tt.mode, res.GetReason())
		}
	}
}

func TestEvaluateObserveNeverWaits(t *testing.T) {
	t.Parallel()
	fake := &fakeVerifier{coldFirst: true, verdicts: map[string]vetting.Verdict{"cold.example.com": registered()}}
	svc := NewService(fake, Config{Mode: vetting.ModeObserve}, discardLogger())
	res, err := svc.Evaluate(t.Context(), validateEval(methodCreate, policyOf(t, "cold.example.com")))
	if err != nil || !res.GetAllowed() {
		t.Fatalf("observe = %v, %v; want allowed", res, err)
	}
	for _, c := range fake.recorded() {
		if c.wait != 0 {
			t.Fatalf("observe waited %v for %s", c.wait, c.host)
		}
	}
	if ann := res.GetLogAnnotations()["ans.vetting.verdicts"]; ann != "cold.example.com=unknown" {
		t.Fatalf("verdicts annotation = %q, want the cold host reported unknown", ann)
	}
}

// callsWithin compares recorded lookups, allowing a bounded wait to fall short
// of the requested budget by up to tol: the wait is the budget's remainder.
func callsWithin(got, want []lookupCall, tol time.Duration) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i].host != want[i].host {
			return false
		}
		if want[i].wait == 0 && got[i].wait != 0 {
			return false
		}
		if want[i].wait != 0 && (got[i].wait > want[i].wait || got[i].wait < want[i].wait-tol) {
			return false
		}
	}
	return true
}

func TestEvaluateProviderProfilesAreVetted(t *testing.T) {
	t.Parallel()
	verdicts := map[string]vetting.Verdict{"evil.example.com": withStatus(vetting.StatusUnregistered), "crm.example.com": registered()}
	tests := []struct {
		name   string
		method string
		op     *structpb.Struct
	}{
		{name: "import", method: methodImport, op: toStruct(t, importProviderProfiles(
			providerProfile("crm", endpoint("crm.example.com")), providerProfile("evil", endpoint("evil.example.com"))))},
		{name: "update", method: methodUpdate, op: toStruct(t, updateProviderProfiles(providerProfile("crm", endpoint("evil.example.com"))))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require := NewService(&fakeVerifier{verdicts: verdicts}, Config{Mode: vetting.ModeRequire}, discardLogger())
			res, err := require.Evaluate(t.Context(), validateEval(tt.method, tt.op))
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if res.GetAllowed() || res.GetStatusCode() != statusPermissionDenied || !strings.Contains(res.GetReason(), "evil.example.com") {
				t.Fatalf("%s with an unregistered profile endpoint = %v, want a denial naming it", tt.method, res)
			}
			observe := NewService(&fakeVerifier{verdicts: verdicts}, Config{Mode: vetting.ModeObserve}, discardLogger())
			res, err = observe.Evaluate(t.Context(), validateEval(tt.method, tt.op))
			if err != nil || !res.GetAllowed() || !strings.Contains(res.GetLogAnnotations()["ans.vetting.verdicts"], "evil.example.com=unregistered") {
				t.Fatalf("observe %s = %v, %v; want allowed with the unregistered endpoint annotated", tt.method, res, err)
			}
		})
	}
}

func TestEvaluateDraftApprovals(t *testing.T) {
	t.Parallel()
	verdicts := map[string]vetting.Verdict{"evil.example.com": withStatus(vetting.StatusUnregistered), "crm.example.com": registered()}
	stored := func(host string) *structpb.Struct {
		return draftState(t, draftChunk("c1", "pending", "", rule(host)))
	}
	operations := map[string]*structpb.Struct{
		methodApprove:    toStruct(t, approveDraftChunk("c1")),
		methodApproveAll: toStruct(t, approveAllDraftChunks(false, "c1")),
	}
	tests := []struct {
		name        string
		mode        vetting.Mode
		state       *structpb.Struct
		wantAllowed bool
		wantOutcome string
		wantReason  string
	}{
		{name: "require denies an unregistered stored rule", mode: vetting.ModeRequire, state: stored("evil.example.com"), wantReason: "evil.example.com"},
		{name: "require allows a registered stored rule", mode: vetting.ModeRequire, state: stored("crm.example.com"), wantAllowed: true},
		{name: "require refuses an approval it cannot resolve", mode: vetting.ModeRequire, wantOutcome: "draft_unresolved", wantReason: "current_state"},
		{name: "observe lets an unresolved approval through and records it", mode: vetting.ModeObserve, wantAllowed: true, wantOutcome: "draft_unresolved"},
		{name: "require refuses state without draft chunks", mode: vetting.ModeRequire, state: mustStruct(t, map[string]any{"resourceVersion": "7"}), wantOutcome: "draft_unresolved", wantReason: "no draft chunks"},
		{name: "require refuses an undecodable state", mode: vetting.ModeRequire, state: mustStruct(t, map[string]any{"chunks": "nope"}), wantOutcome: "draft_unresolved", wantReason: "current_state"},
		{name: "observe lets an undecodable state through and records it", mode: vetting.ModeObserve, state: mustStruct(t, map[string]any{"chunks": "nope"}), wantAllowed: true, wantOutcome: "draft_unresolved"},
	}
	for method, op := range operations {
		for _, tt := range tests {
			t.Run(method+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				svc := NewService(&fakeVerifier{verdicts: verdicts}, Config{Mode: tt.mode}, discardLogger())
				res, err := svc.Evaluate(t.Context(), validateEvalWithState(method, op, tt.state))
				if err != nil {
					t.Fatalf("Evaluate() error = %v", err)
				}
				if res.GetAllowed() != tt.wantAllowed {
					t.Fatalf("allowed = %v, want %v (%v)", res.GetAllowed(), tt.wantAllowed, res)
				}
				if !tt.wantAllowed && res.GetStatusCode() != statusPermissionDenied {
					t.Fatalf("status = %q, want %q", res.GetStatusCode(), statusPermissionDenied)
				}
				if tt.wantOutcome != "" && res.GetLogAnnotations()["ans.vetting"] != tt.wantOutcome {
					t.Fatalf("outcome = %q, want %q", res.GetLogAnnotations()["ans.vetting"], tt.wantOutcome)
				}
				if got := res.GetLogAnnotations()["ans.vetting.denied"]; got != strconv.FormatBool(!tt.wantAllowed) {
					t.Fatalf("denied annotation = %q, want %v", got, !tt.wantAllowed)
				}
				if tt.wantReason != "" && !strings.Contains(res.GetReason(), tt.wantReason) {
					t.Fatalf("reason %q does not mention %q", res.GetReason(), tt.wantReason)
				}
			})
		}
	}
}
