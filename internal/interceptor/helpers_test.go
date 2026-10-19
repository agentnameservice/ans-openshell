package interceptor

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/interceptorv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/openshellv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/sandboxv1"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

const (
	testAudience     = "urn:openshell:extension:interceptor:ans"
	openShellService = "openshell.v1.OpenShell"
	methodCreate     = "CreateSandbox"
	methodSubmit     = "SubmitPolicyAnalysis"
	methodEdit       = "EditDraftChunk"
)

type lookupCall struct {
	host string
	wait time.Duration
}

// fakeVerifier answers scripted verdicts and records every Lookup. With
// coldFirst set, a zero-wait Lookup answers StatusUnknown so the bounded
// second pass runs for every host.
type fakeVerifier struct {
	mu        sync.Mutex
	verdicts  map[string]vetting.Verdict
	calls     []lookupCall
	coldFirst bool
}

func (f *fakeVerifier) Lookup(_ context.Context, host string, wait time.Duration) vetting.Verdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, lookupCall{host: host, wait: wait})
	v, ok := f.verdicts[host]
	if !ok || (f.coldFirst && wait == 0) {
		return vetting.Verdict{Host: host, Status: vetting.StatusUnknown}
	}
	v.Host = host
	return v
}

func (f *fakeVerifier) recorded() []lookupCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]lookupCall(nil), f.calls...)
}

// hosts returns the distinct hosts looked up, in first-call order.
func (f *fakeVerifier) hosts() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range f.recorded() {
		if !seen[c.host] {
			seen[c.host] = true
			out = append(out, c.host)
		}
	}
	return out
}

func registered() vetting.Verdict {
	return vetting.Verdict{Status: vetting.StatusRegistered, AnsName: "ans://v1.0.0.tools.example.com", BadgeStatus: "ACTIVE"}
}

func withStatus(s vetting.Status) vetting.Verdict { return vetting.Verdict{Status: s} }

func toStruct(t *testing.T, msg proto.Message) *structpb.Struct {
	t.Helper()
	raw, err := protojson.Marshal(msg)
	if err != nil {
		t.Fatalf("protojson.Marshal: %v", err)
	}
	var st structpb.Struct
	if err := protojson.Unmarshal(raw, &st); err != nil {
		t.Fatalf("protojson.Unmarshal into Struct: %v", err)
	}
	return &st
}

func mustStruct(t *testing.T, v map[string]any) *structpb.Struct {
	t.Helper()
	st, err := structpb.NewStruct(v)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return st
}

func rule(hosts ...string) *sandboxv1.NetworkPolicyRule {
	endpoints := make([]*sandboxv1.NetworkEndpoint, 0, len(hosts))
	for _, h := range hosts {
		endpoints = append(endpoints, &sandboxv1.NetworkEndpoint{Host: h, Port: 443, Protocol: "rest"})
	}
	return &sandboxv1.NetworkPolicyRule{Name: "rule", Endpoints: endpoints}
}

func createSandbox(rules map[string]*sandboxv1.NetworkPolicyRule) *openshellv1.CreateSandboxRequest {
	return &openshellv1.CreateSandboxRequest{
		Name: "sb-1",
		Spec: &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: rules}},
	}
}

func submitPolicyAnalysis(rules ...*sandboxv1.NetworkPolicyRule) *openshellv1.SubmitPolicyAnalysisRequest {
	chunks := make([]*openshellv1.PolicyChunk, 0, len(rules))
	for i, r := range rules {
		chunks = append(chunks, &openshellv1.PolicyChunk{Id: "chunk-" + string(rune('a'+i)), RuleName: "rule", ProposedRule: r})
	}
	return &openshellv1.SubmitPolicyAnalysisRequest{Name: "sb-1", AnalysisMode: "agent_authored", ProposedChunks: chunks}
}

func editDraftChunk(r *sandboxv1.NetworkPolicyRule) *openshellv1.EditDraftChunkRequest {
	return &openshellv1.EditDraftChunkRequest{Sandbox: "sb-1", ChunkId: "chunk-a", ProposedRule: r}
}

func validateEval(method string, op *structpb.Struct) *interceptorv1.InterceptorEvaluation {
	return &interceptorv1.InterceptorEvaluation{
		InterceptorName: "ans",
		BindingId:       "test-binding",
		Service:         openShellService,
		Method:          method,
		Phase:           &interceptorv1.InterceptorEvaluation_Validate{Validate: &interceptorv1.ValidateEvaluation{ProposedOperation: op}},
	}
}

func withService(e *interceptorv1.InterceptorEvaluation, service string) *interceptorv1.InterceptorEvaluation {
	e.Service = service
	return e
}

func gatewayPeer(major, minor uint32, required ...string) *extensionv1.PeerMetadata {
	return &extensionv1.PeerMetadata{
		ProtocolVersion:       &extensionv1.ProtocolVersion{Major: major, Minor: minor},
		ImplementationName:    "openshell/test",
		ImplementationVersion: "0.0.0-test",
		SupportedCapabilities: []string{contractCapability},
		RequiredCapabilities:  required,
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
