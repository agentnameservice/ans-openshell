package interceptor

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/openshellv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/sandboxv1"
)

// hostExtractor decodes a proposed operation and returns every destination
// host it would admit.
type hostExtractor func(*structpb.Struct) ([]string, error)

type binding struct {
	id      string
	rpc     string
	extract hostExtractor
}

func newBinding(id, fullMethod string, extract hostExtractor) binding {
	return binding{id: id, rpc: strings.TrimPrefix(fullMethod, "/"), extract: extract}
}

func newBindings() []binding {
	return []binding{
		newBinding("create-sandbox", openshellv1.OpenShell_CreateSandbox_FullMethodName, createSandboxHosts),
		newBinding("update-config", openshellv1.OpenShell_UpdateConfig_FullMethodName, updateConfigHosts),
		newBinding("submit-policy-analysis", openshellv1.OpenShell_SubmitPolicyAnalysis_FullMethodName, submitPolicyAnalysisHosts),
		newBinding("edit-draft-chunk", openshellv1.OpenShell_EditDraftChunk_FullMethodName, editDraftChunkHosts),
	}
}

// updateConfigHosts covers both ways UpdateConfig admits destinations: a
// replacement policy and merge operations that add rules or allow-rule
// targets. Removals and deny rules grant nothing and are not vetted.
func updateConfigHosts(op *structpb.Struct) ([]string, error) {
	var req openshellv1.UpdateConfigRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	var hosts []string
	for _, rule := range req.GetPolicy().GetNetworkPolicies() {
		hosts = append(hosts, ruleHosts(rule)...)
	}
	for _, m := range req.GetMergeOperations() {
		if add := m.GetAddRule(); add != nil {
			hosts = append(hosts, ruleHosts(add.GetRule())...)
		}
		if allow := m.GetAddAllowRules(); allow != nil && allow.GetTarget().GetHost() != "" {
			hosts = append(hosts, allow.GetTarget().GetHost())
		}
	}
	return hosts, nil
}

func createSandboxHosts(op *structpb.Struct) ([]string, error) {
	var req openshellv1.CreateSandboxRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	var hosts []string
	for _, rule := range req.GetSpec().GetPolicy().GetNetworkPolicies() {
		hosts = append(hosts, ruleHosts(rule)...)
	}
	return hosts, nil
}

func submitPolicyAnalysisHosts(op *structpb.Struct) ([]string, error) {
	var req openshellv1.SubmitPolicyAnalysisRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	var hosts []string
	for _, chunk := range req.GetProposedChunks() {
		hosts = append(hosts, ruleHosts(chunk.GetProposedRule())...)
	}
	return hosts, nil
}

func editDraftChunkHosts(op *structpb.Struct) ([]string, error) {
	var req openshellv1.EditDraftChunkRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	return ruleHosts(req.GetProposedRule()), nil
}

// ruleHosts lists every destination a rule admits. An endpoint without a host
// admits whatever resolves into its allowed_ips, so those addresses stand in
// for the host and are vetted as IP destinations.
func ruleHosts(rule *sandboxv1.NetworkPolicyRule) []string {
	endpoints := rule.GetEndpoints()
	hosts := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.GetHost() == "" {
			hosts = append(hosts, ep.GetAllowedIps()...)
			continue
		}
		hosts = append(hosts, ep.GetHost())
	}
	return hosts
}

// decodeOperation converts the gateway's protobuf-JSON Struct into msg,
// ignoring fields this build of the contract does not know.
func decodeOperation(op *structpb.Struct, msg proto.Message) error {
	if op == nil {
		return errors.New("proposed_operation is required")
	}
	raw, err := protojson.Marshal(op)
	if err != nil {
		return fmt.Errorf("encode proposed_operation: %w", err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, msg); err != nil {
		return fmt.Errorf("decode proposed_operation: %w", err)
	}
	return nil
}

// normalizeHosts lowercases, trims, drops trailing dots and empties, dedupes
// and sorts so evaluation and annotations are deterministic.
func normalizeHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if _, dup := seen[h]; h == "" || dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}
