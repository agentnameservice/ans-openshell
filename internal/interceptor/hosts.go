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

// hostExtractor decodes a proposed operation, with the read-only gateway state
// the evaluation carries, and returns every destination host the operation
// would admit.
type hostExtractor func(op, state *structpb.Struct) ([]string, error)

// errDraftUnresolved reports an approval whose stored draft rules the gateway
// did not supply, so the destinations it would install cannot be vetted.
var errDraftUnresolved = errors.New("stored draft rules could not be resolved from current_state")

// The gateway installs only pending chunks, and the state it loads for an
// approval must carry the draft policy's chunks for them to be resolvable.
const (
	draftStatusPending = "pending"
	draftChunksField   = "chunks"
)

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
		newBinding("import-provider-profiles", openshellv1.OpenShell_ImportProviderProfiles_FullMethodName, importProviderProfilesHosts),
		newBinding("update-provider-profiles", openshellv1.OpenShell_UpdateProviderProfiles_FullMethodName, updateProviderProfilesHosts),
		newBinding("approve-draft-chunk", openshellv1.OpenShell_ApproveDraftChunk_FullMethodName, approveDraftChunkHosts),
		newBinding("approve-all-draft-chunks", openshellv1.OpenShell_ApproveAllDraftChunks_FullMethodName, approveAllDraftChunksHosts),
	}
}

// updateConfigHosts covers both ways UpdateConfig admits destinations: a
// replacement policy and merge operations that add rules or allow-rule
// targets. Removals and deny rules grant nothing and are not vetted.
func updateConfigHosts(op, _ *structpb.Struct) ([]string, error) {
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

func createSandboxHosts(op, _ *structpb.Struct) ([]string, error) {
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

func submitPolicyAnalysisHosts(op, _ *structpb.Struct) ([]string, error) {
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

func editDraftChunkHosts(op, _ *structpb.Struct) ([]string, error) {
	var req openshellv1.EditDraftChunkRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	return ruleHosts(req.GetProposedRule()), nil
}

// Provider profiles carry endpoints the gateway composes into every attached
// sandbox's effective policy, so a custom profile admits destinations the same
// way a policy rule does. Built-in profiles never pass through these RPCs.
func importProviderProfilesHosts(op, _ *structpb.Struct) ([]string, error) {
	var req openshellv1.ImportProviderProfilesRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	var hosts []string
	for _, item := range req.GetProfiles() {
		hosts = append(hosts, endpointHosts(item.GetProfile().GetEndpoints())...)
	}
	return hosts, nil
}

func updateProviderProfilesHosts(op, _ *structpb.Struct) ([]string, error) {
	var req openshellv1.UpdateProviderProfilesRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	return endpointHosts(req.GetProfile().GetProfile().GetEndpoints()), nil
}

// Approving a draft installs a stored rule the request does not carry, so the
// rule is resolved from the sandbox's draft policy in current_state, in
// GetDraftPolicyResponse shape. The gateway only reliably sends that state
// once it populates method-specific state; until then every approval is
// unresolved and the service decides per mode.
func approveDraftChunkHosts(op, state *structpb.Struct) ([]string, error) {
	var req openshellv1.ApproveDraftChunkRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	return draftHosts(state, []string{req.GetChunkId()}, true)
}

func approveAllDraftChunksHosts(op, state *structpb.Struct) ([]string, error) {
	var req openshellv1.ApproveAllDraftChunksRequest
	if err := decodeOperation(op, &req); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(req.GetApprovals()))
	for _, a := range req.GetApprovals() {
		ids = append(ids, a.GetChunkId())
	}
	return draftHosts(state, ids, req.GetIncludeSecurityFlagged())
}

// draftHosts lists the destinations the named stored chunks would install, the
// way the gateway installs them: pending chunks only, and security-flagged ones
// only when includeFlagged. Without ids every installable chunk counts. State
// without the draft policy's chunks, or a named chunk the state does not carry,
// cannot be vetted and is unresolved.
func draftHosts(state *structpb.Struct, ids []string, includeFlagged bool) ([]string, error) {
	if state == nil || state.GetFields()[draftChunksField] == nil {
		return nil, fmt.Errorf("%w: the state carries no draft chunks", errDraftUnresolved)
	}
	var draft openshellv1.GetDraftPolicyResponse
	if err := decodeState(state, &draft); err != nil {
		return nil, fmt.Errorf("%w: %w", errDraftUnresolved, err)
	}
	installable := func(c *openshellv1.PolicyChunk) bool {
		return c.GetStatus() == draftStatusPending && (includeFlagged || c.GetSecurityNotes() == "")
	}
	var hosts []string
	if len(ids) == 0 {
		for _, c := range draft.GetChunks() {
			if installable(c) {
				hosts = append(hosts, ruleHosts(c.GetProposedRule())...)
			}
		}
		return hosts, nil
	}
	byID := make(map[string]*openshellv1.PolicyChunk, len(draft.GetChunks()))
	for _, c := range draft.GetChunks() {
		byID[c.GetId()] = c
	}
	var missing []string
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			missing = append(missing, clip(id))
			continue
		}
		if installable(c) {
			hosts = append(hosts, ruleHosts(c.GetProposedRule())...)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: unknown chunk ids %s", errDraftUnresolved, capped(missing))
	}
	return hosts, nil
}

// capped joins caller-supplied identifiers for a diagnostic, showing at most
// maxReasonHosts of them.
func capped(items []string) string {
	shown := items
	if len(shown) > maxReasonHosts {
		shown = shown[:maxReasonHosts]
	}
	out := strings.Join(shown, ", ")
	if extra := len(items) - len(shown); extra > 0 {
		out += fmt.Sprintf(" (+%d more)", extra)
	}
	return out
}

func ruleHosts(rule *sandboxv1.NetworkPolicyRule) []string { return endpointHosts(rule.GetEndpoints()) }

// endpointHosts lists every destination a set of endpoints admits. An endpoint
// without a host admits whatever resolves into its allowed_ips, so those
// addresses stand in for the host and are vetted as IP destinations.
func endpointHosts(endpoints []*sandboxv1.NetworkEndpoint) []string {
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

// decodeOperation converts the gateway's protobuf-JSON operation into msg,
// ignoring fields this build of the contract does not know.
func decodeOperation(op *structpb.Struct, msg proto.Message) error {
	return decodeStruct(op, msg, "proposed_operation")
}

// decodeState does the same for the read-only state loaded for the evaluation.
func decodeState(state *structpb.Struct, msg proto.Message) error {
	return decodeStruct(state, msg, "current_state")
}

func decodeStruct(st *structpb.Struct, msg proto.Message, what string) error {
	if st == nil {
		return errors.New(what + " is required")
	}
	raw, err := protojson.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode %s: %w", what, err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, msg); err != nil {
		return fmt.Errorf("decode %s: %w", what, err)
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
