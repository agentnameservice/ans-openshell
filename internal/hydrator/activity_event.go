package hydrator

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

type activityGroup string

const (
	groupHTTPInitial activityGroup = "httpInitial"
	groupPostRewrite activityGroup = "postRewriteEvaluations"
	groupWebSocket   activityGroup = "websocketEvaluations" //nolint:gosec // Measurement name, not a credential.
	groupConnections activityGroup = "connections"
)

type policyDecision string

const (
	decisionAllowed policyDecision = "allowed"
	decisionDenied  policyDecision = "denied"
	decisionAudited policyDecision = "audited"
	decisionUnknown policyDecision = "unknown"
)

// These fields become grouping keys in local evidence. Bound each key as well
// as the number of keys retained by the aggregator.
const maxActivityFieldBytes = 1024

const (
	networkActivityOpen    = 1
	networkActivityFail    = 4
	networkActivityTraffic = 5
	policyActivityOther    = 99
	observedActionID       = 3
	middlewareTokenCount   = 2
	minimumL7Tokens        = 4
	minimumJSONRPCTokens   = 3
)

const (
	connectKeyword        = "CONNECT"
	connectL7Keyword      = "CONNECT_L7"
	jsonRPCRequestKeyword = "JSONRPC_L7_REQUEST"
	transparentTCPAllowed = "transparent_tcp_allowed"
)

type classifiedActivity struct {
	Group         activityGroup
	Decision      policyDecision
	Diagnostic    string
	Incomplete    bool
	Finding       *ActivityFinding
	AuditFallback bool
}

// activityRecord is a policy-relevant event with its unmapped fields decoded
// and its message split into tokens once.
type activityRecord struct {
	Event
	unmapped map[string]json.RawMessage
	tokens   []string
}

// activityRule classifies a record it recognizes and reports false otherwise.
type activityRule func(activityRecord) (classifiedActivity, bool)

func classifyActivity(ev Event) classifiedActivity {
	unmapped, valid := activityUnmapped(ev.Unmapped)
	if ev.ClassUID == ClassDetectionFinding {
		return classifyActivityFinding(ev, unmapped, valid)
	}
	if !valid {
		return classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}
	}
	record := activityRecord{Event: ev, unmapped: unmapped, tokens: strings.Fields(ev.Message)}
	result := classifyPolicyRecord(record)
	if result.Group == "" && !result.Incomplete && record.statesDecision() {
		return classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}
	}
	return result
}

// classifyPolicyRecord applies the first rule that recognizes the record.
// Record metadata comes first because OpenShell sets it on records that are not
// policy evaluations. Message families that never state a decision follow, then
// network records identified by activity, then decision messages, and finally
// connection decisions with a class-based fallback. classifyActivity rejects
// any uncounted result whose message states a decision, so rule order can make
// an agent incomplete but cannot hide a decision.
func classifyPolicyRecord(record activityRecord) classifiedActivity {
	rules := [...]activityRule{
		classifyCoverageMetadata,
		classifyStatusDetail,
		classifyHTTPMiddleware,
		classifyWebSocketMiddleware,
		classifyPassthroughHTTP,
		classifyWebSocketNotice,
		classifySession,
		classifyConnectionFailure,
		classifyDNSTraffic,
		classifyL7Decision,
	}
	for _, rule := range rules {
		if result, ok := rule(record); ok {
			return result
		}
	}
	return classifyConnectionActivity(record)
}

// statesDecision reports whether the message has the shape of an L7 or
// connection policy decision, judged by its leading tokens.
func (r activityRecord) statesDecision() bool {
	if _, isL7 := l7DecisionGroup(r.tokens); isL7 {
		return true
	}
	if connectDecision(r.tokens) != decisionUnknown {
		return true
	}
	return strings.HasPrefix(r.Message, "Transparent TCP denied") ||
		strings.HasPrefix(r.Message, "Transparent TCP ") && r.StatusDetail == transparentTCPAllowed
}

func (r activityRecord) withoutDecisionEnums() bool {
	return r.ActionID == 0 && r.DispositionID == 0
}

func (r activityRecord) deniedEnum() bool {
	return r.ActionID == deniedID || r.DispositionID == deniedID
}

func activityUnmapped(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false
	}
	return fields, true
}

func classifyCoverageMetadata(record activityRecord) (classifiedActivity, bool) {
	raw, present := record.unmapped["coverage_state"]
	if !present {
		return classifiedActivity{}, false
	}
	var state string
	if json.Unmarshal(raw, &state) != nil || state == "" {
		return classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}, true
	}
	return classifiedActivity{Diagnostic: "coverage"}, true
}

func classifyStatusDetail(record activityRecord) (classifiedActivity, bool) {
	switch record.StatusDetail {
	case "credential_endpoint_mismatch", "request_authority_mismatch":
		return classifiedActivity{Diagnostic: "unclassified_guard_denial", Incomplete: true}, true
	case "credential_unavailable", "assembly_capacity_exhausted", "policy_dns_trusted_gateway_unavailable":
		return classifiedActivity{Diagnostic: "operational_failure"}, true
	default:
		return classifiedActivity{}, false
	}
}

func classifyHTTPMiddleware(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassHTTPActivity || !strings.HasPrefix(record.Message, "MIDDLEWARE ") {
		return classifiedActivity{}, false
	}
	failed, valid := activityFailed(record.unmapped)
	if !valid {
		return classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}, true
	}
	if failed {
		return classifiedActivity{Diagnostic: "middleware_failure"}, true
	}
	decision := activityMessageValue(record.Message, "decision")
	if decision != "Allow" && decision != "Deny" {
		return classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}, true
	}
	if decision == "Deny" || record.deniedEnum() {
		return classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}, true
	}
	return classifiedActivity{Diagnostic: "middleware_stage"}, true
}

func classifyWebSocketMiddleware(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassNetworkActivity || !strings.HasPrefix(record.Message, "WEBSOCKET_MIDDLEWARE ") {
		return classifiedActivity{}, false
	}
	if len(record.tokens) < middlewareTokenCount {
		return classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}, true
	}
	switch record.tokens[1] {
	case "fail_open", "fail_closed":
		return classifiedActivity{Diagnostic: "middleware_failure"}, true
	case "deny":
		return classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}, true
	case "inspect", "voluntary_skip", "allow":
		if record.deniedEnum() {
			return classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}, true
		}
		return classifiedActivity{Diagnostic: "middleware_stage"}, true
	default:
		return classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}, true
	}
}

func classifyPassthroughHTTP(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassHTTPActivity || !strings.HasPrefix(record.Message, "HTTP_REQUEST ") {
		return classifiedActivity{}, false
	}
	if record.deniedEnum() {
		return unknownActivity(groupHTTPInitial), true
	}
	return classifiedActivity{Diagnostic: "passthrough_http"}, true
}

func classifyWebSocketNotice(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassNetworkActivity {
		return classifiedActivity{}, false
	}
	switch {
	case strings.HasPrefix(record.Message, "WEBSOCKET_MIDDLEWARE_COVERAGE "):
		return classifiedActivity{Diagnostic: "coverage"}, true
	case strings.HasPrefix(record.Message, "WEBSOCKET_CREDENTIAL_REWRITE "):
		return classifiedActivity{Diagnostic: "operational_failure"}, true
	default:
		return classifiedActivity{}, false
	}
}

func classifySession(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassNetworkActivity || record.ActivityID != networkActivityOpen || !record.withoutDecisionEnums() {
		return classifiedActivity{}, false
	}
	message := strings.ToLower(record.Message)
	if message == "supervisor session established" || strings.HasPrefix(message, "supervisor session established (") {
		return classifiedActivity{Diagnostic: "session"}, true
	}
	return classifiedActivity{}, false
}

func classifyConnectionFailure(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassNetworkActivity || record.ActivityID != networkActivityFail || !record.withoutDecisionEnums() {
		return classifiedActivity{}, false
	}
	return classifiedActivity{Diagnostic: "connection_failure"}, true
}

func classifyDNSTraffic(record activityRecord) (classifiedActivity, bool) {
	if record.ClassUID != ClassNetworkActivity || record.ActivityID != networkActivityTraffic {
		return classifiedActivity{}, false
	}
	if record.StatusDetail == "policy_dns_ineligible" && strings.HasPrefix(record.Message, "Policy DNS refused ") &&
		record.deniedEnum() && decisionEnumsMatch(record.Event, decisionDenied) {
		return classifiedActivity{Diagnostic: activityDNSRefused}, true
	}
	return classifiedActivity{Diagnostic: "unknown_dns_decision", Incomplete: true}, true
}

func activityFailed(unmapped map[string]json.RawMessage) (bool, bool) {
	raw, present := unmapped["failed"]
	if !present {
		return false, true
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return true, true
	}
	return false, bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}

func activityMessageValue(message, key string) string {
	var value string
	for _, field := range strings.Fields(message) {
		name, candidate, ok := strings.Cut(field, "=")
		if ok && name == key {
			if value != "" || candidate == "" {
				return ""
			}
			value = candidate
		}
	}
	return value
}

// l7DecisionGroup reports the measurement group of a known L7 policy-decision
// message, judged by its first token only.
func l7DecisionGroup(tokens []string) (activityGroup, bool) {
	if len(tokens) == 0 {
		return "", false
	}
	switch tokens[0] {
	case "L7_REQUEST", "GRAPHQL_L7_REQUEST", jsonRPCRequestKeyword:
		return groupHTTPInitial, true
	case "L7_REQUEST_TRANSFORMED":
		return groupPostRewrite, true
	case "WEBSOCKET_L7_REQUEST":
		return groupWebSocket, true
	default:
		return "", false
	}
}

func classifyL7Decision(record activityRecord) (classifiedActivity, bool) {
	group, ok := l7DecisionGroup(record.tokens)
	if !ok {
		return classifiedActivity{}, false
	}
	class := ClassHTTPActivity
	if group == groupWebSocket {
		class = ClassNetworkActivity
	}
	parts := record.tokens
	if record.ClassUID != class || record.ActivityID != policyActivityOther || len(parts) < minimumJSONRPCTokens {
		return unknownActivity(group), true
	}
	token := parts[1]
	if parts[0] == jsonRPCRequestKeyword {
		if !strings.HasPrefix(token, "decision=") || activityMessageValue(record.Message, "http_method") == "" || activityMessageValue(record.Message, "endpoint") == "" {
			return unknownActivity(group), true
		}
		token = strings.TrimPrefix(token, "decision=")
	} else if len(parts) < minimumL7Tokens {
		return unknownActivity(group), true
	}
	decision := activityDecision(token)
	if decision == decisionUnknown || !decisionEnumsMatch(record.Event, decision) {
		return unknownActivity(group), true
	}
	return classifiedActivity{Group: group, Decision: decision, AuditFallback: decision == decisionAudited}, true
}

func activityDecision(token string) policyDecision {
	switch token {
	case "allow":
		return decisionAllowed
	case "deny":
		return decisionDenied
	case "audit":
		return decisionAudited
	default:
		return decisionUnknown
	}
}

func decisionEnumsMatch(ev Event, decision policyDecision) bool {
	if decision == decisionAudited {
		return (ev.ActionID == 0 || ev.ActionID == 1 || ev.ActionID == observedActionID) && (ev.DispositionID == 0 || ev.DispositionID == 1)
	}
	id := 1
	if decision == decisionDenied {
		id = deniedID
	}
	return (ev.ActionID == 0 || ev.ActionID == id) && (ev.DispositionID == 0 || ev.DispositionID == id)
}

// classifyConnectionActivity is the last rule: it counts connection decisions
// and gives every other record a class-based fallback.
func classifyConnectionActivity(record activityRecord) classifiedActivity {
	if record.ClassUID == ClassHTTPActivity {
		return unknownActivity(groupHTTPInitial)
	}
	if record.ClassUID != ClassNetworkActivity {
		return classifiedActivity{Diagnostic: "other"}
	}
	if record.ActivityID == policyActivityOther {
		return unknownActivity(groupWebSocket)
	}
	if record.ActivityID != networkActivityOpen {
		if record.withoutDecisionEnums() {
			return classifiedActivity{Diagnostic: "network_no_policy_decision"}
		}
		return unknownActivity(groupConnections)
	}
	decision := decisionUnknown
	if len(record.tokens) >= minimumJSONRPCTokens {
		decision = connectDecision(record.tokens)
	}
	if decision == decisionUnknown && strings.HasPrefix(record.Message, "Transparent TCP ") {
		decision = transparentPolicyDecision(record.Event)
	}
	if decision != decisionUnknown && decisionEnumsMatch(record.Event, decision) {
		return classifiedActivity{Group: groupConnections, Decision: decision}
	}
	if record.withoutDecisionEnums() && !strings.HasPrefix(record.Message, connectKeyword) && !strings.HasPrefix(record.Message, "Transparent TCP ") {
		return classifiedActivity{Diagnostic: "network_no_policy_decision"}
	}
	return unknownActivity(groupConnections)
}

// connectDecision returns the decision stated by a CONNECT or CONNECT_L7
// message, or decisionUnknown for any other message.
func connectDecision(tokens []string) policyDecision {
	if len(tokens) < 2 || (tokens[0] != connectKeyword && tokens[0] != connectL7Keyword) {
		return decisionUnknown
	}
	if decision := policyDecision(tokens[1]); decision == decisionAllowed || decision == decisionDenied {
		return decision
	}
	return decisionUnknown
}

func transparentPolicyDecision(ev Event) policyDecision {
	if ev.StatusDetail == transparentTCPAllowed && !strings.HasPrefix(ev.Message, "Transparent TCP denied") {
		return decisionAllowed
	}
	if strings.HasPrefix(ev.Message, "Transparent TCP denied") {
		switch ev.StatusDetail {
		case "transparent_tcp_policy_denied", "transparent_tcp_identity_denied", "transparent_tcp_destination_denied":
			return decisionDenied
		}
	}
	return decisionUnknown
}

func unknownActivity(group activityGroup) classifiedActivity {
	return classifiedActivity{Group: group, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}
}

func classifyActivityFinding(ev Event, unmapped map[string]json.RawMessage, valid bool) classifiedActivity {
	finding := ActivityFinding{Origin: "unclassified", Type: "unknown", Severity: ev.SeverityID, Records: 1, Occurrences: 1}
	var info struct {
		UID string `json:"uid"`
	}
	diagnostic := ""
	validInfo := len(ev.FindingInfo) == 0 || json.Unmarshal(ev.FindingInfo, &info) == nil
	if !valid || !validInfo {
		diagnostic = "invalid_finding_metadata"
	} else if info.UID == "" {
		diagnostic = "finding_type_unknown"
	}
	if info.UID != "" {
		finding.Type = info.UID
	}
	if raw, present := unmapped["middleware"]; present {
		if json.Unmarshal(raw, &finding.Middleware) != nil || finding.Middleware == "" {
			finding.Middleware = ""
			diagnostic = "invalid_finding_metadata"
		}
	}
	if raw, present := unmapped["count"]; present {
		finding.Occurrences = 0
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &finding.Occurrences) != nil || finding.Occurrences < 0 {
			finding.Occurrences = 0
			finding.InvalidCounts = 1
			diagnostic = "invalid_finding_count"
		}
		if finding.Middleware != "" {
			finding.Origin = "plugin"
		}
	}
	if finding.Origin != "plugin" {
		finding.Origin = nativeFindingOrigin(finding.Type, unmapped)
	}
	if len(finding.Type) > maxActivityFieldBytes || len(finding.Middleware) > maxActivityFieldBytes {
		finding.Type = boundActivityField(finding.Type)
		finding.Middleware = boundActivityField(finding.Middleware)
		diagnostic = "finding_metadata_truncated"
	}
	return classifiedActivity{Finding: &finding, Diagnostic: diagnostic}
}

func nativeFindingOrigin(kind string, unmapped map[string]json.RawMessage) string {
	if _, present := unmapped["coverage_state"]; present {
		return "coverage"
	}
	switch kind {
	case "openshell.middleware.body_unavailable", "openshell.middleware.traffic_uninspectable":
		return "coverage"
	case "openshell.middleware.admission_saturated", "openshell.middleware.admission_exhausted", "openshell.middleware.session_capacity_exhausted",
		"openshell.middleware.websocket_failure", "openshell.middleware.websocket_stage_disabled", "openshell.middleware.failure", "openshell.middleware.policy_evaluation_failure":
		return "operational"
	default:
		return "unclassified"
	}
}

func boundActivityField(value string) string {
	if len(value) <= maxActivityFieldBytes {
		return value
	}
	value = value[:maxActivityFieldBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
