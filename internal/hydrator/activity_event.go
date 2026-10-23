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

type classifiedActivity struct {
	Group         activityGroup
	Decision      policyDecision
	Diagnostic    string
	Incomplete    bool
	Finding       *ActivityFinding
	AuditFallback bool
}

func classifyActivity(ev Event) classifiedActivity {
	unmapped, valid := activityUnmapped(ev.Unmapped)
	if ev.ClassUID == ClassDetectionFinding {
		return classifyActivityFinding(ev, unmapped, valid)
	}
	if !valid {
		return classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}
	}
	if raw, present := unmapped["coverage_state"]; present {
		var state string
		if json.Unmarshal(raw, &state) != nil || state == "" {
			return classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}
		}
		return classifiedActivity{Diagnostic: "coverage"}
	}
	if result, ok := classifyActivityDiagnostic(ev, unmapped); ok {
		return result
	}
	if result, ok := classifyL7Activity(ev); ok {
		return result
	}
	return classifyConnectionActivity(ev)
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

func classifyActivityDiagnostic(ev Event, unmapped map[string]json.RawMessage) (classifiedActivity, bool) {
	switch ev.StatusDetail {
	case "credential_endpoint_mismatch", "request_authority_mismatch":
		return classifiedActivity{Diagnostic: "unclassified_guard_denial", Incomplete: true}, true
	case "credential_unavailable", "assembly_capacity_exhausted", "policy_dns_trusted_gateway_unavailable":
		return classifiedActivity{Diagnostic: "operational_failure"}, true
	}
	if result, ok := classifyMiddlewareActivity(ev, unmapped); ok {
		return result, true
	}
	if ev.ClassUID == ClassHTTPActivity && strings.HasPrefix(ev.Message, "HTTP_REQUEST ") {
		if ev.ActionID == deniedID || ev.DispositionID == deniedID {
			return unknownActivity(groupHTTPInitial), true
		}
		return classifiedActivity{Diagnostic: "passthrough_http"}, true
	}
	if ev.ClassUID != ClassNetworkActivity {
		return classifiedActivity{}, false
	}
	return classifyNetworkDiagnostic(ev)
}

func classifyNetworkDiagnostic(ev Event) (classifiedActivity, bool) {
	if strings.HasPrefix(ev.Message, "WEBSOCKET_MIDDLEWARE_COVERAGE ") {
		return classifiedActivity{Diagnostic: "coverage"}, true
	}
	if strings.HasPrefix(ev.Message, "WEBSOCKET_CREDENTIAL_REWRITE ") {
		return classifiedActivity{Diagnostic: "operational_failure"}, true
	}
	if ev.ActivityID == networkActivityOpen && ev.ActionID == 0 && ev.DispositionID == 0 {
		message := strings.ToLower(ev.Message)
		if message == "supervisor session established" || strings.HasPrefix(message, "supervisor session established (") {
			return classifiedActivity{Diagnostic: "session"}, true
		}
	}
	if ev.ActivityID == networkActivityFail && ev.ActionID == 0 && ev.DispositionID == 0 {
		return classifiedActivity{Diagnostic: "connection_failure"}, true
	}
	if ev.ActivityID == networkActivityTraffic {
		if ev.StatusDetail == "policy_dns_ineligible" && strings.HasPrefix(ev.Message, "Policy DNS refused ") &&
			(ev.ActionID == deniedID || ev.DispositionID == deniedID) && decisionEnumsMatch(ev, decisionDenied) {
			return classifiedActivity{Diagnostic: "dns_refused"}, true
		}
		return classifiedActivity{Diagnostic: "unknown_dns_decision", Incomplete: true}, true
	}
	return classifiedActivity{}, false
}

func classifyMiddlewareActivity(ev Event, unmapped map[string]json.RawMessage) (classifiedActivity, bool) {
	if ev.ClassUID == ClassHTTPActivity && strings.HasPrefix(ev.Message, "MIDDLEWARE ") {
		failed, valid := activityFailed(unmapped)
		if !valid {
			return classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}, true
		}
		if failed {
			return classifiedActivity{Diagnostic: "middleware_failure"}, true
		}
		decision := activityMessageValue(ev.Message, "decision")
		if decision != "Allow" && decision != "Deny" {
			return classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}, true
		}
		if decision == "Deny" || ev.ActionID == deniedID || ev.DispositionID == deniedID {
			return classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}, true
		}
		return classifiedActivity{Diagnostic: "middleware_stage"}, true
	}
	if ev.ClassUID != ClassNetworkActivity || !strings.HasPrefix(ev.Message, "WEBSOCKET_MIDDLEWARE ") {
		return classifiedActivity{}, false
	}
	parts := strings.Fields(ev.Message)
	if len(parts) < middlewareTokenCount {
		return classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}, true
	}
	switch parts[1] {
	case "fail_open", "fail_closed":
		return classifiedActivity{Diagnostic: "middleware_failure"}, true
	case "deny":
		return classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}, true
	case "inspect", "voluntary_skip", "allow":
		if ev.ActionID == deniedID || ev.DispositionID == deniedID {
			return classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}, true
		}
		return classifiedActivity{Diagnostic: "middleware_stage"}, true
	default:
		return classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}, true
	}
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

func classifyL7Activity(ev Event) (classifiedActivity, bool) {
	parts := strings.Fields(ev.Message)
	if len(parts) == 0 {
		return classifiedActivity{}, false
	}
	group, class := groupHTTPInitial, ClassHTTPActivity
	switch parts[0] {
	case "L7_REQUEST", "GRAPHQL_L7_REQUEST", "JSONRPC_L7_REQUEST":
	case "L7_REQUEST_TRANSFORMED":
		group = groupPostRewrite
	case "WEBSOCKET_L7_REQUEST":
		group, class = groupWebSocket, ClassNetworkActivity
	default:
		return classifiedActivity{}, false
	}
	if ev.ClassUID != class || ev.ActivityID != policyActivityOther || len(parts) < minimumJSONRPCTokens {
		return unknownActivity(group), true
	}
	token := parts[1]
	if parts[0] == "JSONRPC_L7_REQUEST" {
		if !strings.HasPrefix(token, "decision=") || activityMessageValue(ev.Message, "http_method") == "" || activityMessageValue(ev.Message, "endpoint") == "" {
			return unknownActivity(group), true
		}
		token = strings.TrimPrefix(token, "decision=")
	} else if len(parts) < minimumL7Tokens {
		return unknownActivity(group), true
	}
	decision := activityDecision(token)
	if decision == decisionUnknown || !decisionEnumsMatch(ev, decision) {
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

func classifyConnectionActivity(ev Event) classifiedActivity {
	if ev.ClassUID == ClassHTTPActivity {
		return unknownActivity(groupHTTPInitial)
	}
	if ev.ClassUID != ClassNetworkActivity {
		return classifiedActivity{Diagnostic: "other"}
	}
	if ev.ActivityID == policyActivityOther {
		return unknownActivity(groupWebSocket)
	}
	if ev.ActivityID != networkActivityOpen {
		if ev.ActionID == 0 && ev.DispositionID == 0 {
			return classifiedActivity{Diagnostic: "network_no_policy_decision"}
		}
		return unknownActivity(groupConnections)
	}
	parts := strings.Fields(ev.Message)
	decision := decisionUnknown
	if len(parts) >= minimumJSONRPCTokens && (parts[0] == "CONNECT" || parts[0] == "CONNECT_L7") {
		switch parts[1] {
		case "allowed":
			decision = decisionAllowed
		case "denied":
			decision = decisionDenied
		}
	} else if strings.HasPrefix(ev.Message, "Transparent TCP ") {
		decision = transparentPolicyDecision(ev)
	}
	if decision != decisionUnknown && decisionEnumsMatch(ev, decision) {
		return classifiedActivity{Group: groupConnections, Decision: decision}
	}
	if ev.ActionID == 0 && ev.DispositionID == 0 && !strings.HasPrefix(ev.Message, "CONNECT") && !strings.HasPrefix(ev.Message, "Transparent TCP ") {
		return classifiedActivity{Diagnostic: "network_no_policy_decision"}
	}
	return unknownActivity(groupConnections)
}

func transparentPolicyDecision(ev Event) policyDecision {
	if ev.StatusDetail == "transparent_tcp_allowed" && !strings.HasPrefix(ev.Message, "Transparent TCP denied") {
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
