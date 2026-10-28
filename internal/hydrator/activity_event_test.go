package hydrator

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClassifyActivityDecisions(t *testing.T) {
	t.Parallel()
	formats := []struct {
		name, format string
		class        int
		group        activityGroup
	}{
		{"rest", "L7_REQUEST %s POST example.com:443/test reason=rule", ClassHTTPActivity, groupHTTPInitial},
		{"graphql", "GRAPHQL_L7_REQUEST %s POST example.com:443/graphql reason=rule", ClassHTTPActivity, groupHTTPInitial},
		{"jsonrpc", "JSONRPC_L7_REQUEST decision=%s rule_methods=tools/call tools=test http_method=POST endpoint=/mcp policy_version=1 reason=rule", ClassHTTPActivity, groupHTTPInitial},
		{"transformed", "L7_REQUEST_TRANSFORMED %s POST example.com:443/mcp reason=rule", ClassHTTPActivity, groupPostRewrite},
		{"websocket", "WEBSOCKET_L7_REQUEST %s WEBSOCKET_TEXT example.com:443/ws reason=rule", ClassNetworkActivity, groupWebSocket},
	}
	decisions := []struct {
		token    string
		decision policyDecision
		id       int
	}{
		{"allow", decisionAllowed, 1},
		{"deny", decisionDenied, 2},
		{"audit", decisionAudited, 1},
	}
	for _, format := range formats {
		for _, decision := range decisions {
			for _, version := range []string{"0.1.5", "0.1.6-pre.3"} {
				t.Run(format.name+"/"+decision.token+"/"+version, func(t *testing.T) {
					t.Parallel()
					ev := Event{ClassUID: format.class, ActivityID: 99, ActionID: decision.id, DispositionID: decision.id,
						StatusID: 1, Message: fmt.Sprintf(format.format, decision.token), Metadata: Metadata{Product: Product{Version: version}}}
					got := classifyActivity(ev)
					want := classifiedActivity{Group: format.group, Decision: decision.decision, AuditFallback: decision.token == "audit"}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("classifyActivity() = %+v, want %+v", got, want)
					}
				})
			}
		}
	}
}

func TestClassifyActivityMalformedDecisions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                          string
		message                       string
		class                         int
		activity, action, disposition int
		wantGroup                     activityGroup
	}{
		{"unknown token", "L7_REQUEST permit POST example.com:443/test", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"past tense token is not L7 grammar", "L7_REQUEST allowed POST example.com:443/test", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"missing token", "L7_REQUEST", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"missing request", "L7_REQUEST allow", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"incorrect jsonrpc grammar", "JSONRPC_L7_REQUEST audit POST example.com", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"missing jsonrpc method", "JSONRPC_L7_REQUEST decision=allow endpoint=/mcp", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"missing jsonrpc endpoint", "JSONRPC_L7_REQUEST decision=allow http_method=POST", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"allow with denied action", "L7_REQUEST allow POST example.com:443/test", ClassHTTPActivity, 99, 2, 1, groupHTTPInitial},
		{"deny with allowed disposition", "L7_REQUEST deny POST example.com:443/test", ClassHTTPActivity, 99, 2, 1, groupHTTPInitial},
		{"audit with denied action", "L7_REQUEST audit POST example.com:443/test", ClassHTTPActivity, 99, 2, 2, groupHTTPInitial},
		{"unknown action enum", "L7_REQUEST allow POST example.com:443/test", ClassHTTPActivity, 99, 99, 1, groupHTTPInitial},
		{"unknown disposition enum", "L7_REQUEST allow POST example.com:443/test", ClassHTTPActivity, 99, 1, 99, groupHTTPInitial},
		{"quarantine is not observed", "L7_REQUEST audit POST example.com:443/test", ClassHTTPActivity, 99, 3, 3, groupHTTPInitial},
		{"wrong class", "WEBSOCKET_L7_REQUEST audit WEBSOCKET_TEXT example.com:443/ws", ClassHTTPActivity, 99, 1, 1, groupWebSocket},
		{"wrong activity", "L7_REQUEST allow POST example.com:443/test", ClassHTTPActivity, 1, 1, 1, groupHTTPInitial},
		{"future http format", "FUTURE_L7_FORMAT permitted=true", ClassHTTPActivity, 99, 1, 1, groupHTTPInitial},
		{"future websocket format", "FUTURE_WEBSOCKET permitted=true", ClassNetworkActivity, 99, 1, 1, groupWebSocket},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := Event{ClassUID: tt.class, ActivityID: tt.activity, ActionID: tt.action, DispositionID: tt.disposition, Message: tt.message}
			got := classifyActivity(ev)
			if got.Group != tt.wantGroup || got.Decision != decisionUnknown || !got.Incomplete || got.Diagnostic != "unknown_policy_decision" {
				t.Fatalf("classifyActivity() = %+v", got)
			}
		})
	}
}

func TestClassifyActivitySpecialEnums(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ev       Event
		want     policyDecision
		fallback bool
	}{
		{"absent enum fields", Event{ClassUID: ClassHTTPActivity, ActivityID: 99, Message: "L7_REQUEST allow GET example.com:443/test"}, decisionAllowed, false},
		{"observed audit action", Event{ClassUID: ClassHTTPActivity, ActivityID: 99, ActionID: 3, DispositionID: 1, Message: "L7_REQUEST audit GET example.com:443/test"}, decisionAudited, true},
		{"failed status does not reverse explicit allow", Event{ClassUID: ClassHTTPActivity, ActivityID: 99, ActionID: 1, DispositionID: 1, StatusID: 2, Message: "L7_REQUEST allow GET example.com:443/test"}, decisionAllowed, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifyActivity(tt.ev)
			if got.Decision != tt.want || got.Incomplete || got.AuditFallback != tt.fallback {
				t.Fatalf("classifyActivity() = %+v", got)
			}
		})
	}
}

func TestClassifyActivityRouting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   Event
		want classifiedActivity
	}{
		{"connect allow", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Message: "CONNECT allowed example.com:443"}, classifiedActivity{Group: groupConnections, Decision: decisionAllowed}},
		{"connect L7 allow", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Message: "CONNECT_L7 allowed example.com:443"}, classifiedActivity{Group: groupConnections, Decision: decisionAllowed}},
		{"connect allowed transport failed", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, StatusID: 2, Message: "CONNECT allowed example.com:443"}, classifiedActivity{Group: groupConnections, Decision: decisionAllowed}},
		{"connect denied", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "CONNECT denied example.com:443"}, classifiedActivity{Group: groupConnections, Decision: decisionDenied}},
		{"transparent policy denial", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "Transparent TCP denied before relay: outside policy", StatusDetail: "transparent_tcp_policy_denied"}, classifiedActivity{Group: groupConnections, Decision: decisionDenied}},
		{"transparent OPA identity denial", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "Transparent TCP denied example.com:443", StatusDetail: "transparent_tcp_identity_denied"}, classifiedActivity{Group: groupConnections, Decision: decisionDenied}},
		{"transparent destination denial", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "Transparent TCP denied example.com:443", StatusDetail: "transparent_tcp_destination_denied"}, classifiedActivity{Group: groupConnections, Decision: decisionDenied}},
		{"transparent allowed", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Message: "Transparent TCP mapping_id=placeholder synthetic=example real=example", StatusDetail: "transparent_tcp_allowed"}, classifiedActivity{Group: groupConnections, Decision: decisionAllowed}},
		{"DNS refusal is not another TCP check", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, Message: "Policy DNS refused a name that is not eligible in the active policy", StatusDetail: "policy_dns_ineligible"}, classifiedActivity{Diagnostic: "dns_refused"}},
		{"unknown DNS event is incomplete", Event{ClassUID: 4001, ActivityID: 5, ActionID: 1, DispositionID: 1, Message: "DNS lookup"}, classifiedActivity{Diagnostic: "unknown_dns_decision", Incomplete: true}},
		{"missing DNS decision", Event{ClassUID: 4001, ActivityID: 5, Message: "Policy DNS refused a name that is not eligible in the active policy", StatusDetail: "policy_dns_ineligible"}, classifiedActivity{Diagnostic: "unknown_dns_decision", Incomplete: true}},
		{"DNS gateway unavailable", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, Message: "Policy DNS refused a reserved host-gateway alias because no trusted gateway is configured", StatusDetail: "policy_dns_trusted_gateway_unavailable"}, classifiedActivity{Diagnostic: "operational_failure"}},
		{"DNS upstream failure", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, StatusID: 2, Message: "Policy DNS trusted resolver query failed", StatusDetail: "policy_dns_upstream_nxdomain"}, classifiedActivity{Diagnostic: "dns_failure"}},
		{"DNS no valid address", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, StatusID: 2, Message: "Policy DNS rejected every trusted resolver address", StatusDetail: "policy_dns_no_valid_address"}, classifiedActivity{Diagnostic: "dns_failure"}},
		{"DNS publication failure", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, StatusID: 2, Message: "Policy DNS resolved-endpoint mapping publication failed", StatusDetail: "policy_dns_publication_pool_exhausted"}, classifiedActivity{Diagnostic: "dns_failure"}},
		{"DNS observation budget", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, StatusID: 2, Message: "Policy DNS resolved-endpoint mapping publication failed", StatusDetail: "policy_dns_observation_budget_exhausted"}, classifiedActivity{Diagnostic: "dns_failure"}},
		{"DNS failure detail without policy DNS message", Event{ClassUID: 4001, ActivityID: 5, ActionID: 2, DispositionID: 2, StatusID: 2, Message: "resolver query failed", StatusDetail: "policy_dns_upstream_timeout"}, classifiedActivity{Diagnostic: "unknown_dns_decision", Incomplete: true}},
		{"proxy connection failure", Event{ClassUID: 4001, ActivityID: 4, StatusID: 2, Message: "Proxy connection error: connection refused"}, classifiedActivity{Diagnostic: "connection_failure"}},
		{"transparent connection failure", Event{ClassUID: 4001, ActivityID: 4, StatusID: 2, Message: "Transparent TCP connection error: timeout"}, classifiedActivity{Diagnostic: "connection_failure"}},
		{"network failure without message", Event{ClassUID: 4001, ActivityID: 4, StatusID: 2}, classifiedActivity{Diagnostic: "connection_failure"}},
		{"supervisor session", Event{ClassUID: 4001, ActivityID: 1, StatusID: 1, Message: "Supervisor session established"}, classifiedActivity{Diagnostic: "session"}},
		{"real supervisor session", Event{ClassUID: 4001, ActivityID: 1, StatusID: 1, Message: "supervisor session established (session_id=placeholder, heartbeat_secs=15)"}, classifiedActivity{Diagnostic: "session"}},
		{"non-policy network record", Event{ClassUID: 4001, ActivityID: 1, StatusID: 1, Message: "control plane event"}, classifiedActivity{Diagnostic: "network_no_policy_decision"}},
		{"other network lifecycle record", Event{ClassUID: 4001, ActivityID: 3, StatusID: 1, Message: "connection lifecycle"}, classifiedActivity{Diagnostic: "network_no_policy_decision"}},
		{"unknown failed policy record", Event{ClassUID: 4001, ActivityID: 4, ActionID: 2, Message: "Future failed policy decision"}, classifiedActivity{Group: groupConnections, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"unknown denied network record", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "Future guard denied"}, classifiedActivity{Group: groupConnections, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"unknown allowed network record", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Message: "Future connection allowed"}, classifiedActivity{Group: groupConnections, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"connection enum contradiction", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 1, Message: "CONNECT allowed example.com:443"}, classifiedActivity{Group: groupConnections, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"missing CONNECT endpoint", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Message: "CONNECT allowed"}, classifiedActivity{Group: groupConnections, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"unsupported transparent guard", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "Transparent TCP denied: stale mapping", StatusDetail: "transparent_tcp_mapping_expired"}, classifiedActivity{Group: groupConnections, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"wrong CONNECT class", Event{ClassUID: 4002, ActivityID: 1, ActionID: 1, DispositionID: 1, Message: "CONNECT allowed example.com:443"}, classifiedActivity{Group: groupHTTPInitial, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"authority guard", Event{ClassUID: 4002, ActivityID: 3, ActionID: 2, DispositionID: 2, StatusDetail: "request_authority_mismatch"}, classifiedActivity{Diagnostic: "unclassified_guard_denial", Incomplete: true}},
		{"credential guard", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, StatusDetail: "credential_endpoint_mismatch"}, classifiedActivity{Diagnostic: "unclassified_guard_denial", Incomplete: true}},
		{"credential unavailable", Event{ClassUID: 4002, ActivityID: 3, ActionID: 2, DispositionID: 2, StatusDetail: "credential_unavailable"}, classifiedActivity{Diagnostic: "operational_failure"}},
		{"websocket capacity", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, StatusDetail: "assembly_capacity_exhausted"}, classifiedActivity{Diagnostic: "operational_failure"}},
		{"passthrough HTTP", Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Message: "HTTP_REQUEST GET example.com:443/ credentials_injected=false request_num=1"}, classifiedActivity{Diagnostic: "passthrough_http"}},
		{"passthrough denial cannot hide", Event{ClassUID: 4002, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "HTTP_REQUEST GET example.com:443/ credentials_injected=false request_num=1"}, classifiedActivity{Group: groupHTTPInitial, Decision: decisionUnknown, Diagnostic: "unknown_policy_decision", Incomplete: true}},
		{"websocket coverage", Event{ClassUID: 4001, ActivityID: 99, ActionID: 1, DispositionID: 1, Message: "WEBSOCKET_MIDDLEWARE_COVERAGE state=binding_not_selected"}, classifiedActivity{Diagnostic: "coverage"}},
		{"coverage metadata before class routing", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Unmapped: json.RawMessage(`{"coverage_state":"binding_not_selected"}`)}, classifiedActivity{Diagnostic: "coverage"}},
		{"invalid coverage metadata", Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Unmapped: json.RawMessage(`{"coverage_state":[]}`)}, classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}},
		{"coverage metadata on a denied decision", Event{ClassUID: 4002, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "L7_REQUEST deny POST example.com:443/upload reason=rule", Unmapped: json.RawMessage(`{"coverage_state":"binding_not_selected"}`)}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"operational status on a websocket decision", Event{ClassUID: 4001, ActivityID: 99, ActionID: 2, DispositionID: 2, StatusDetail: "assembly_capacity_exhausted", Message: "WEBSOCKET_L7_REQUEST deny WEBSOCKET_TEXT example.com:443/ws reason=rule"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"operational status on a rewrite decision", Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, StatusDetail: "credential_unavailable", Message: "L7_REQUEST_TRANSFORMED allow POST example.com:443/mcp reason=rule"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"coverage metadata on a connection denial", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "CONNECT denied example.com:443 reason=rule", Unmapped: json.RawMessage(`{"coverage_state":"binding_not_selected"}`)}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"operational status on a transparent denial", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, StatusDetail: "assembly_capacity_exhausted", Message: "Transparent TCP denied example.com:443"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"connection failure carrying a websocket denial", Event{ClassUID: 4001, ActivityID: 4, Message: "WEBSOCKET_L7_REQUEST deny WEBSOCKET_TEXT example.com:443/ws reason=rule"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"connection failure carrying a connect decision", Event{ClassUID: 4001, ActivityID: 4, Message: "CONNECT allowed example.com:443"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"middleware allow", Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Message: "MIDDLEWARE content remote decision=Allow", Unmapped: json.RawMessage(`{"failed":false}`)}, classifiedActivity{Diagnostic: "middleware_stage"}},
		{"middleware denied", Event{ClassUID: 4002, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "MIDDLEWARE content remote decision=Deny", Unmapped: json.RawMessage(`{"failed":false}`)}, classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}},
		{"middleware failed closed", Event{ClassUID: 4002, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "MIDDLEWARE content remote decision=Deny", Unmapped: json.RawMessage(`{"failed":true}`)}, classifiedActivity{Diagnostic: "middleware_failure"}},
		{"middleware failure metadata malformed", Event{ClassUID: 4002, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "MIDDLEWARE content remote decision=Deny", Unmapped: json.RawMessage(`{"failed":"true"}`)}, classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}},
		{"middleware unknown decision", Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Message: "MIDDLEWARE content remote decision=Observe"}, classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}},
		{"middleware duplicate decision", Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Message: "MIDDLEWARE content remote decision=Allow decision=Deny"}, classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}},
		{"middleware empty duplicate decision", Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Message: "MIDDLEWARE content remote decision= decision=Allow"}, classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}},
		{"websocket middleware deny", Event{ClassUID: 4001, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "WEBSOCKET_MIDDLEWARE deny config=guard implementation=remote"}, classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}},
		{"websocket middleware failed closed", Event{ClassUID: 4001, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "WEBSOCKET_MIDDLEWARE fail_closed config=guard implementation=remote"}, classifiedActivity{Diagnostic: "middleware_failure"}},
		{"websocket middleware failed open", Event{ClassUID: 4001, ActivityID: 99, ActionID: 99, DispositionID: 1, StatusID: 2, Message: "WEBSOCKET_MIDDLEWARE fail_open config=guard implementation=remote"}, classifiedActivity{Diagnostic: "middleware_failure"}},
		{"websocket middleware inspect", Event{ClassUID: 4001, ActivityID: 99, ActionID: 99, DispositionID: 1, Message: "WEBSOCKET_MIDDLEWARE inspect config=guard implementation=remote"}, classifiedActivity{Diagnostic: "middleware_stage"}},
		{"websocket middleware empty", Event{ClassUID: 4001, ActivityID: 99, ActionID: 1, Message: "WEBSOCKET_MIDDLEWARE "}, classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}},
		{"websocket middleware unknown", Event{ClassUID: 4001, ActivityID: 99, ActionID: 1, Message: "WEBSOCKET_MIDDLEWARE observe config=guard"}, classifiedActivity{Diagnostic: "unknown_middleware_decision", Incomplete: true}},
		{"websocket middleware contradictory allow", Event{ClassUID: 4001, ActivityID: 99, ActionID: 2, DispositionID: 2, Message: "WEBSOCKET_MIDDLEWARE allow config=guard"}, classifiedActivity{Diagnostic: "unclassified_middleware_denial", Incomplete: true}},
		{"websocket rewrite failure", Event{ClassUID: 4001, ActivityID: 1, ActionID: 2, DispositionID: 2, Message: "WEBSOCKET_CREDENTIAL_REWRITE closed ambiguous client frame [host:example.com port:443]"}, classifiedActivity{Diagnostic: "operational_failure"}},
		{"non-object unmapped metadata", Event{ClassUID: 4002, ActivityID: 99, Message: "L7_REQUEST allow GET example.com:443/test", Unmapped: json.RawMessage(`[]`)}, classifiedActivity{Diagnostic: "invalid_metadata", Incomplete: true}},
		{"irrelevant class", Event{ClassUID: ClassProcessActivity, ActivityID: 1, Message: "process start"}, classifiedActivity{Diagnostic: "other"}},
		{"empty event", Event{}, classifiedActivity{Diagnostic: "other"}},
		{"lifecycle record carrying a connect denial", Event{ClassUID: 4001, ActivityID: 3, Message: "CONNECT denied example.com:443"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
		{"irrelevant class carrying a transparent denial", Event{ClassUID: ClassProcessActivity, ActivityID: 1, Message: "Transparent TCP denied example.com:443"}, classifiedActivity{Diagnostic: "conflicting_decision_metadata", Incomplete: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyActivity(tt.ev); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("classifyActivity() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// fuzzActivityEvent builds a classifier input from fuzzed choices, biased
// toward the classes, activities, statuses and message families the rules read.
func fuzzActivityEvent(class, activity, action, disposition, status, family, metadata uint8, suffix string) Event {
	classes := [...]int{ClassHTTPActivity, ClassNetworkActivity, ClassProcessActivity, ClassDetectionFinding, 0}
	activities := [...]int{0, networkActivityOpen, 2, 3, networkActivityFail, networkActivityRefuse, policyActivityOther}
	enums := [...]int{0, 1, deniedID, observedActionID, policyActivityOther}
	statuses := [...]string{"", "credential_endpoint_mismatch", "request_authority_mismatch", "credential_unavailable",
		"assembly_capacity_exhausted", "policy_dns_trusted_gateway_unavailable", "policy_dns_ineligible",
		"transparent_tcp_allowed", "transparent_tcp_policy_denied", "transparent_tcp_mapping_expired",
		"policy_dns_upstream_nxdomain", "policy_dns_no_valid_address", "policy_dns_publication_pool_exhausted",
		"policy_dns_observation_budget_exhausted"}
	families := [...]string{"", "L7_REQUEST ", "GRAPHQL_L7_REQUEST ", "JSONRPC_L7_REQUEST ", "JSONRPC_L7_REQUEST decision=",
		"L7_REQUEST_TRANSFORMED ", "WEBSOCKET_L7_REQUEST ", "CONNECT ", "CONNECT_L7 ", "CONNECT denied ", "Transparent TCP ",
		"Transparent TCP denied ", "MIDDLEWARE ", "WEBSOCKET_MIDDLEWARE ", "WEBSOCKET_MIDDLEWARE_COVERAGE ",
		"WEBSOCKET_CREDENTIAL_REWRITE ", "HTTP_REQUEST ", "Policy DNS refused ", "Supervisor session established",
		"Proxy connection error: ", "Policy DNS trusted resolver query failed"}
	metadatas := [...]string{"", `{"coverage_state":"binding_not_selected"}`, `{"coverage_state":""}`, `{"failed":true}`,
		`{"failed":"maybe"}`, `{"middleware":"guard","count":1}`, `not json`}
	return Event{
		ClassUID:      classes[int(class)%len(classes)],
		ActivityID:    activities[int(activity)%len(activities)],
		ActionID:      enums[int(action)%len(enums)],
		DispositionID: enums[int(disposition)%len(enums)],
		StatusDetail:  statuses[int(status)%len(statuses)],
		Message:       families[int(family)%len(families)] + suffix,
		Unmapped:      json.RawMessage(metadatas[int(metadata)%len(metadatas)]),
	}
}

// statedDecision reports whether a message states an L7 or connection policy
// decision, and which one. It is written independently of the classifier.
func statedDecision(ev Event) (policyDecision, bool) {
	tokens := strings.Fields(ev.Message)
	if len(tokens) > 0 {
		switch tokens[0] {
		case "L7_REQUEST", "GRAPHQL_L7_REQUEST", "JSONRPC_L7_REQUEST", "L7_REQUEST_TRANSFORMED", "WEBSOCKET_L7_REQUEST":
			if len(tokens) == 1 {
				return decisionUnknown, true
			}
			return activityDecision(strings.TrimPrefix(tokens[1], "decision=")), true
		case "CONNECT", "CONNECT_L7":
			if len(tokens) > 1 && (tokens[1] == "allowed" || tokens[1] == "denied") {
				return policyDecision(tokens[1]), true
			}
		}
	}
	switch {
	case strings.HasPrefix(ev.Message, "Transparent TCP denied"):
		return decisionDenied, true
	case strings.HasPrefix(ev.Message, "Transparent TCP ") && ev.StatusDetail == "transparent_tcp_allowed":
		return decisionAllowed, true
	default:
		return "", false
	}
}

func FuzzClassifyActivityKeepsStatedDecisions(f *testing.F) {
	f.Add(uint8(1), uint8(1), uint8(2), uint8(2), uint8(0), uint8(9), uint8(1), "example.com:443")
	f.Add(uint8(1), uint8(4), uint8(0), uint8(0), uint8(0), uint8(6), uint8(0), "deny WEBSOCKET_TEXT example.com:443/ws reason=rule")
	f.Add(uint8(0), uint8(6), uint8(2), uint8(2), uint8(3), uint8(1), uint8(0), "deny POST example.com:443/upload reason=rule")
	f.Add(uint8(1), uint8(3), uint8(0), uint8(0), uint8(0), uint8(11), uint8(0), "example.com:443")
	f.Add(uint8(2), uint8(1), uint8(0), uint8(0), uint8(7), uint8(10), uint8(0), "mapping_id=placeholder")
	f.Add(uint8(1), uint8(5), uint8(2), uint8(2), uint8(10), uint8(20), uint8(0), "")
	f.Fuzz(func(t *testing.T, class, activity, action, disposition, status, family, metadata uint8, suffix string) {
		ev := fuzzActivityEvent(class, activity, action, disposition, status, family, metadata, suffix)
		if ev.ClassUID == ClassDetectionFinding {
			return
		}
		stated, states := statedDecision(ev)
		if !states {
			return
		}
		got := classifyActivity(ev)
		if got.Group == "" && !got.Incomplete {
			t.Fatalf("stated %q decision dropped: %+v -> %+v", stated, ev, got)
		}
		if stated == decisionDenied && got.Group != "" && got.Decision != decisionDenied && got.Decision != decisionUnknown {
			t.Fatalf("stated denial counted as %s: %+v", got.Decision, ev)
		}
	})
}

func TestClassifyActivityFindings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, info, unmapped string
		want                 ActivityFinding
		diagnostic           string
	}{
		{"builtin detector", `{"uid":"regex.api_key"}`, `{"middleware":"content-guard","count":7}`, ActivityFinding{Origin: "plugin", Middleware: "content-guard", Type: "regex.api_key", Records: 1, Occurrences: 7}, ""},
		{"normalized remote", `{"uid":"remote-detector.finding"}`, `{"middleware":"remote-detector","count":3}`, ActivityFinding{Origin: "plugin", Middleware: "remote-detector", Type: "remote-detector.finding", Records: 1, Occurrences: 3}, ""},
		{"zero matches", `{"uid":"remote.finding"}`, `{"middleware":"remote","count":0}`, ActivityFinding{Origin: "plugin", Middleware: "remote", Type: "remote.finding", Records: 1}, ""},
		{"native health with middleware only", `{"uid":"openshell.middleware.failure"}`, `{"middleware":"remote"}`, ActivityFinding{Origin: "operational", Middleware: "remote", Type: "openshell.middleware.failure", Records: 1, Occurrences: 1}, ""},
		{"unknown native", `{"uid":"native.finding"}`, `{}`, ActivityFinding{Origin: "unclassified", Type: "native.finding", Records: 1, Occurrences: 1}, ""},
		{"count without middleware", `{"uid":"native.finding"}`, `{"count":5}`, ActivityFinding{Origin: "unclassified", Type: "native.finding", Records: 1, Occurrences: 5}, ""},
		{"empty info", `{}`, `{}`, ActivityFinding{Origin: "unclassified", Type: "unknown", Records: 1, Occurrences: 1}, "finding_type_unknown"},
		{"null info", `null`, `null`, ActivityFinding{Origin: "unclassified", Type: "unknown", Records: 1, Occurrences: 1}, "finding_type_unknown"},
		{"malformed info shape", `[]`, `{}`, ActivityFinding{Origin: "unclassified", Type: "unknown", Records: 1, Occurrences: 1}, "invalid_finding_metadata"},
		{"info UID wrong type", `{"uid":7}`, `{}`, ActivityFinding{Origin: "unclassified", Type: "unknown", Records: 1, Occurrences: 1}, "invalid_finding_metadata"},
		{"invalid unmapped shape", `{"uid":"native.finding"}`, `[]`, ActivityFinding{Origin: "unclassified", Type: "native.finding", Records: 1, Occurrences: 1}, "invalid_finding_metadata"},
		{"invalid middleware type", `{"uid":"remote.finding"}`, `{"middleware":7,"count":1}`, ActivityFinding{Origin: "unclassified", Type: "remote.finding", Records: 1, Occurrences: 1}, "invalid_finding_metadata"},
		{"empty middleware", `{"uid":"remote.finding"}`, `{"middleware":"","count":1}`, ActivityFinding{Origin: "unclassified", Type: "remote.finding", Records: 1, Occurrences: 1}, "invalid_finding_metadata"},
		{"negative count", `{"uid":"remote.finding"}`, `{"middleware":"remote","count":-1}`, ActivityFinding{Origin: "plugin", Middleware: "remote", Type: "remote.finding", Records: 1, InvalidCounts: 1}, "invalid_finding_count"},
		{"string count", `{"uid":"remote.finding"}`, `{"middleware":"remote","count":"7"}`, ActivityFinding{Origin: "plugin", Middleware: "remote", Type: "remote.finding", Records: 1, InvalidCounts: 1}, "invalid_finding_count"},
		{"fractional count", `{"uid":"remote.finding"}`, `{"middleware":"remote","count":1.5}`, ActivityFinding{Origin: "plugin", Middleware: "remote", Type: "remote.finding", Records: 1, InvalidCounts: 1}, "invalid_finding_count"},
		{"null count", `{"uid":"remote.finding"}`, `{"middleware":"remote","count":null}`, ActivityFinding{Origin: "plugin", Middleware: "remote", Type: "remote.finding", Records: 1, InvalidCounts: 1}, "invalid_finding_count"},
		{"overflow count", `{"uid":"remote.finding"}`, `{"middleware":"remote","count":9223372036854775808}`, ActivityFinding{Origin: "plugin", Middleware: "remote", Type: "remote.finding", Records: 1, InvalidCounts: 1}, "invalid_finding_count"},
		{"coverage metadata", `{"uid":"native.finding"}`, `{"coverage_state":"body_unavailable"}`, ActivityFinding{Origin: "coverage", Type: "native.finding", Records: 1, Occurrences: 1}, ""},
		{"body unavailable", `{"uid":"openshell.middleware.body_unavailable"}`, `{}`, ActivityFinding{Origin: "coverage", Type: "openshell.middleware.body_unavailable", Records: 1, Occurrences: 1}, ""},
		{"traffic uninspectable", `{"uid":"openshell.middleware.traffic_uninspectable"}`, `{}`, ActivityFinding{Origin: "coverage", Type: "openshell.middleware.traffic_uninspectable", Records: 1, Occurrences: 1}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.want.Severity = 3
			ev := Event{ClassUID: ClassDetectionFinding, SeverityID: 3, FindingInfo: json.RawMessage(tt.info), Unmapped: json.RawMessage(tt.unmapped)}
			got := classifyActivity(ev)
			if got.Finding == nil || !reflect.DeepEqual(*got.Finding, tt.want) || got.Diagnostic != tt.diagnostic || got.Incomplete {
				t.Fatalf("classifyActivity() = %+v, finding %+v; want %+v / %q", got, got.Finding, tt.want, tt.diagnostic)
			}
		})
	}
}

func TestClassifyActivityOperationalFindings(t *testing.T) {
	t.Parallel()
	types := []string{"admission_saturated", "admission_exhausted", "session_capacity_exhausted", "websocket_failure", "websocket_stage_disabled", "failure", "policy_evaluation_failure"}
	for _, suffix := range types {
		t.Run(suffix, func(t *testing.T) {
			t.Parallel()
			ev := Event{ClassUID: ClassDetectionFinding, FindingInfo: json.RawMessage(`{"uid":"openshell.middleware.` + suffix + `"}`)}
			got := classifyActivity(ev)
			if got.Finding == nil || got.Finding.Origin != "operational" || got.Incomplete {
				t.Fatalf("classifyActivity() = %+v", got)
			}
		})
	}
}

func TestClassifyActivityFindingTextBounds(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, kind, middleware string }{
		{"ascii", strings.Repeat("a", maxActivityFieldBytes+1), strings.Repeat("a", maxActivityFieldBytes+1)},
		{"unicode", strings.Repeat("界", maxActivityFieldBytes), strings.Repeat("界", maxActivityFieldBytes)},
		{"type only", strings.Repeat("a", maxActivityFieldBytes+1), "content-guard"},
		{"middleware only", "regex.api_key", strings.Repeat("a", maxActivityFieldBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, err := json.Marshal(map[string]string{"uid": tt.kind})
			if err != nil {
				t.Fatal(err)
			}
			unmapped, err := json.Marshal(map[string]any{"middleware": tt.middleware, "count": 1})
			if err != nil {
				t.Fatal(err)
			}
			got := classifyActivity(Event{ClassUID: ClassDetectionFinding, FindingInfo: info, Unmapped: unmapped})
			if got.Finding == nil || len(got.Finding.Type) > maxActivityFieldBytes || len(got.Finding.Middleware) > maxActivityFieldBytes || !utf8.ValidString(got.Finding.Type) || !utf8.ValidString(got.Finding.Middleware) || got.Diagnostic != "finding_metadata_truncated" || got.Incomplete {
				t.Fatalf("bounded finding = %+v / %+v", got, got.Finding)
			}
		})
	}
}

func TestActivityMetadataReaderCompatibility(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, value string }{{"object", `{}`}, {"array", `[]`}, {"string", `"opaque"`}, {"null", `null`}, {"boolean", `true`}, {"integer", `123`}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			line := `{"class_uid":4001,"action_id":1,"disposition_id":1,"status_id":2,"unmapped":` + tt.value + `,"finding_info":` + tt.value + `}`
			ev, ok := decodeLine([]byte(line))
			if !ok || !ev.Denied() || string(ev.Unmapped) != tt.value || string(ev.FindingInfo) != tt.value {
				t.Fatalf("decodeLine() = %+v, %v", ev, ok)
			}
		})
	}
}

func TestActivityReaderInvalidOCSF(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, line string
		want       int
	}{
		{"plain stderr", "INFO a normal supervisor message", 0},
		{"blank", " ", 0},
		{"shorthand", "FINDING: detector count=1", 0},
		{"valid audit", `{"class_uid":4001}`, 0},
		{"valid stderr audit", `timestamp OCSF-JSON {"class_uid":4001}`, 0},
		{"malformed object", `{"class_uid":`, 1},
		{"malformed indented object", `  {not JSON}`, 1},
		{"wrong type in object", `{"class_uid":"4001"}`, 1},
		{"bad stderr payload", `timestamp OCSF-JSON {"class_uid":"4001"}`, 1},
		{"missing stderr payload", `timestamp OCSF-JSON`, 1},
		{"non-object stderr payload", `timestamp OCSF-JSON []`, 0},
		{"marker text inside plain stderr", `CONNECT allowed OCSF-JSON.attacker.example:443`, 0},
		{"marker as a word in plain stderr", `WARN failed to encode OCSF-JSON payload`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewReader(strings.NewReader(tt.line + "\n"))
			_, _ = r.Read()
			if r.invalidOCSF != tt.want || r.Stats().Lines != 1 {
				t.Fatalf("invalid OCSF = %d; stats %+v", r.invalidOCSF, r.Stats())
			}
		})
	}
}
