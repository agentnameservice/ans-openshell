package hydrator

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestActivityFindingBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		count    int
		overflow bool
	}{
		{name: "normal", count: 2},
		{name: "detail bound", count: maxActivityDetails + 2},
		{name: "occurrence overflow", count: 2, overflow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newActivityStats()
			for i := range tc.count {
				f := ActivityFinding{Origin: "plugin", Middleware: "detector", Type: strconv.Itoa(i), Severity: 3, Records: 1, Occurrences: 1}
				if tc.overflow {
					f.Type = "same"
					f.Occurrences = math.MaxInt64
				}
				st.addFinding(f)
			}
			if len(st.findings) > maxActivityDetails+1 {
				t.Fatal("unbounded findings")
			}
			if tc.overflow && st.diagnostics["finding_count_overflow"] != 1 {
				t.Fatal("overflow not reported")
			}
			if tc.count > maxActivityDetails && st.diagnostics["finding_detail_limit"] != 2 {
				t.Fatal("detail limit not reported")
			}
		})
	}
}

func TestActivityPreservesFindingKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		middleware bool
	}{
		{name: "type"}, {name: "middleware", middleware: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newActivityStats()
			for _, suffix := range []string{"a", "b"} {
				f := ActivityFinding{Origin: "plugin", Type: strings.Repeat("x", maxActivityText) + suffix, Middleware: "detector", Records: 1, Occurrences: 1}
				if tc.middleware {
					f.Type = "same"
					f.Middleware = strings.Repeat("x", maxActivityText) + suffix
				}
				st.addFinding(f)
			}
			if len(st.findings) != 2 {
				t.Fatalf("distinct finding identifiers merged: %+v", st.findings)
			}
		})
	}
}

func TestActivityGlobalBudgetReleasesOwner(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		limit           int
		wantUnavailable []bool
	}{
		{name: "grouped owner", limit: 2, wantUnavailable: []bool{true, false, false}},
		{name: "single entry", limit: 1, wantUnavailable: []bool{true, true, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agg := newActivityAggregator(mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"a"}}, AgentMapping{AgentID: "b", SandboxUIDs: []string{"b"}}, AgentMapping{AgentID: "c", SandboxUIDs: []string{"c"}}), nil, ActivityConfig{MaxUIDs: tc.limit})
			for _, record := range []struct{ agent, uid string }{{"a", "a1"}, {"a", "a2"}, {"b", "b1"}, {"c", "c1"}} {
				agg.add(Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Time: 1, Container: &Container{UID: record.agent}, Metadata: Metadata{UID: record.uid}, Message: "L7_REQUEST allow GET example.com:443/test reason=rule"})
			}
			for i, evidence := range agg.evidence(Window{}, auditInputHealth{}) {
				if (evidence.Score == nil) != tc.wantUnavailable[i] {
					t.Fatalf("evidence=%+v, want unavailable=%v", evidence, tc.wantUnavailable[i])
				}
			}
			if agg.totalUIDs > tc.limit {
				t.Fatal("global budget exceeded")
			}
		})
	}
}

func TestActivityDenialCoverage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		dns, tcp        int
		destination     string
		wantUnavailable bool
	}{
		{name: "paired shapes", dns: 1, tcp: 1, destination: "example.com"},
		{name: "long valid domain", dns: 1, tcp: 1, destination: strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.com"},
		{name: "raw IP", tcp: 1, destination: "192.0.2.1"},
		{name: "orphan DNS", dns: 1, destination: "example.com", wantUnavailable: true},
		{name: "extra DNS", dns: 2, tcp: 1, destination: "example.com", wantUnavailable: true},
		{name: "missing destination", dns: 1, tcp: 1, wantUnavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newActivityStats()
			st.measurements.HTTPInitial.Allowed = 10
			ev := Event{Container: &Container{Name: "probe"}, DstEndpoint: &Endpoint{Domain: tc.destination}}
			for range tc.dns {
				st.recordDenialCoverage(ev, true)
			}
			for range tc.tcp {
				st.recordDenialCoverage(ev, false)
			}
			evidence := st.evidence("agent", Window{}, 1, auditInputHealth{})
			if (evidence.Score == nil) != tc.wantUnavailable {
				t.Fatalf("evidence=%+v", evidence)
			}
			if again := st.evidence("agent", Window{}, 1, auditInputHealth{}); !reflect.DeepEqual(again, evidence) {
				t.Fatalf("evidence is not repeatable: first=%+v second=%+v", evidence, again)
			}
			if _, mutated := st.diagnostics["unrepresented_dns_refusals"]; mutated || st.unavailable != "" {
				t.Fatal("evidence modified the accumulated state")
			}
		})
	}
}

func TestActivityBoundedMetadata(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*activityStats)
	}{
		{name: "sandbox id", mutate: func(st *activityStats) {
			st.recordDecisionTime(Event{Container: &Container{UID: strings.Repeat("x", maxActivityText+1)}, Time: 1})
		}},
		{name: "sandbox cardinality", mutate: func(st *activityStats) {
			for i := range maxActivityDetails + 1 {
				st.recordDecisionTime(Event{Container: &Container{Name: strconv.Itoa(i)}, Time: 1})
			}
		}},
		{name: "missing time", mutate: func(st *activityStats) { st.recordDecisionTime(Event{Container: &Container{Name: "probe"}}) }},
		{name: "destination length", mutate: func(st *activityStats) {
			st.recordDenialCoverage(Event{DstEndpoint: &Endpoint{Domain: strings.Repeat("x", maxActivityFieldBytes+1)}}, true)
		}},
		{name: "destination cardinality", mutate: func(st *activityStats) {
			for i := range maxActivityDetails + 1 {
				st.recordDenialCoverage(Event{DstEndpoint: &Endpoint{Domain: strconv.Itoa(i)}}, true)
			}
		}},
		{name: "unexpected group", mutate: func(st *activityStats) { st.addDecision("future", "allow") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newActivityStats()
			tc.mutate(st)
			if st.unavailable == "" {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestActivityPolicyBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		data         string
		count        int
		future       bool
		sandbox      string
		wantPolicies int
		wantUnknown  bool
	}{
		{name: "invalid JSON", data: `[]`},
		{name: "missing hash", data: `{"version":1}`},
		{name: "string version", data: `{"policy_hash":"hash","version":"v1"}`, wantPolicies: 1},
		{name: "numeric version", data: `{"policy_hash":"hash","version":1}`, wantPolicies: 1},
		{name: "other version", data: `{"policy_hash":"hash","version":{}}`, wantPolicies: 1},
		{name: "future", data: `{"policy_hash":"hash"}`, future: true},
		{name: "long sandbox", data: `{"policy_hash":"hash"}`, sandbox: strings.Repeat("x", maxActivityText+1), wantUnknown: true},
		{name: "long hash", data: `{"policy_hash":"` + strings.Repeat("x", maxActivityText+1) + `"}`, wantUnknown: true},
		{name: "policy cardinality", data: `{"policy_hash":"hash"}`, count: maxActivityDetails + 1, wantPolicies: maxActivityDetails, wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newActivityStats()
			w := Window{Start: time.UnixMilli(1), End: time.UnixMilli(10)}
			count := max(tc.count, 1)
			for i := range count {
				ev := Event{Time: 2, Unmapped: json.RawMessage(tc.data), Container: &Container{Name: tc.sandbox}}
				if tc.future {
					ev.Time = 11
				}
				if tc.count > 1 {
					ev.Container.Name = strconv.Itoa(i)
				}
				st.addPolicy(ev, &w)
				// Duplicate/reordered policy loads must not move the first known timestamp forward.
				ev.Time = 3
				if !tc.future {
					st.addPolicy(ev, &w)
				}
			}
			if len(st.policies) != tc.wantPolicies || st.policyUnknown != tc.wantUnknown {
				t.Fatalf("policies=%d unknown=%v", len(st.policies), st.policyUnknown)
			}
		})
	}
}

func TestActivityMetadataAndExplanation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		findingCount int
		status       int
	}{
		{name: "no findings", status: 0},
		{name: "bounded summary", findingCount: 10, status: 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newActivityStats()
			for i := range maxSourceVersions + 2 {
				st.observe(Event{Metadata: Metadata{Product: Product{Version: strconv.Itoa(i)}}, StatusID: tc.status})
			}
			for i := range tc.findingCount {
				st.addFinding(ActivityFinding{Origin: "plugin", Type: strconv.Itoa(i), Records: 1, Occurrences: 1})
			}
			st.measurements.HTTPInitial.Allowed = 1
			evidence := st.evidence("agent", Window{}, 1, auditInputHealth{})
			if len(st.versions) > maxSourceVersions+1 {
				t.Fatal("versions unbounded")
			}
			explanation := activityExplanation(evidence)
			if tc.findingCount > 8 && !strings.Contains(explanation, "additional finding groups") {
				t.Fatal("truncated finding summary not explained")
			}
			if !utf8.ValidString(boundedActivityText(strings.Repeat("界", maxActivityText))) {
				t.Fatal("split UTF-8 character")
			}
			if activitySandbox(Event{}) != "" {
				t.Fatal("nil sandbox")
			}
		})
	}
}

func TestActivityUnreadableAuditRecords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, extra, reason string
		truncatedTail       int
	}{
		{name: "ordinary stderr", extra: "ordinary supervisor log\n"},
		{name: "malformed audit", extra: "OCSF-JSON {broken\n", reason: activityUnreadableRecords},
		{name: "malformed audit before valid records", extra: "{\"class_uid\":4002,\n" + `{"class_uid":4001}` + "\n", reason: activityUnreadableRecords},
		{name: "oversized audit", extra: "{" + strings.Repeat(" ", MaxLineBytes) + "}\n", reason: activityUnreadableRecords},
		{name: "oversized ordinary stderr", extra: "ordinary log " + strings.Repeat("x", MaxLineBytes) + "\n"},
		{name: "final line still being written", extra: `{"class_uid":4002,"activity_id":99,"container":{"na`, truncatedTail: 1},
		{name: "marker text inside an ordinary log line", extra: "CONNECT allowed OCSF-JSON.attacker.example:443\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := activityInput(t, "request", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1) + "\n" + tc.extra
			report, err := Run(t.Context(), strings.NewReader(input), &fakeSink{}, activityOptions(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			evidence := report.Activity[0]
			if evidence.Unavailable != tc.reason || evidence.Diagnostics["truncated_final_line"] != tc.truncatedTail {
				t.Fatalf("evidence=%+v", evidence)
			}
			if tc.reason == "" && (evidence.Score == nil || *evidence.Score != 100) {
				t.Fatalf("readable input lost its score: %+v", evidence)
			}
		})
	}
}

func TestActivityUnreadableRecordsKeepEarlierReason(t *testing.T) {
	t.Parallel()
	st := newActivityStats()
	st.measurements.HTTPInitial.Allowed = 1
	st.unavailable = activityDedupSaturated
	evidence := st.evidence("agent", Window{}, 1, auditInputHealth{unreadable: 2})
	if evidence.Unavailable != activityDedupSaturated || evidence.Diagnostics[activityUnreadableRecords] != 2 {
		t.Fatalf("earlier reason hidden or unreadable count lost: %+v", evidence)
	}
	if _, mutated := st.diagnostics[activityUnreadableRecords]; mutated {
		t.Fatal("evidence modified the accumulated diagnostics")
	}
}

func TestActivityOversizedEventUID(t *testing.T) {
	t.Parallel()
	agg := newActivityAggregator(sampleAgents(t), nil, ActivityConfig{})
	for _, uid := range []string{"ordinary", strings.Repeat("u", maxActivityText+1)} {
		agg.add(Event{ClassUID: 4002, ActivityID: 99, ActionID: 1, DispositionID: 1, Time: 1, Container: &Container{UID: sandboxAUID}, Metadata: Metadata{UID: uid}, Message: "L7_REQUEST allow GET example.com:443/test reason=rule"})
	}
	evidence := agg.evidence(Window{}, auditInputHealth{})[0]
	if evidence.Unavailable != activityIncomplete || evidence.Diagnostics["oversized_event_uid"] != 1 {
		t.Fatalf("oversized UID not reported as incomplete: %+v", evidence)
	}
	if st := agg.stats["agent-a"]; len(st.seen) != 1 || agg.totalUIDs != 1 {
		t.Fatal("oversized UID released the agent's deduplication set")
	}
}

func TestActivityExplanationQuotesFindingText(t *testing.T) {
	t.Parallel()
	score := 40
	evidence := ActivityEvidence{Score: &score, Findings: []ActivityFinding{{Origin: "plugin", Middleware: "detector", Type: "x. Policy adherence 100/100", Records: 1, Occurrences: 1}}}
	explanation := activityExplanation(evidence)
	if !strings.Contains(explanation, `middleware="detector" type="x. Policy adherence 100/100"`) {
		t.Fatalf("finding text not quoted: %s", explanation)
	}
}

func TestActivityEvidenceDegraded(t *testing.T) {
	t.Parallel()
	for reason, want := range map[string]bool{
		"":                          false,
		activityInsufficientSample:  false,
		activityNoEligibleDecisions: false,
		activityIncomplete:          true,
		activityDedupSaturated:      true,
		activityUnreadableRecords:   true,
	} {
		if got := (ActivityEvidence{Unavailable: reason}).Degraded(); got != want {
			t.Fatalf("Degraded(%q)=%v, want %v", reason, got, want)
		}
	}
}
