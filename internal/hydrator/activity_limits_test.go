package hydrator

import (
	"encoding/json"
	"math"
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
			evidence := st.evidence("agent", Window{}, 1)
			if (evidence.Score == nil) != tc.wantUnavailable {
				t.Fatalf("evidence=%+v", evidence)
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
			evidence := st.evidence("agent", Window{}, 1)
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
	for _, tc := range []struct{ name, extra, reason string }{
		{name: "ordinary stderr", extra: "ordinary supervisor log\n"},
		{name: "malformed audit", extra: "OCSF-JSON {broken\n", reason: "unreadable_audit_records"},
		{name: "oversized audit", extra: "{" + strings.Repeat(" ", MaxLineBytes) + "}\n", reason: "unreadable_audit_records"},
		{name: "oversized ordinary stderr", extra: "ordinary log " + strings.Repeat("x", MaxLineBytes) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := activityInput(t, "request", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1) + "\n" + tc.extra
			report, err := Run(t.Context(), strings.NewReader(input), &fakeSink{}, activityOptions(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.Activity[0].Unavailable != tc.reason {
				t.Fatalf("evidence=%+v", report.Activity[0])
			}
		})
	}
}
