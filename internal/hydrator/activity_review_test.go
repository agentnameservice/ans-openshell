package hydrator

import (
	"strings"
	"testing"
)

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
			for i, evidence := range agg.evidence(Window{}, 0) {
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

func TestActivityOnlyDoesNotAccumulateLegacyPayload(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		legacy bool
	}{
		{name: "new only"}, {name: "legacy kept", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agg := newAggregator(sampleAgents(t), nil)
			agg.activity = newActivityAggregator(sampleAgents(t), nil, ActivityConfig{MaxUIDsPerAgent: 1})
			agg.skipLegacyStats = !tc.legacy
			for _, uid := range []string{"1", "2", "3"} {
				agg.add(Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Time: 1, Container: &Container{UID: sandboxAUID}, Metadata: Metadata{UID: uid}, DstEndpoint: &Endpoint{Domain: uid + ".example.com"}, Message: "CONNECT allowed example.com:443"})
			}
			st := agg.stats["agent-a"]
			if st.events != 3 {
				t.Fatal("summary attribution lost")
			}
			want := 0
			if tc.legacy {
				want = 3
			}
			if len(st.destinations) != want {
				t.Fatalf("legacy destinations=%d want %d", len(st.destinations), want)
			}
		})
	}
}

func TestActivityFailureStatusKeepsLegacyBehavior(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		legacy bool
	}{
		{name: "new only"}, {name: "legacy alongside", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			if tc.legacy {
				opts.Signals = DefaultSignalConfig()
				opts.Signals.EmitActivity = true
			}
			input := activityInput(t, "allowed", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1) + "\n" + `{"class_uid":4001,"activity_id":4,"status_id":2,"time":1791996121000,"container":{"uid":"3949f6fc-2b84-45b2-a631-46debe41d84f"},"message":"Proxy connection error: connection refused"}`
			sink := &fakeSink{}
			report, err := Run(t.Context(), strings.NewReader(input), sink, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.Activity[0].Score == nil || *report.Activity[0].Score != 100 {
				t.Fatal("connection failure penalized corrected score")
			}
			if tc.legacy && report.Agents[0].Denied != 1 {
				t.Fatal("legacy status-failure counting changed")
			}
		})
	}
}
