package hydrator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestActivityConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  ActivityConfig
		bad  bool
	}{
		{name: "defaults"},
		{name: "custom", cfg: ActivityConfig{MinDecisions: 10, MaxUIDsPerAgent: 2, MaxUIDs: 1}},
		{name: "negative sample", cfg: ActivityConfig{MinDecisions: -1}, bad: true},
		{name: "negative agent budget", cfg: ActivityConfig{MaxUIDsPerAgent: -1}, bad: true},
		{name: "negative total budget", cfg: ActivityConfig{MaxUIDs: -1}, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); (err != nil) != tc.bad {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
}

func TestActivityReferenceAssessment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                    string
		http, conn, rewrite, ws DecisionCounts
		minimum                 int
		want                    int
		reason                  string
	}{
		{name: "baseline allowed", http: DecisionCounts{Allowed: 6}, conn: DecisionCounts{Allowed: 6}, minimum: 1, want: 100},
		{name: "baseline method", http: DecisionCounts{Allowed: 4, Denied: 2}, conn: DecisionCounts{Allowed: 6}, minimum: 1, want: 67},
		{name: "baseline hosts", http: DecisionCounts{Allowed: 3}, conn: DecisionCounts{Allowed: 3, Denied: 3}, minimum: 1, want: 50},
		{name: "baseline raw IP", http: DecisionCounts{Allowed: 3}, conn: DecisionCounts{Allowed: 3, Denied: 5}, minimum: 1, want: 38},
		{name: "all audit", http: DecisionCounts{Audited: 6}, minimum: 1, want: 0},
		{name: "post rewrite", http: DecisionCounts{Allowed: 1}, rewrite: DecisionCounts{Denied: 1}, minimum: 1, want: 0},
		{name: "websocket", http: DecisionCounts{Allowed: 1}, ws: DecisionCounts{Audited: 1}, minimum: 1, want: 0},
		{name: "keep alive", http: DecisionCounts{Allowed: 50}, conn: DecisionCounts{Allowed: 1}, minimum: 10, want: 100},
		{name: "low sample denied", http: DecisionCounts{Allowed: 50}, conn: DecisionCounts{Denied: 1}, minimum: 10, reason: "insufficient_sample"},
		{name: "low sample audited", http: DecisionCounts{Audited: 1}, minimum: 10, reason: "insufficient_sample"},
		{name: "low sample allowed", http: DecisionCounts{Allowed: 1}, minimum: 10, reason: "no_eligible_decisions"},
		{name: "unknown", http: DecisionCounts{Allowed: 50, Unknown: 1}, minimum: 1, reason: "interpretation_incomplete"},
		{name: "empty", minimum: 1, reason: "no_eligible_decisions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := ActivityMeasurements{HTTPInitial: tc.http, Connections: tc.conn, PostRewriteEvaluations: tc.rewrite, WebSocketEvaluations: tc.ws}
			score, reason, _ := assessActivity(m, tc.minimum, "")
			if reason != tc.reason {
				t.Fatalf("reason=%q, want %q", reason, tc.reason)
			}
			if tc.reason != "" {
				if score != nil {
					t.Fatalf("unexpected score %v", *score)
				}
				return
			}
			if score == nil || *score != tc.want {
				t.Fatalf("score=%v, want %d", score, tc.want)
			}
		})
	}
}

func activityInput(t *testing.T, uid, message string, class, activity, action int) string {
	t.Helper()
	return jsonLine(t, map[string]any{"class_uid": class, "activity_id": activity, "action_id": action, "disposition_id": action, "time": sampleBaseMs, "container": map[string]any{"uid": sandboxAUID}, "metadata": map[string]any{"uid": uid, "product": map[string]any{"version": "0.1.5"}}, "message": message})
}

func activityOptions(t *testing.T) Options {
	t.Helper()
	return Options{Agents: sampleAgents(t), Signals: SignalConfig{EmitActivity: true}, Clock: fixedClock}
}

func TestActivityRunAndLegacyIsolation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		legacy bool
	}{{name: "activity only"}, {name: "both paths", legacy: true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			if tc.legacy {
				opts.Signals = DefaultSignalConfig()
				opts.Signals.EmitActivity = true
			}
			var evidence bytes.Buffer
			opts.Evidence = &evidence
			lines := []string{
				activityInput(t, "a1", "CONNECT_L7 allowed example.com:443", 4001, 1, 1),
				activityInput(t, "a2", "L7_REQUEST audit POST example.com:443/test reason=rule", 4002, 99, 1),
				activityInput(t, "a3", "Proxy connection error: connection refused", 4001, 4, 0),
				activityInput(t, "a4", "Supervisor session established", 4001, 1, 0),
			}
			sink := &fakeSink{}
			report, err := Run(t.Context(), strings.NewReader(strings.Join(lines, "\n")), sink, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Activity) != 1 || report.Activity[0].Score == nil || *report.Activity[0].Score != 0 {
				t.Fatalf("evidence=%+v", report.Activity)
			}
			if evidence.Len() == 0 {
				t.Fatal("missing local evidence")
			}
			wantObs := 1
			if tc.legacy {
				wantObs = 3
			}
			if report.Observations != wantObs || len(sink.batches) != 1 {
				t.Fatalf("report=%+v", report)
			}
			found := false
			for _, row := range sink.batches[0].Observations {
				var value map[string]any
				if err := json.Unmarshal(row.Value, &value); err != nil {
					t.Fatal(err)
				}
				if row.SignalID == DefaultActivitySignal {
					found = true
					if value["score"] != float64(0) || len(value) != 2 {
						t.Fatalf("generic value=%v", value)
					}
				}
				if row.SignalID == DefaultPolicyViolationRateSignal && value["denied"] != float64(0) {
					t.Fatalf("legacy changed: %v", value)
				}
			}
			if !found {
				t.Fatal("activity observation missing")
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
			opts := activityOptions(t)
			if tc.legacy {
				opts.Signals = DefaultSignalConfig()
				opts.Signals.EmitActivity = true
			}
			stats := newRunStats(opts)
			if stats.activity == nil {
				t.Fatal("activity aggregator not built")
			}
			for _, uid := range []string{"1", "2", "3"} {
				stats.attributor.add(Event{ClassUID: 4001, ActivityID: 1, ActionID: 1, DispositionID: 1, Time: 1, Container: &Container{UID: sandboxAUID}, Metadata: Metadata{UID: uid}, DstEndpoint: &Endpoint{Domain: uid + ".example.com"}, Message: "CONNECT allowed example.com:443"})
			}
			if stats.attributor.seen["agent-a"].events != 3 {
				t.Fatal("summary attribution lost")
			}
			if (stats.legacy != nil) != tc.legacy {
				t.Fatalf("legacy aggregator registered=%v, want %v", stats.legacy != nil, tc.legacy)
			}
			if tc.legacy && len(stats.legacy.stats["agent-a"].destinations) != 3 {
				t.Fatalf("legacy destinations=%d want 3", len(stats.legacy.stats["agent-a"].destinations))
			}
			if got := stats.activity.stats["agent-a"].measurements.Connections.Allowed; got != 3 {
				t.Fatalf("activity connections allowed=%d, want 3", got)
			}
		})
	}
}

func TestActivityAggregatorOnlyWhenRequested(t *testing.T) {
	t.Parallel()
	stats := newRunStats(Options{Agents: sampleAgents(t), Signals: DefaultSignalConfig()})
	if stats.activity != nil || stats.legacy == nil {
		t.Fatal("legacy-only run built the activity path")
	}
	if consumers := stats.attributor.consumers; len(consumers) != 1 {
		t.Fatalf("consumers=%d, want the legacy aggregator only", len(consumers))
	}
	stats = newRunStats(Options{Agents: sampleAgents(t), Evidence: &bytes.Buffer{}})
	if stats.activity == nil || stats.legacy != nil {
		t.Fatal("evidence-only run did not build only the activity path")
	}
}

func TestActivityPolicyBeforeWindow(t *testing.T) {
	t.Parallel()
	window := Window{Start: time.UnixMilli(sampleBaseMs).UTC(), End: time.UnixMilli(sampleBaseMs + 60_000).UTC()}
	opts := activityOptions(t)
	opts.Window = &window
	policy := func(uid string, offsetMs int64) string {
		return jsonLine(t, map[string]any{"class_uid": ClassDeviceConfigChange, "activity_id": 1, "time": sampleBaseMs + offsetMs, "container": map[string]any{"uid": sandboxAUID}, "metadata": map[string]any{"uid": uid}, "unmapped": map[string]any{"policy_hash": "before" + uid, "version": 1}})
	}
	lines := []string{
		policy("p1", -1000),
		policy("p2", 120_000),
		jsonLine(t, map[string]any{"class_uid": ClassDeviceConfigChange, "activity_id": 1, "time": sampleBaseMs - 1000, "container": map[string]any{"uid": "unmapped-sandbox"}, "unmapped": map[string]any{"policy_hash": "unmapped", "version": 1}}),
		activityInput(t, "a1", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1),
	}
	report, err := Run(t.Context(), strings.NewReader(strings.Join(lines, "\n")), &fakeSink{}, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.OutOfWindow != 3 || report.Attributed != 1 || report.Unmapped != 0 {
		t.Fatalf("outOfWindow/attributed/unmapped=%d/%d/%d, want 3/1/0", report.OutOfWindow, report.Attributed, report.Unmapped)
	}
	if len(report.Activity) != 1 || len(report.Activity[0].Policies) != 1 || report.Activity[0].Policies[0].Hash != "beforep1" {
		t.Fatalf("pre-window policy context=%+v, want only the policy loaded before the window", report.Activity)
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
			wantLegacyDenied := 0
			if tc.legacy {
				wantLegacyDenied = 1
			}
			if report.Agents[0].Denied != wantLegacyDenied {
				t.Fatalf("legacy denied=%d, want %d", report.Agents[0].Denied, wantLegacyDenied)
			}
		})
	}
}

func TestActivityConnectionOnlyTraffic(t *testing.T) {
	t.Parallel()
	lines := []string{
		activityInput(t, "c1", "CONNECT allowed example.com:443", 4001, 1, 1),
		activityInput(t, "c2", "CONNECT allowed example.com:443", 4001, 1, 1),
		activityInput(t, "c3", "CONNECT allowed example.com:443", 4001, 1, 1),
		activityInput(t, "c4", "CONNECT denied blocked.example.com:443", 4001, 1, 2),
	}
	sink := &fakeSink{}
	report, err := Run(t.Context(), strings.NewReader(strings.Join(lines, "\n")), sink, activityOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	evidence := report.Activity[0]
	want := ActivityMeasurements{Connections: DecisionCounts{Allowed: 3, Denied: 1}}
	if evidence.Measurements != want || evidence.Score == nil || *evidence.Score != 75 {
		t.Fatalf("connection-only evidence=%+v", evidence)
	}
	if len(sink.batches) != 1 || len(sink.batches[0].Observations) != 1 {
		t.Fatalf("connection-only score not posted: %+v", sink.batches)
	}
}

// OpenShell v0.1.5 logs the L7 decision before forwarding, so an upstream 503
// appears only as an allowed request with no status or response fields.
func TestActivityAllowedUpstreamFailure(t *testing.T) {
	t.Parallel()
	requests := []string{"r1", "r2", "r3"}
	lines := make([]string, 0, 2*len(requests))
	for _, uid := range requests {
		lines = append(lines,
			activityInput(t, uid+"-connect", "CONNECT_L7 allowed httpbingo.org:443", 4001, 1, 1),
			activityInput(t, uid+"-request", "L7_REQUEST allow GET httpbingo.org:443/status/503 reason=", 4002, 99, 1))
	}
	report, err := Run(t.Context(), strings.NewReader(strings.Join(lines, "\n")), &fakeSink{}, activityOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	evidence := report.Activity[0]
	want := ActivityMeasurements{HTTPInitial: DecisionCounts{Allowed: 3}, Connections: DecisionCounts{Allowed: 3}}
	if evidence.Measurements != want || evidence.Score == nil || *evidence.Score != 100 {
		t.Fatalf("allowed upstream failures counted against the agent: %+v", evidence)
	}
}

func TestActivityDegradedAgentSkippedFromBatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		legacy bool
	}{
		{name: "activity only"}, {name: "legacy alongside", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			if tc.legacy {
				opts.Signals = DefaultSignalConfig()
				opts.Signals.EmitActivity = true
			}
			clean := activityInput(t, "a1", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1)
			degraded := jsonLine(t, map[string]any{"class_uid": 4002, "activity_id": 99, "action_id": 1, "disposition_id": 1, "time": sampleBaseMs, "container": map[string]any{"name": sandboxBName}, "metadata": map[string]any{"uid": "b1"}, "message": "FUTURE_L7_FORMAT permitted=true"})
			sink := &fakeSink{}
			report, err := Run(t.Context(), strings.NewReader(clean+"\n"+degraded), sink, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Activity) != 2 {
				t.Fatalf("evidence=%+v, want one record per agent", report.Activity)
			}
			activityRows, legacyRows := 0, 0
			for _, row := range sink.batches[0].Observations {
				if row.SignalID == DefaultActivitySignal {
					activityRows++
					if row.AgentID != "agent-a" {
						t.Fatalf("degraded agent posted a score: %+v", row)
					}
				} else {
					legacyRows++
				}
			}
			wantLegacy := 0
			if tc.legacy {
				wantLegacy = 4
			}
			if activityRows != 1 || legacyRows != wantLegacy {
				t.Fatalf("activity rows=%d legacy rows=%d, want 1 and %d", activityRows, legacyRows, wantLegacy)
			}
		})
	}
}

func TestActivityMeasurementsTotals(t *testing.T) {
	t.Parallel()
	measurements := ActivityMeasurements{
		HTTPInitial:            DecisionCounts{Allowed: 9, Denied: 1},
		PostRewriteEvaluations: DecisionCounts{Denied: 2, Audited: 5},
		WebSocketEvaluations:   DecisionCounts{Denied: 3, Unknown: 7},
		Connections:            DecisionCounts{Denied: 4},
	}
	if got := measurements.Denied(); got != 10 {
		t.Fatalf("Denied()=%d, want 10", got)
	}
	if got := measurements.Audited(); got != 5 {
		t.Fatalf("Audited()=%d, want 5", got)
	}
}

func TestActivityObservationRequiresScore(t *testing.T) {
	t.Parallel()
	builder := observationBuilder{signals: SignalConfig{EmitActivity: true}.withDefaults()}
	if _, err := builder.activity("agent", ActivityEvidence{Unavailable: activityIncomplete}); err == nil {
		t.Fatal("expected an error for evidence without a score")
	}
	score := 67
	row, err := builder.activity("agent", ActivityEvidence{Score: &score})
	if err != nil {
		t.Fatal(err)
	}
	var value ActivityScoreValue
	if err := json.Unmarshal(row.Value, &value); err != nil || value.Score != 67 || row.SignalID != DefaultActivitySignal {
		t.Fatalf("row=%+v value=%+v err=%v", row, value, err)
	}
}

func TestActivityFindingOnlyAndFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, input, reason string
		writerError         bool
		inputError          bool
		invalidConfig       bool
	}{
		{name: "finding only", input: `{"class_uid":2004,"time":1791996120000,"container":{"uid":"3949f6fc-2b84-45b2-a631-46debe41d84f"},"finding_info":{"uid":"detector.finding"},"severity_id":3,"unmapped":{"middleware":"detector","count":7}}`, reason: "no_eligible_decisions"},
		{name: "unknown message", input: `{"class_uid":4002,"activity_id":99,"time":1791996120000,"container":{"uid":"3949f6fc-2b84-45b2-a631-46debe41d84f"},"message":"FUTURE_L7_FORMAT permitted=true","action_id":1}`, reason: "interpretation_incomplete"},
		{name: "evidence write failure", input: `{"class_uid":2004,"container":{"uid":"3949f6fc-2b84-45b2-a631-46debe41d84f"}}`, writerError: true},
		{name: "input failure", inputError: true},
		{name: "bad config", invalidConfig: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			var output bytes.Buffer
			opts.Evidence = &output
			if tc.writerError {
				opts.Evidence = failingWriter{}
			}
			if tc.invalidConfig {
				opts.Activity.MinDecisions = -1
			}
			input := strings.NewReader(tc.input)
			sink := &fakeSink{}
			var report Report
			var err error
			if tc.inputError {
				report, err = Run(t.Context(), iotest.ErrReader(errors.New("read failed")), sink, opts, nil)
			} else {
				report, err = Run(t.Context(), input, sink, opts, nil)
			}
			if tc.writerError || tc.inputError || tc.invalidConfig {
				if err == nil {
					t.Fatal("expected error")
				}
				if len(sink.batches) != 0 {
					t.Fatal("posted despite failure")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Activity) != 1 || report.Activity[0].Unavailable != tc.reason || report.Activity[0].Score != nil {
				t.Fatalf("evidence=%+v", report.Activity)
			}
			if len(sink.batches) != 0 || output.Len() == 0 {
				t.Fatal("finding/unknown evidence was lost or invented a score")
			}
		})
	}
}

func TestActivityDedupIsolation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		cfg    ActivityConfig
		count  int
		reason string
	}{
		{name: "deduplicate", count: 1},
		{name: "agent saturated", cfg: ActivityConfig{MaxUIDsPerAgent: 1}, count: 2, reason: "dedup_saturated"},
		{name: "global saturated releases owner", cfg: ActivityConfig{MaxUIDs: 1}, count: 2, reason: "dedup_saturated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			opts.Activity = tc.cfg
			lines := make([]string, 0, 2*tc.count+1)
			for i := range tc.count {
				line := activityInput(t, strconv.Itoa(i), "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1)
				lines = append(lines, line, line)
			}
			// Agent b follows after a's working set has been released.
			lines = append(lines, jsonLine(t, map[string]any{"class_uid": 4002, "activity_id": 99, "container": map[string]any{"name": sandboxBName}, "metadata": map[string]any{"uid": "b"}, "time": sampleBaseMs, "action_id": 1, "disposition_id": 1, "message": "L7_REQUEST allow GET example.com:443/test reason=rule"}))
			report, err := Run(t.Context(), strings.NewReader(strings.Join(lines, "\n")), &fakeSink{}, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.Activity[0].Unavailable != tc.reason {
				t.Fatalf("a=%+v", report.Activity[0])
			}
			if tc.reason == "" && report.Activity[0].Measurements.HTTPInitial.Allowed != 1 {
				t.Fatal("duplicate counted")
			}
			if tc.reason != "" && (report.Activity[1].Score == nil || *report.Activity[1].Score != 100) {
				t.Fatalf("unrelated b lost score: %+v", report.Activity[1])
			}
		})
	}
}

func TestActivityPolicyContext(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		policyTimes []int64
		wantUnknown bool
		wantChanged bool
	}{
		{name: "policy before window", policyTimes: []int64{sampleBaseMs - 1000}},
		{name: "policy after decision", policyTimes: []int64{sampleBaseMs + 1000}, wantUnknown: true, wantChanged: true},
		{name: "policy changed mid window", policyTimes: []int64{sampleBaseMs - 1000, sampleBaseMs + 1000}, wantChanged: true},
		{name: "missing policy", wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			opts.Window = &Window{Start: time.UnixMilli(sampleBaseMs), End: time.UnixMilli(sampleBaseMs + 2000)}
			lines := make([]string, 0, 1+len(tc.policyTimes))
			lines = append(lines, activityInput(t, "request", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1))
			for i, policyTime := range tc.policyTimes {
				lines = append(lines, jsonLine(t, map[string]any{"class_uid": 5019, "time": policyTime, "container": map[string]any{"uid": sandboxAUID}, "unmapped": map[string]any{"policy_hash": "policy-" + strconv.Itoa(i), "version": 1}}))
			}
			report, err := Run(t.Context(), strings.NewReader(strings.Join(lines, "\n")), &fakeSink{}, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			evidence := report.Activity[0]
			if evidence.PolicyUnknown != tc.wantUnknown || evidence.PolicyChanged != tc.wantChanged {
				t.Fatalf("policy=%+v", evidence)
			}
			if len(evidence.Policies) != len(tc.policyTimes) {
				t.Fatal("policy context lost")
			}
			explanation := activityExplanation(evidence)
			if strings.Contains(explanation, "loaded after counting began") != tc.wantChanged {
				t.Fatalf("policy change not explained: %s", explanation)
			}
			for _, policy := range evidence.Policies {
				if !strings.Contains(explanation, fmt.Sprintf("hash=%q version=%q", policy.Hash, policy.Version)) {
					t.Fatalf("policy %q missing from explanation: %s", policy.Hash, explanation)
				}
			}
		})
	}
}

func TestActivityPolicySummaryBounds(t *testing.T) {
	t.Parallel()
	const policyCount = 5
	policies := make([]PolicyContext, 0, policyCount)
	for i := range policyCount {
		policies = append(policies, PolicyContext{Hash: strings.Repeat("a", 64) + strconv.Itoa(i), Version: strconv.Itoa(i)})
	}
	score := 100
	explanation := activityExplanation(ActivityEvidence{Score: &score, Policies: policies})
	if strings.Count(explanation, " Policy hash=") != 4 || !strings.Contains(explanation, "1 additional policies in local evidence") {
		t.Fatalf("policy summary not bounded: %s", explanation)
	}
	if !strings.Contains(explanation, `hash="aaaaaaaaaaaa" version="0"`) {
		t.Fatalf("policy hash not shortened: %s", explanation)
	}
}

func TestActivityFindingsDoNotChangeScore(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		withFinding bool
	}{{name: "no finding"}, {name: "finding", withFinding: true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			input := activityInput(t, "request", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1)
			if tc.withFinding {
				input += "\n" + `{"class_uid":2004,"container":{"uid":"3949f6fc-2b84-45b2-a631-46debe41d84f"},"finding_info":{"uid":"detector.finding"},"severity_id":3,"unmapped":{"middleware":"detector","count":7}}`
			}
			sink := &fakeSink{}
			report, err := Run(t.Context(), strings.NewReader(input), sink, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.Activity[0].Score == nil || *report.Activity[0].Score != 100 {
				t.Fatalf("score=%v", report.Activity[0].Score)
			}
			if tc.withFinding && !strings.Contains(string(sink.batches[0].Observations[0].Value), "detector") {
				t.Fatal("finding explanation missing")
			}
		})
	}
}
