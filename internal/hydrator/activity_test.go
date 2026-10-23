package hydrator

import (
	"bytes"
	"encoding/json"
	"errors"
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
			var lines []string
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
		policyTime  int64
		wantUnknown bool
	}{
		{name: "policy before window", policyTime: sampleBaseMs - 1000},
		{name: "policy after decision", policyTime: sampleBaseMs + 1000, wantUnknown: true},
		{name: "missing policy", wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := activityOptions(t)
			opts.Window = &Window{Start: time.UnixMilli(sampleBaseMs), End: time.UnixMilli(sampleBaseMs + 2000)}
			input := activityInput(t, "request", "L7_REQUEST allow GET example.com:443/test reason=rule", 4002, 99, 1)
			if tc.policyTime != 0 {
				input += "\n" + jsonLine(t, map[string]any{"class_uid": 5019, "time": tc.policyTime, "container": map[string]any{"uid": sandboxAUID}, "unmapped": map[string]any{"policy_hash": "test-policy", "version": 1}})
			}
			report, err := Run(t.Context(), strings.NewReader(input), &fakeSink{}, opts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if report.Activity[0].PolicyUnknown != tc.wantUnknown {
				t.Fatalf("policy=%+v", report.Activity[0])
			}
			if tc.policyTime != 0 && len(report.Activity[0].Policies) != 1 {
				t.Fatal("policy context lost")
			}
		})
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
