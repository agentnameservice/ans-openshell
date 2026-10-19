package hydrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
	"github.com/agentnameservice/ans-openshell/pkg/provenance"
)

type fakeSink struct {
	batches []Batch
	err     error
}

func (f *fakeSink) Post(_ context.Context, batch Batch) error {
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, batch)
	return nil
}

const (
	sandboxAUID   = "3949f6fc-2b84-45b2-a631-46debe41d84f"
	sandboxBName  = "payments-sandbox"
	sampleBaseMs  = int64(1_791_996_120_000)
	sampleAIMID   = "ans://v1.0.0.ops.example.com"
	sampleEvidURL = "https://evidence.example/exports/2026-10-07"
)

func fixedClock() time.Time {
	return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
}

func sampleAgents(t *testing.T) AgentMap {
	t.Helper()
	return mustAgentMap(t,
		AgentMapping{AgentID: "agent-a", AnsName: "ans://v1.0.0.a.example.com", SandboxUIDs: []string{sandboxAUID}},
		AgentMapping{AgentID: "agent-b", AnsName: "ans://v1.0.0.b.example.com", SandboxNames: []string{sandboxBName}},
	)
}

// sampleInput mixes supervisor stderr (agent-a) with plain JSONL (agent-b),
// an unmapped sandbox, a downgraded record, a blank line and garbage.
func sampleInput(t *testing.T) string {
	t.Helper()
	lines := []string{
		stderrTimestamp + " OCSF NET:OPEN [MED] DENIED github.com:443",
		stderrLine(netLine(t, netSpec{class: ClassNetworkActivity, uid: sandboxAUID, name: "docs-deny", denied: true, detail: "transparent_tcp_policy_denied", domain: "github.com", timeMs: sampleBaseMs + 1000})),
		stderrLine(netLine(t, netSpec{class: ClassNetworkActivity, uid: sandboxAUID, name: "docs-deny", domain: "api.github.com", timeMs: sampleBaseMs + 2000})),
		netLine(t, netSpec{class: ClassHTTPActivity, name: sandboxBName, domain: "api.github.com", timeMs: sampleBaseMs + 3000}),
		netLine(t, netSpec{class: ClassHTTPActivity, name: sandboxBName, statusID: 2, domain: "api.github.com", timeMs: sampleBaseMs + 4000}),
		netLine(t, netSpec{class: ClassNetworkActivity, uid: "unknown-uid", name: "unknown", domain: "example.com", timeMs: sampleBaseMs + 5000}),
		netLine(t, netSpec{class: ClassNetworkActivity, domain: "example.com", timeMs: sampleBaseMs + 6000}),
		"",
		"garbage",
		findingLine(t, sandboxAUID, 3, sampleBaseMs+7000),
	}
	return strings.Join(lines, "\n") + "\n"
}

func decodeBatch(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var req struct {
		Observations []map[string]any `json:"observations"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	return req.Observations
}

func TestRunEndToEnd(t *testing.T) {
	t.Parallel()
	sink := &fakeSink{}
	opts := Options{
		Agents:      sampleAgents(t),
		Signals:     DefaultSignalConfig(),
		AIMID:       sampleAIMID,
		EvidenceURL: sampleEvidURL,
		Clock:       fixedClock,
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	report, err := Run(t.Context(), strings.NewReader(sampleInput(t)), sink, opts, logger)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	wantWindow := Window{Start: time.UnixMilli(sampleBaseMs + 1000).UTC(), End: time.UnixMilli(sampleBaseMs + 7000).UTC()}
	want := Report{
		Parse:        ParseStats{Lines: 10, Events: 7, Skipped: 3},
		Attributed:   5,
		Unmapped:     2,
		NoContainer:  1,
		Window:       wantWindow,
		Observations: 4,
		Posted:       true,
		Agents: []AgentSummary{
			{AgentID: "agent-a", AnsName: "ans://v1.0.0.a.example.com", Events: 3, Denied: 1, Observations: 2},
			{AgentID: "agent-b", AnsName: "ans://v1.0.0.b.example.com", Events: 2, Denied: 1, Observations: 2},
		},
	}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("Report = %+v\nwant     %+v", report, want)
	}
	if len(sink.batches) != 1 {
		t.Fatalf("sink received %d batches, want 1", len(sink.batches))
	}
	batch := sink.batches[0]
	if batch.Signature != "" || len(batch.Observations) != 4 {
		t.Fatalf("batch = %+v", batch)
	}
	rows := decodeBatch(t, batch.Body)
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	wantObservedAt := wantWindow.End.Format(time.RFC3339)
	wantRows := []struct{ agent, signal string }{
		{"agent-a", DefaultPolicyViolationRateSignal}, {"agent-a", DefaultProtocolAdherenceSignal},
		{"agent-b", DefaultPolicyViolationRateSignal}, {"agent-b", DefaultProtocolAdherenceSignal},
	}
	for i, row := range rows {
		if row["agentId"] != wantRows[i].agent || row["signalId"] != wantRows[i].signal || row["observedAt"] != wantObservedAt {
			t.Fatalf("rows[%d] = %v, want %+v at %s", i, row, wantRows[i], wantObservedAt)
		}
		if !reflect.DeepEqual(row["provenance"], map[string]any{"aimId": sampleAIMID, "evidenceUrl": sampleEvidURL}) {
			t.Fatalf("rows[%d].provenance = %v", i, row["provenance"])
		}
	}
	valueA, _ := rows[0]["value"].(map[string]any)
	if valueA["total"] != 2.0 || valueA["denied"] != 1.0 || valueA["rate"] != 0.5 || valueA["destinations"] != 2.0 {
		t.Fatalf("agent-a value = %v", valueA)
	}
	if !reflect.DeepEqual(valueA["findings"], map[string]any{"3": 1.0}) || !reflect.DeepEqual(valueA["denyReasons"], map[string]any{"transparent_tcp_policy_denied": 1.0}) {
		t.Fatalf("agent-a value = %v", valueA)
	}
	valueB, _ := rows[2]["value"].(map[string]any)
	if !reflect.DeepEqual(valueB["classes"], map[string]any{"4001": 0.0, "4002": 2.0}) || !reflect.DeepEqual(valueB["denyReasons"], map[string]any{"unspecified": 1.0}) {
		t.Fatalf("agent-b value = %v", valueB)
	}
	for _, want := range []string{"input parsed", "events without an agent mapping were skipped", "unmapped=2", "no_container=1", "observations posted", "observations=4"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs missing %q:\n%s", want, logs.String())
		}
	}
}

func TestRunSignsBatch(t *testing.T) {
	t.Parallel()
	id := testfixtures.MustNewIdentity("agent-signing", "ans://v1.0.0.platform.example.com")
	signer, err := provenance.NewPEMSigner(id.KeyPEM, id.CertPEM)
	if err != nil {
		t.Fatalf("NewPEMSigner() error = %v", err)
	}
	sink := &fakeSink{}
	opts := Options{Agents: sampleAgents(t), Signals: DefaultSignalConfig(), AIMID: sampleAIMID, Signer: signer, Clock: fixedClock}

	report, err := Run(t.Context(), strings.NewReader(sampleInput(t)), sink, opts, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !report.Signed || !report.Posted {
		t.Fatalf("Report = %+v, want signed and posted", report)
	}
	batch := sink.batches[0]
	claims, cert, err := provenance.Verify(batch.Signature, batch.Body)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Count != 4 || claims.AIMID != sampleAIMID || claims.IssuedAt != fixedClock().Unix() {
		t.Fatalf("claims = %+v", claims)
	}
	if !cert.Equal(signer.Certificate()) {
		t.Fatal("signature carries a different certificate")
	}
	if _, _, err := provenance.Verify(batch.Signature, append(batch.Body, ' ')); !errors.Is(err, provenance.ErrBadSignature) {
		t.Fatalf("Verify() over a modified body = %v, want ErrBadSignature", err)
	}
}

func TestRunWithoutObservations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		agents     AgentMap
		signals    SignalConfig
		wantReport Report
	}{
		{
			name:       "empty input",
			agents:     AgentMap{},
			signals:    DefaultSignalConfig(),
			wantReport: Report{Window: Window{Start: fixedClock(), End: fixedClock()}, Agents: []AgentSummary{}},
		},
		{
			name:    "only unmapped events",
			input:   allowedExampleJSON + "\n" + deniedExampleJSON + "\n",
			agents:  AgentMap{},
			signals: DefaultSignalConfig(),
			wantReport: Report{
				Parse:       ParseStats{Lines: 2, Events: 2},
				Unmapped:    2,
				NoContainer: 1,
				Window:      Window{Start: time.UnixMilli(allowedExampleTime).UTC(), End: time.UnixMilli(deniedExampleTime).UTC()},
				Agents:      []AgentSummary{},
			},
		},
		{
			name:    "mapped process event under the default signals",
			input:   `{"class_uid":1007,"container":{"uid":"sb"},"time":1000}` + "\n",
			agents:  mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"sb"}}),
			signals: DefaultSignalConfig(),
			wantReport: Report{
				Parse:      ParseStats{Lines: 1, Events: 1},
				Attributed: 1,
				Window:     Window{Start: time.UnixMilli(1000).UTC(), End: time.UnixMilli(1000).UTC()},
				Agents:     []AgentSummary{{AgentID: "a", Events: 1}},
			},
		},
		{
			name:    "no signals selected",
			input:   `{"class_uid":4001,"container":{"uid":"sb"}}` + "\n",
			agents:  mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"sb"}}),
			signals: SignalConfig{},
			wantReport: Report{
				Parse:      ParseStats{Lines: 1, Events: 1},
				Attributed: 1,
				Window:     Window{Start: fixedClock(), End: fixedClock()},
				Agents:     []AgentSummary{{AgentID: "a", Events: 1}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sink := &fakeSink{}
			report, err := Run(t.Context(), strings.NewReader(tt.input), sink, Options{Agents: tt.agents, Signals: tt.signals, Clock: fixedClock}, nil)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if !reflect.DeepEqual(report, tt.wantReport) {
				t.Fatalf("Report = %+v\nwant     %+v", report, tt.wantReport)
			}
			if len(sink.batches) != 0 {
				t.Fatalf("sink received %d batches, want none", len(sink.batches))
			}
		})
	}
}

func TestRunMappedAgentWithoutObservationsStillSummarized(t *testing.T) {
	t.Parallel()
	sink := &fakeSink{}
	opts := Options{Agents: mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"sb"}}), Clock: fixedClock}
	report, err := Run(t.Context(), strings.NewReader(`{"class_uid":4001,"container":{"uid":"sb"},"time":1000}`+"\n"), sink, opts, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Observations != 0 || report.Posted || report.Attributed != 1 || len(report.Agents) != 1 || report.Agents[0].Events != 1 || report.Agents[0].Observations != 0 {
		t.Fatalf("Report = %+v", report)
	}
}

func TestRunExplicitWindow(t *testing.T) {
	t.Parallel()
	window := Window{Start: time.UnixMilli(sampleBaseMs + 2000).UTC(), End: time.UnixMilli(sampleBaseMs + 4000).UTC()}
	sink := &fakeSink{}
	opts := Options{Agents: sampleAgents(t), Signals: DefaultSignalConfig(), Window: &window, Clock: fixedClock}

	report, err := Run(t.Context(), strings.NewReader(sampleInput(t)), sink, opts, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.OutOfWindow != 4 || report.Unmapped != 0 || report.Attributed != 3 || report.Window != window || report.Observations != 4 {
		t.Fatalf("Report = %+v", report)
	}
	if report.Agents[0].Events != 1 || report.Agents[1].Events != 2 {
		t.Fatalf("Agents = %+v", report.Agents)
	}
	rows := decodeBatch(t, sink.batches[0].Body)
	if rows[0]["observedAt"] != window.End.Format(time.RFC3339) {
		t.Fatalf("observedAt = %v, want window end", rows[0]["observedAt"])
	}
	value, _ := rows[0]["value"].(map[string]any)
	if value["windowStart"] != window.Start.Format(time.RFC3339) || value["windowEnd"] != window.End.Format(time.RFC3339) {
		t.Fatalf("value window = %v/%v", value["windowStart"], value["windowEnd"])
	}
}

func TestRunSignalSubset(t *testing.T) {
	t.Parallel()
	sink := &fakeSink{}
	opts := Options{
		Agents:  sampleAgents(t),
		Signals: SignalConfig{EmitProtocolAdherence: true, ProtocolAdherenceID: "custom.adherence"},
		Clock:   fixedClock,
	}
	report, err := Run(t.Context(), strings.NewReader(sampleInput(t)), sink, opts, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Observations != 2 {
		t.Fatalf("Observations = %d, want 2", report.Observations)
	}
	for _, row := range decodeBatch(t, sink.batches[0].Body) {
		if row["signalId"] != "custom.adherence" {
			t.Fatalf("row = %v", row)
		}
		if _, present := row["provenance"]; present {
			t.Fatalf("provenance present without aim id or evidence: %v", row)
		}
	}
}

func TestRunFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name     string
		ctx      context.Context
		in       io.Reader
		sink     Sink
		wantErr  error
		wantMsg  string
		check    func(t *testing.T, report Report)
		wantPost bool
	}{
		{
			name: "sink error", ctx: t.Context(), in: strings.NewReader(sampleInput(t)), sink: &fakeSink{err: boom}, wantErr: boom,
			check: func(t *testing.T, report Report) {
				if report.Posted || report.Observations != 4 {
					t.Fatalf("Report = %+v", report)
				}
			},
		},
		{
			name: "reader error", ctx: t.Context(), in: io.MultiReader(strings.NewReader(sampleInput(t)), iotest.ErrReader(boom)), sink: &fakeSink{}, wantErr: boom,
			check: func(t *testing.T, report Report) {
				if report.Parse.Events != 7 || report.Posted || report.Observations != 0 {
					t.Fatalf("Report = %+v", report)
				}
			},
		},
		{name: "context cancelled", ctx: cancelled, in: strings.NewReader(sampleInput(t)), sink: &fakeSink{}, wantErr: context.Canceled},
		{name: "nil input", ctx: t.Context(), sink: &fakeSink{}, wantMsg: "input and sink are required"},
		{name: "nil sink", ctx: t.Context(), in: strings.NewReader(""), wantMsg: "input and sink are required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			report, err := Run(tt.ctx, tt.in, tt.sink, Options{Agents: sampleAgents(t), Signals: DefaultSignalConfig(), Clock: fixedClock}, nil)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantMsg)) {
				t.Fatalf("Run() error = %v, want containing %q", err, tt.wantMsg)
			}
			if fs, ok := tt.sink.(*fakeSink); ok && len(fs.batches) != 0 {
				t.Fatalf("sink received %d batches, want none", len(fs.batches))
			}
			if tt.check != nil {
				tt.check(t, report)
			}
		})
	}
}

func TestRunWarnsWhenEveryEventIsOutsideTheWindow(t *testing.T) {
	t.Parallel()
	window := Window{Start: time.UnixMilli(sampleBaseMs + 60_000).UTC(), End: time.UnixMilli(sampleBaseMs + 120_000).UTC()}
	var logs bytes.Buffer
	sink := &fakeSink{}
	opts := Options{Agents: sampleAgents(t), Signals: DefaultSignalConfig(), Window: &window, Clock: fixedClock}
	report, err := Run(t.Context(), strings.NewReader(sampleInput(t)), sink, opts, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.OutOfWindow != report.Parse.Events || report.Attributed != 0 || len(sink.batches) != 0 {
		t.Fatalf("Report = %+v, batches = %d", report, len(sink.batches))
	}
	if !strings.Contains(logs.String(), "every event fell outside the window") {
		t.Fatalf("missing out-of-window warning:\n%s", logs.String())
	}
}
