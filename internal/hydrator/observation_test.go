package hydrator

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return m
}

func TestObservationValuesGolden(t *testing.T) {
	t.Parallel()
	agg := newAggregator(mustAgentMap(t, AgentMapping{AgentID: "agent-a", SandboxUIDs: []string{"sb"}}), nil)
	for _, ev := range []Event{
		netEvent(ClassNetworkActivity, "sb", false, "", "api.github.com", "", 1000),
		netEvent(ClassNetworkActivity, "sb", true, "transparent_tcp_policy_denied", "github.com", "", 2000),
		{ClassUID: ClassHTTPActivity, Container: &Container{UID: "sb"}, StatusID: deniedID, DstEndpoint: &Endpoint{Domain: "api.github.com"}, Time: 3000},
		netEvent(ClassHTTPActivity, "sb", false, "", "", "198.18.0.2", 4000),
		{ClassUID: ClassDetectionFinding, Container: &Container{UID: "sb"}, SeverityID: 3},
		{ClassUID: ClassDetectionFinding, Container: &Container{UID: "sb"}, SeverityID: 5},
	} {
		agg.add(ev)
	}
	window := agg.resolveWindow(time.Time{})
	provenance := newProvenance("ans://v1.0.0.ops.example.com", "https://evidence.example/run/1")
	b := observationBuilder{signals: DefaultSignalConfig(), provenance: provenance, window: window}

	obs, err := b.build(agg.stats["agent-a"])
	if err != nil {
		t.Fatalf("build() error = %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("len(obs) = %d, want 2", len(obs))
	}
	for i, want := range []string{DefaultPolicyViolationRateSignal, DefaultProtocolAdherenceSignal} {
		if obs[i].SignalID != want || obs[i].AgentID != "agent-a" || obs[i].ObservedAt != "1970-01-01T00:00:04Z" {
			t.Fatalf("obs[%d] = %+v", i, obs[i])
		}
		if obs[i].Provenance != provenance {
			t.Fatalf("obs[%d].Provenance = %+v", i, obs[i].Provenance)
		}
	}
	wantRate := map[string]any{
		"windowStart":  "1970-01-01T00:00:01Z",
		"windowEnd":    "1970-01-01T00:00:04Z",
		"total":        4.0,
		"denied":       2.0,
		"rate":         0.5,
		"denyReasons":  map[string]any{"transparent_tcp_policy_denied": 1.0, "unspecified": 1.0},
		"classes":      map[string]any{"4001": 2.0, "4002": 2.0},
		"destinations": 3.0,
		"findings":     map[string]any{"3": 1.0, "5": 1.0},
	}
	if got := decodeJSON(t, obs[0].Value); !reflect.DeepEqual(got, wantRate) {
		t.Fatalf("policyViolationRate value = %v, want %v", got, wantRate)
	}
	wantAdherence := map[string]any{
		"windowStart": "1970-01-01T00:00:01Z",
		"windowEnd":   "1970-01-01T00:00:04Z",
		"total":       4.0,
		"adherence":   0.5,
		"sampleSize":  4.0,
	}
	if got := decodeJSON(t, obs[1].Value); !reflect.DeepEqual(got, wantAdherence) {
		t.Fatalf("protocolAdherence value = %v, want %v", got, wantAdherence)
	}
}

func TestObservationValuesWithoutTraffic(t *testing.T) {
	t.Parallel()
	st := newAgentStats(AgentMapping{AgentID: "agent-quiet"})
	st.events = 1
	st.findings[3]++
	b := observationBuilder{signals: DefaultSignalConfig(), window: Window{Start: time.Unix(1, 0), End: time.Unix(1, 0)}}
	obs, err := b.build(st)
	if err != nil {
		t.Fatalf("build() error = %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("build() emitted %d observations for an agent with no network or HTTP activity, want none", len(obs))
	}
}

func TestObservationBuilderSignalSelection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		signals SignalConfig
		wantIDs []string
	}{
		{name: "none", signals: SignalConfig{}},
		{name: "rate only, custom id", signals: SignalConfig{EmitPolicyViolationRate: true, PolicyViolationRateID: "custom.rate"}, wantIDs: []string{"custom.rate"}},
		{name: "adherence only, default id", signals: SignalConfig{EmitProtocolAdherence: true}, wantIDs: []string{DefaultProtocolAdherenceSignal}},
		{name: "both", signals: DefaultSignalConfig(), wantIDs: []string{DefaultPolicyViolationRateSignal, DefaultProtocolAdherenceSignal}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := newAgentStats(AgentMapping{AgentID: "a"})
			st.add(netEvent(ClassNetworkActivity, "", false, "", "h", "", 0))
			b := observationBuilder{signals: tt.signals.withDefaults()}
			obs, err := b.build(st)
			if err != nil {
				t.Fatalf("build() error = %v", err)
			}
			var ids []string
			for _, o := range obs {
				ids = append(ids, o.SignalID)
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Fatalf("signal ids = %v, want %v", ids, tt.wantIDs)
			}
		})
	}
}

func TestSignalConfigDefaults(t *testing.T) {
	t.Parallel()
	def := DefaultSignalConfig()
	if !def.EmitPolicyViolationRate || !def.EmitProtocolAdherence {
		t.Fatalf("DefaultSignalConfig() = %+v, want both signals emitted", def)
	}
	if def.PolicyViolationRateID != "openshell.policyViolationRate" || def.ProtocolAdherenceID != "openshell.protocolAdherence" {
		t.Fatalf("DefaultSignalConfig() ids = %+v", def)
	}
	custom := SignalConfig{PolicyViolationRateID: "x", ProtocolAdherenceID: "y"}.withDefaults()
	if custom.PolicyViolationRateID != "x" || custom.ProtocolAdherenceID != "y" {
		t.Fatalf("withDefaults() overwrote custom ids: %+v", custom)
	}
	filled := SignalConfig{}.withDefaults()
	if filled.PolicyViolationRateID != def.PolicyViolationRateID || filled.ProtocolAdherenceID != def.ProtocolAdherenceID {
		t.Fatalf("withDefaults() = %+v", filled)
	}
}

func TestNewProvenance(t *testing.T) {
	t.Parallel()
	if p := newProvenance("", ""); p != nil {
		t.Fatalf("newProvenance(\"\", \"\") = %+v, want nil", p)
	}
	if p := newProvenance("did:web:ops.example.com", ""); p == nil || p.AIMID != "did:web:ops.example.com" || p.EvidenceURL != "" {
		t.Fatalf("newProvenance(aim) = %+v", p)
	}
	if p := newProvenance("", "https://e"); p == nil || p.EvidenceURL != "https://e" {
		t.Fatalf("newProvenance(evidence) = %+v", p)
	}
}

func TestBatchBodyWireShape(t *testing.T) {
	t.Parallel()
	st := newAgentStats(AgentMapping{AgentID: "agent-a"})
	st.add(netEvent(ClassNetworkActivity, "", false, "", "h", "", 1000))
	window := Window{Start: time.UnixMilli(1000), End: time.UnixMilli(1000)}

	t.Run("with provenance", func(t *testing.T) {
		t.Parallel()
		b := observationBuilder{signals: SignalConfig{EmitPolicyViolationRate: true}.withDefaults(), provenance: newProvenance("aim", "https://e"), window: window}
		obs, err := b.build(st)
		if err != nil {
			t.Fatalf("build() error = %v", err)
		}
		batch, err := newBatch(obs, Options{}, time.Time{})
		if err != nil {
			t.Fatalf("newBatch() error = %v", err)
		}
		body := decodeJSON(t, batch.Body)
		if len(body) != 1 {
			t.Fatalf("body keys = %v, want only observations", body)
		}
		rows, ok := body["observations"].([]any)
		if !ok || len(rows) != 1 {
			t.Fatalf("observations = %v", body["observations"])
		}
		row, _ := rows[0].(map[string]any)
		wantKeys := map[string]bool{"agentId": true, "signalId": true, "observedAt": true, "value": true, "provenance": true}
		for k := range row {
			if !wantKeys[k] {
				t.Fatalf("unexpected row key %q in %v", k, row)
			}
		}
		if len(row) != len(wantKeys) {
			t.Fatalf("row = %v, want keys %v", row, wantKeys)
		}
		if row["agentId"] != "agent-a" || row["signalId"] != DefaultPolicyViolationRateSignal || row["observedAt"] != "1970-01-01T00:00:01Z" {
			t.Fatalf("row = %v", row)
		}
		if !reflect.DeepEqual(row["provenance"], map[string]any{"aimId": "aim", "evidenceUrl": "https://e"}) {
			t.Fatalf("provenance = %v", row["provenance"])
		}
		if batch.Signature != "" || len(batch.Observations) != 1 {
			t.Fatalf("batch = %+v", batch)
		}
	})
	t.Run("without provenance", func(t *testing.T) {
		t.Parallel()
		b := observationBuilder{signals: DefaultSignalConfig(), window: window}
		obs, err := b.build(st)
		if err != nil {
			t.Fatalf("build() error = %v", err)
		}
		batch, err := newBatch(obs, Options{}, time.Time{})
		if err != nil {
			t.Fatalf("newBatch() error = %v", err)
		}
		rows, _ := decodeJSON(t, batch.Body)["observations"].([]any)
		row, _ := rows[0].(map[string]any)
		if _, present := row["provenance"]; present {
			t.Fatalf("provenance present in %v", row)
		}
	})
}
