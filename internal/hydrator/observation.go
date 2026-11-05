package hydrator

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Default Trust Index signal identifiers. They are not yet registered in the
// Trust Index; see the package documentation.
const (
	DefaultPolicyViolationRateSignal = "openshell.policyViolationRate"
	DefaultProtocolAdherenceSignal   = "openshell.protocolAdherence"
)

// SignalConfig names the signals observations are posted under and selects
// which to emit. Empty identifiers take the defaults.
type SignalConfig struct {
	ActivityID              string
	EmitActivity            bool
	PolicyViolationRateID   string
	ProtocolAdherenceID     string
	EmitPolicyViolationRate bool
	EmitProtocolAdherence   bool
}

// DefaultSignalConfig emits both signals under their default identifiers.
func DefaultSignalConfig() SignalConfig {
	return SignalConfig{
		PolicyViolationRateID:   DefaultPolicyViolationRateSignal,
		ProtocolAdherenceID:     DefaultProtocolAdherenceSignal,
		EmitPolicyViolationRate: true,
		EmitProtocolAdherence:   true,
	}
}

func (c SignalConfig) withDefaults() SignalConfig {
	if c.ActivityID == "" {
		c.ActivityID = DefaultActivitySignal
	}
	if c.PolicyViolationRateID == "" {
		c.PolicyViolationRateID = DefaultPolicyViolationRateSignal
	}
	if c.ProtocolAdherenceID == "" {
		c.ProtocolAdherenceID = DefaultProtocolAdherenceSignal
	}
	return c
}

// Observation is one row of the Trust Index import request.
type Observation struct {
	AgentID    string          `json:"agentId"`
	SignalID   string          `json:"signalId"`
	ObservedAt string          `json:"observedAt"`
	Value      json.RawMessage `json:"value"`
	Provenance *Provenance     `json:"provenance,omitempty"`
}

// Provenance identifies the producer of an observation.
type Provenance struct {
	AIMID       string `json:"aimId,omitempty"`
	EvidenceURL string `json:"evidenceUrl,omitempty"`
}

type importRequest struct {
	Observations []Observation `json:"observations"`
}

// PolicyViolationRateValue is the value of the policy violation rate signal:
// the share of network and HTTP events in the window that were denied, with
// the deny reasons, per-class counts, distinct destinations and detection
// findings by severity that explain it.
type PolicyViolationRateValue struct {
	WindowStart  string         `json:"windowStart"`
	WindowEnd    string         `json:"windowEnd"`
	Total        int            `json:"total"`
	Denied       int            `json:"denied"`
	Rate         float64        `json:"rate"`
	DenyReasons  map[string]int `json:"denyReasons"`
	Classes      map[string]int `json:"classes"`
	Destinations int            `json:"destinations"`
	Findings     map[string]int `json:"findings"`
}

// ProtocolAdherenceValue is the value of the protocol adherence signal: one
// minus the policy violation rate, with the sample size it rests on.
type ProtocolAdherenceValue struct {
	WindowStart string  `json:"windowStart"`
	WindowEnd   string  `json:"windowEnd"`
	Total       int     `json:"total"`
	Adherence   float64 `json:"adherence"`
	SampleSize  int     `json:"sampleSize"`
}

// ActivityScoreValue is the value of the activity signal: the generic numeric
// score format of the Trust Index reference implementation. It carries no
// provider risk codes.
type ActivityScoreValue struct {
	Score       int    `json:"score"`
	Explanation string `json:"explanation"`
}

func newProvenance(aimID, evidenceURL string) *Provenance {
	if aimID == "" && evidenceURL == "" {
		return nil
	}
	return &Provenance{AIMID: aimID, EvidenceURL: evidenceURL}
}

type observationBuilder struct {
	signals    SignalConfig
	provenance *Provenance
	window     Window
}

// build returns the agent's observations for the window. An agent with no
// network or HTTP activity yields none: a rate over zero events would read as
// perfect adherence.
func (b observationBuilder) build(st *agentStats) ([]Observation, error) {
	if st.total == 0 {
		return nil, nil
	}
	var out []Observation
	if b.signals.EmitPolicyViolationRate {
		obs, err := b.observation(st.mapping.AgentID, b.signals.PolicyViolationRateID, b.policyViolationRate(st))
		if err != nil {
			return nil, err
		}
		out = append(out, obs)
	}
	if b.signals.EmitProtocolAdherence {
		obs, err := b.observation(st.mapping.AgentID, b.signals.ProtocolAdherenceID, b.protocolAdherence(st))
		if err != nil {
			return nil, err
		}
		out = append(out, obs)
	}
	return out, nil
}

func (b observationBuilder) observation(agentID, signalID string, value any) (Observation, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Observation{}, fmt.Errorf("hydrator: encode %s for agent %s: %w", signalID, agentID, err)
	}
	return Observation{
		AgentID:    agentID,
		SignalID:   signalID,
		ObservedAt: formatTime(b.window.End),
		Value:      raw,
		Provenance: b.provenance,
	}, nil
}

// activity returns the activity observation for evidence that carries a score.
func (b observationBuilder) activity(agentID string, evidence ActivityEvidence) (Observation, error) {
	if evidence.Score == nil {
		return Observation{}, fmt.Errorf("hydrator: activity evidence for agent %s has no score", agentID)
	}
	value := ActivityScoreValue{Score: *evidence.Score, Explanation: activityExplanation(evidence)}
	return b.observation(agentID, b.signals.ActivityID, value)
}

func (b observationBuilder) policyViolationRate(st *agentStats) PolicyViolationRateValue {
	return PolicyViolationRateValue{
		WindowStart:  formatTime(b.window.Start),
		WindowEnd:    formatTime(b.window.End),
		Total:        st.total,
		Denied:       st.denied,
		Rate:         st.rate(),
		DenyReasons:  cloneCounts(st.denyReasons),
		Classes:      stringKeys(st.classes),
		Destinations: len(st.destinations),
		Findings:     stringKeys(st.findings),
	}
}

func (b observationBuilder) protocolAdherence(st *agentStats) ProtocolAdherenceValue {
	return ProtocolAdherenceValue{
		WindowStart: formatTime(b.window.Start),
		WindowEnd:   formatTime(b.window.End),
		Total:       st.total,
		Adherence:   1 - st.rate(),
		SampleSize:  st.total,
	}
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func cloneCounts(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringKeys(in map[int]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[strconv.Itoa(k)] = v
	}
	return out
}
