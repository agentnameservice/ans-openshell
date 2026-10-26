package hydrator

import "time"

// DefaultActivitySignal is the opt-in generic provider score signal.
const DefaultActivitySignal = "openshell.behavior.activity"

// ActivityConfig bounds the corrected evidence path. Zero values select defaults.
type ActivityConfig struct {
	MinDecisions    int
	MaxUIDsPerAgent int
	MaxUIDs         int
}

// DecisionCounts reports policy decisions for one enforcement phase.
type DecisionCounts struct {
	Allowed int `json:"allowed"`
	Denied  int `json:"denied"`
	Audited int `json:"audited"`
	Unknown int `json:"unknown"`
}

// ActivityMeasurements keeps different policy-check units separate.
type ActivityMeasurements struct {
	HTTPInitial            DecisionCounts `json:"httpInitial"`
	PostRewriteEvaluations DecisionCounts `json:"postRewriteEvaluations"`
	WebSocketEvaluations   DecisionCounts `json:"websocketEvaluations"`
	Connections            DecisionCounts `json:"connections"`
}

// ActivityFinding preserves source and occurrence counts without scoring findings.
type ActivityFinding struct {
	Origin        string `json:"origin"`
	Middleware    string `json:"middleware,omitempty"`
	Type          string `json:"type"`
	Severity      int    `json:"severity"`
	Records       int    `json:"records"`
	Occurrences   int64  `json:"occurrences"`
	InvalidCounts int    `json:"invalidCounts,omitempty"`
}

// PolicyContext identifies an observed sandbox/hash/version. ObservedAt is its
// earliest recorded load in the input, not a complete policy-activation timeline.
type PolicyContext struct {
	Sandbox    string    `json:"sandbox"`
	Hash       string    `json:"hash,omitempty"`
	Version    string    `json:"version,omitempty"`
	ObservedAt time.Time `json:"observedAt"`
}

// ActivityEvidence is local structured evidence, not a Trust Index value schema.
type ActivityEvidence struct {
	SchemaVersion  int                  `json:"schemaVersion"`
	AgentID        string               `json:"agentId"`
	WindowStart    string               `json:"windowStart"`
	WindowEnd      string               `json:"windowEnd"`
	Measurements   ActivityMeasurements `json:"measurements"`
	ReportedStatus map[string]int       `json:"reportedStatus"`
	SourceVersions map[string]int       `json:"sourceVersions"`
	FirstEventAt   string               `json:"firstEventAt,omitempty"`
	LastEventAt    string               `json:"lastEventAt,omitempty"`
	Findings       []ActivityFinding    `json:"findings"`
	Diagnostics    map[string]int       `json:"diagnostics"`
	Policies       []PolicyContext      `json:"policies"`
	PolicyUnknown  bool                 `json:"policyUnknown"`
	SampleSize     int                  `json:"sampleSize"`
	Score          *int                 `json:"score"`
	Unavailable    string               `json:"unavailableReason,omitempty"`
}

// Degraded reports whether the score was withheld because the agent's records
// could not be interpreted or counted, as opposed to there being too few
// policy decisions to measure.
func (e ActivityEvidence) Degraded() bool {
	switch e.Unavailable {
	case "", activityInsufficientSample, activityNoEligibleDecisions:
		return false
	default:
		return true
	}
}
