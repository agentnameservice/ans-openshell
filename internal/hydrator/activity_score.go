package hydrator

import (
	"errors"
	"math"
)

const (
	activityIncomplete     = "interpretation_incomplete"
	activityDedupSaturated = "dedup_saturated"
	activityOther          = "other"
	defaultMinDecisions    = 1
	defaultMaxUIDsPerAgent = 100_000
	defaultMaxUIDs         = 1_000_000
	fullAdherence          = 100
)

// Validate rejects invalid explicitly configured limits. Zero selects defaults.
func (c ActivityConfig) Validate() error {
	if c.MinDecisions < 0 || c.MaxUIDsPerAgent < 0 || c.MaxUIDs < 0 {
		return errors.New("hydrator: activity sample minimum and UID limits must be positive")
	}
	return nil
}

func (c ActivityConfig) withDefaults() ActivityConfig {
	if c.MinDecisions == 0 {
		c.MinDecisions = defaultMinDecisions
	}
	if c.MaxUIDsPerAgent == 0 {
		c.MaxUIDsPerAgent = defaultMaxUIDsPerAgent
	}
	if c.MaxUIDs == 0 {
		c.MaxUIDs = defaultMaxUIDs
	}
	return c
}

func (m ActivityMeasurements) groups() []DecisionCounts {
	return []DecisionCounts{m.HTTPInitial, m.PostRewriteEvaluations, m.WebSocketEvaluations, m.Connections}
}

func assessActivity(m ActivityMeasurements, minimum int, unavailable string) (*int, string, int) {
	sample := 0
	for _, counts := range m.groups() {
		sample += counts.Allowed + counts.Denied + counts.Audited
		if counts.Unknown > 0 && unavailable == "" {
			unavailable = activityIncomplete
		}
	}
	if unavailable != "" {
		return nil, unavailable, sample
	}
	lowest := float64(fullAdherence)
	eligible := false
	for _, counts := range m.groups() {
		n := counts.Allowed + counts.Denied + counts.Audited
		if n == 0 {
			continue
		}
		if n < minimum {
			if counts.Denied+counts.Audited > 0 {
				return nil, "insufficient_sample", sample
			}
			continue
		}
		eligible = true
		lowest = min(lowest, fullAdherence*float64(counts.Allowed)/float64(n))
	}
	if !eligible {
		return nil, "no_eligible_decisions", sample
	}
	score := int(math.Round(lowest))
	return &score, "", sample
}
