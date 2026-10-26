package hydrator

import (
	"errors"
	"math"
)

// Unavailable reasons recorded in ActivityEvidence.Unavailable.
const (
	activityIncomplete          = "interpretation_incomplete"
	activityDedupSaturated      = "dedup_saturated"
	activityUnreadableRecords   = "unreadable_audit_records"
	activityInsufficientSample  = "insufficient_sample"
	activityNoEligibleDecisions = "no_eligible_decisions"
)

// activityDNSRefused is the diagnostic that feeds the DNS-to-TCP denial
// coverage check, so producer and consumer must agree on it.
const activityDNSRefused = "dns_refused"

const (
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

// Denied returns the denied policy decisions across all measurement groups.
func (m ActivityMeasurements) Denied() int {
	return m.sum(func(counts DecisionCounts) int { return counts.Denied })
}

// Audited returns the audited policy decisions across all measurement groups.
func (m ActivityMeasurements) Audited() int {
	return m.sum(func(counts DecisionCounts) int { return counts.Audited })
}

func (m ActivityMeasurements) sum(count func(DecisionCounts) int) int {
	total := 0
	for _, counts := range m.groups() {
		total += count(counts)
	}
	return total
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
				return nil, activityInsufficientSample, sample
			}
			continue
		}
		eligible = true
		lowest = min(lowest, fullAdherence*float64(counts.Allowed)/float64(n))
	}
	if !eligible {
		return nil, activityNoEligibleDecisions, sample
	}
	score := int(math.Round(lowest))
	return &score, "", sample
}
