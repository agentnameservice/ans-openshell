package hydrator

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxActivityText    = 128
	maxActivityDetails = 256
	maxSourceVersions  = 32
)

type findingKey struct {
	origin, middleware, kind string
	severity                 int
}
type policyKey struct{ sandbox, hash, version string }
type destinationKey struct{ sandbox, destination string }
type denialCoverage struct{ dns, tcp int }

type activityStats struct {
	active         bool
	measurements   ActivityMeasurements
	reportedStatus map[string]int
	versions       map[string]int
	diagnostics    map[string]int
	findings       map[findingKey]ActivityFinding
	policies       map[policyKey]PolicyContext
	firstDecision  map[string]int64
	denialCoverage map[destinationKey]denialCoverage
	seen           map[string]struct{}
	unavailable    string
	policyUnknown  bool
	first, last    time.Time
}

func newActivityStats() *activityStats {
	return &activityStats{
		reportedStatus: map[string]int{}, versions: map[string]int{}, diagnostics: map[string]int{},
		findings: map[findingKey]ActivityFinding{}, policies: map[policyKey]PolicyContext{},
		firstDecision: map[string]int64{}, denialCoverage: map[destinationKey]denialCoverage{}, seen: map[string]struct{}{},
	}
}

type activityAggregator struct {
	agents    AgentMap
	window    *Window
	config    ActivityConfig
	stats     map[string]*activityStats
	totalUIDs int
}

func newActivityAggregator(agents AgentMap, window *Window, config ActivityConfig) *activityAggregator {
	return &activityAggregator{agents: agents, window: window, config: config.withDefaults(), stats: map[string]*activityStats{}}
}

func (a *activityAggregator) add(ev Event) {
	mapping, ok := a.agents.Lookup(ev)
	if !ok {
		return
	}
	st := a.stats[mapping.AgentID]
	if st == nil {
		st = newActivityStats()
		a.stats[mapping.AgentID] = st
	}
	// Policy load records can precede the selected traffic window and arrive out of order.
	if ev.ClassUID == ClassDeviceConfigChange {
		st.addPolicy(ev, a.window)
	}
	ts, hasTime := ev.Timestamp()
	if a.window != nil && (!hasTime || !a.window.Contains(ts)) {
		return
	}
	st.active = true
	if !a.acceptUID(st, ev.Metadata.UID) {
		return
	}
	st.observe(ev)
}

func (a *activityAggregator) acceptUID(st *activityStats, uid string) bool {
	if st.unavailable == activityDedupSaturated {
		st.diagnostics["after_dedup_saturation"]++
		return false
	}
	if uid == "" {
		st.diagnostics["missing_event_uid"]++
		return true
	}
	if _, duplicate := st.seen[uid]; duplicate {
		st.diagnostics["duplicate_events"]++
		return false
	}
	if len(uid) > maxActivityText {
		// An unbounded UID cannot be deduplicated within the memory budget.
		st.diagnostics["oversized_event_uid"]++
		if st.unavailable == "" {
			st.unavailable = activityIncomplete
		}
		return false
	}
	if len(st.seen) >= a.config.MaxUIDsPerAgent {
		a.saturate(st)
		return false
	}
	if a.totalUIDs >= a.config.MaxUIDs {
		owner := a.largestUIDOwner()
		if owner == nil {
			a.saturate(st)
			return false
		}
		a.saturate(owner)
		if owner == st {
			return false
		}
	}
	st.seen[uid] = struct{}{}
	a.totalUIDs++
	return true
}

func (a *activityAggregator) saturate(st *activityStats) {
	st.unavailable = activityDedupSaturated
	st.diagnostics[activityDedupSaturated]++
	a.totalUIDs -= len(st.seen)
	st.seen = nil
}

// Release the largest existing owner rather than starving every new agent.
// Lexical agent ID breaks ties, making the pressure policy deterministic.
func (a *activityAggregator) largestUIDOwner() *activityStats {
	var owner *activityStats
	ownerID := ""
	for id, candidate := range a.stats {
		if len(candidate.seen) == 0 {
			continue
		}
		if owner == nil || len(candidate.seen) > len(owner.seen) || len(candidate.seen) == len(owner.seen) && id < ownerID {
			owner, ownerID = candidate, id
		}
	}
	return owner
}

func (s *activityStats) observe(ev Event) {
	if ts, ok := ev.Timestamp(); ok {
		if s.first.IsZero() || ts.Before(s.first) {
			s.first = ts
		}
		if ts.After(s.last) {
			s.last = ts
		}
	}
	status := "unreported_or_unknown"
	if ev.StatusID != 0 {
		status = strconv.Itoa(ev.StatusID)
	}
	// OCSF statuses have a small enum; keep unexpected integers in one diagnostic bucket.
	if ev.StatusID < 0 || ev.StatusID > 99 {
		status = activityOther
	}
	s.reportedStatus[status]++
	version := boundedActivityText(ev.Metadata.Product.Version)
	if version == "" {
		version = "unreported"
	}
	if _, known := s.versions[version]; !known && len(s.versions) >= maxSourceVersions {
		version = activityOther
	}
	s.versions[version]++
	route := classifyActivity(ev)
	if route.Diagnostic != "" {
		s.diagnostics[route.Diagnostic]++
	}
	if route.AuditFallback {
		s.diagnostics["message_decision_fallback"]++
	}
	if route.Incomplete {
		s.unavailable = activityIncomplete
	}
	if route.Finding != nil {
		s.addFinding(*route.Finding)
	}
	if route.Group != "" {
		s.addDecision(route.Group, route.Decision)
		s.recordDecisionTime(ev)
	}
	if route.Diagnostic == activityDNSRefused || route.Group == groupConnections && route.Decision == decisionDenied {
		s.recordDenialCoverage(ev, route.Diagnostic == activityDNSRefused)
	}
}

func (s *activityStats) addDecision(group activityGroup, decision policyDecision) {
	var counts *DecisionCounts
	switch group {
	case groupHTTPInitial:
		counts = &s.measurements.HTTPInitial
	case groupPostRewrite:
		counts = &s.measurements.PostRewriteEvaluations
	case groupWebSocket:
		counts = &s.measurements.WebSocketEvaluations
	case groupConnections:
		counts = &s.measurements.Connections
	default:
		s.unavailable = activityIncomplete
		return
	}
	switch decision {
	case decisionAllowed:
		counts.Allowed++
	case decisionDenied:
		counts.Denied++
	case decisionAudited:
		counts.Audited++
	case decisionUnknown:
		counts.Unknown++
	default:
		counts.Unknown++
	}
}

func (s *activityStats) recordDecisionTime(ev Event) {
	sandbox := activitySandbox(ev)
	if len(sandbox) > maxActivityText {
		s.unavailable = activityIncomplete
		s.diagnostics["oversized_sandbox_id"]++
		return
	}
	if _, known := s.firstDecision[sandbox]; !known && len(s.firstDecision) >= maxActivityDetails {
		s.unavailable = activityIncomplete
		s.diagnostics["sandbox_limit"]++
		return
	}
	if ev.Time <= 0 {
		s.unavailable = activityIncomplete
		s.diagnostics["missing_decision_time"]++
		return
	}
	previous := s.firstDecision[sandbox]
	if previous == 0 || ev.Time < previous {
		s.firstDecision[sandbox] = ev.Time
	}
}

func (s *activityStats) recordDenialCoverage(ev Event, dns bool) {
	key := destinationKey{sandbox: activitySandbox(ev), destination: ev.Destination()}
	if len(key.sandbox) > maxActivityText || len(key.destination) > maxActivityFieldBytes {
		s.unavailable = activityIncomplete
		s.diagnostics["denial_coverage_limit"]++
		return
	}
	if _, known := s.denialCoverage[key]; !known && len(s.denialCoverage) >= maxActivityDetails {
		s.unavailable = activityIncomplete
		s.diagnostics["denial_coverage_limit"]++
		return
	}
	counts := s.denialCoverage[key]
	if dns {
		counts.dns++
	} else {
		counts.tcp++
	}
	s.denialCoverage[key] = counts
}

func (s *activityStats) addFinding(f ActivityFinding) {
	// The classifier already bounds these to maxActivityFieldBytes and reports
	// truncation. Preserve its full keys so distinct detectors are not merged.
	key := findingKey{origin: f.Origin, middleware: f.Middleware, kind: f.Type, severity: f.Severity}
	if _, known := s.findings[key]; !known && len(s.findings) >= maxActivityDetails {
		s.diagnostics["finding_detail_limit"]++
		key = findingKey{origin: activityOther, kind: activityOther}
		f.Origin, f.Middleware, f.Type, f.Severity = activityOther, "", activityOther, 0
	}
	previous := s.findings[key]
	f.Records += previous.Records
	f.InvalidCounts += previous.InvalidCounts
	if f.Occurrences > math.MaxInt64-previous.Occurrences {
		f.Occurrences = math.MaxInt64
		s.diagnostics["finding_count_overflow"]++
	} else {
		f.Occurrences += previous.Occurrences
	}
	s.findings[key] = f
}

func (s *activityStats) addPolicy(ev Event, window *Window) {
	ts, ok := ev.Timestamp()
	if !ok || window != nil && ts.After(window.End) {
		return
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(ev.Unmapped, &raw) != nil {
		return
	}
	var hash string
	if json.Unmarshal(raw["policy_hash"], &hash) != nil || hash == "" {
		return
	}
	version := ""
	if value := raw["version"]; json.Unmarshal(value, &version) != nil {
		var number json.Number
		if json.Unmarshal(value, &number) == nil {
			version = number.String()
		}
	}
	key := policyKey{sandbox: activitySandbox(ev), hash: hash, version: version}
	if len(key.sandbox) > maxActivityText || len(hash) > maxActivityText || len(version) > maxActivityText {
		s.policyUnknown = true
		s.diagnostics["policy_context_limit"]++
		return
	}
	if _, known := s.policies[key]; !known && len(s.policies) >= maxActivityDetails {
		s.policyUnknown = true
		s.diagnostics["policy_context_limit"]++
		return
	}
	// Earliest occurrence of a given policy establishes whether it covered the first decision.
	if previous, known := s.policies[key]; !known || ts.Before(previous.ObservedAt) {
		s.policies[key] = PolicyContext{Sandbox: key.sandbox, Hash: hash, Version: version, ObservedAt: ts}
	}
}

// evidence summarizes every active agent. It does not modify the aggregator,
// so repeated calls return the same result.
func (a *activityAggregator) evidence(window Window, input auditInputHealth) []ActivityEvidence {
	ids := make([]string, 0, len(a.stats))
	for id, st := range a.stats {
		if st.active {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	out := make([]ActivityEvidence, 0, len(ids))
	for _, id := range ids {
		out = append(out, a.stats[id].evidence(id, window, a.config.MinDecisions, input))
	}
	return out
}

// finalState returns the unavailable reason and diagnostics after the
// end-of-input checks, without changing the accumulated state. The first
// recorded reason wins, so a later check never hides an earlier one.
func (s *activityStats) finalState(input auditInputHealth) (string, map[string]int) {
	unavailable := s.unavailable
	diagnostics := maps.Clone(s.diagnostics)
	for key, counts := range s.denialCoverage {
		// This is only an aggregate coverage guard, never event pairing or unique-request reconstruction.
		if counts.dns > counts.tcp || counts.dns > 0 && key.destination == "" {
			unavailable = cmp.Or(unavailable, activityIncomplete)
			diagnostics["unrepresented_dns_refusals"] += counts.dns
		}
	}
	// An unreadable audit line cannot be attributed to an agent, so it withholds every new score.
	if input.unreadable > 0 {
		unavailable = cmp.Or(unavailable, activityUnreadableRecords)
		diagnostics[activityUnreadableRecords] = input.unreadable
	}
	// A final line without a newline is still being written; the next run reads it whole.
	if input.truncatedTail > 0 {
		diagnostics["truncated_final_line"] = input.truncatedTail
	}
	return unavailable, diagnostics
}

func (s *activityStats) evidence(id string, window Window, minimum int, input auditInputHealth) ActivityEvidence {
	unavailable, diagnostics := s.finalState(input)
	policies := make([]PolicyContext, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}
	slices.SortFunc(policies, func(a, b PolicyContext) int {
		return cmp.Or(cmp.Compare(a.Sandbox, b.Sandbox), a.ObservedAt.Compare(b.ObservedAt), cmp.Compare(a.Hash, b.Hash), cmp.Compare(a.Version, b.Version))
	})
	findings := make([]ActivityFinding, 0, len(s.findings))
	for _, f := range s.findings {
		findings = append(findings, f)
	}
	slices.SortFunc(findings, func(a, b ActivityFinding) int {
		return cmp.Or(cmp.Compare(a.Origin, b.Origin), cmp.Compare(a.Middleware, b.Middleware), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Severity, b.Severity))
	})
	score, reason, sample := assessActivity(s.measurements, minimum, unavailable)
	ev := ActivityEvidence{
		SchemaVersion:  1,
		AgentID:        id,
		WindowStart:    formatTime(window.Start),
		WindowEnd:      formatTime(window.End),
		Measurements:   s.measurements,
		ReportedStatus: maps.Clone(s.reportedStatus),
		SourceVersions: maps.Clone(s.versions),
		Findings:       findings,
		Diagnostics:    diagnostics,
		Policies:       policies,
		PolicyUnknown:  !s.hasPolicyContext(policies),
		PolicyChanged:  s.policyChanged(policies),
		SampleSize:     sample,
		Score:          score,
		Unavailable:    reason,
	}
	if !s.first.IsZero() {
		ev.FirstEventAt = formatTime(s.first)
		ev.LastEventAt = formatTime(s.last)
	}
	return ev
}

func (s *activityStats) hasPolicyContext(policies []PolicyContext) bool {
	if s.policyUnknown || len(s.firstDecision) == 0 {
		return false
	}
	for sandbox, first := range s.firstDecision {
		covered := slices.ContainsFunc(policies, func(p PolicyContext) bool {
			return p.Sandbox == sandbox && p.ObservedAt.UnixMilli() <= first
		})
		if !covered {
			return false
		}
	}
	return true
}

// policyChanged reports whether a sandbox loaded a policy after its first
// counted decision, so the counts may span more than one policy.
func (s *activityStats) policyChanged(policies []PolicyContext) bool {
	return slices.ContainsFunc(policies, func(p PolicyContext) bool {
		first, counted := s.firstDecision[p.Sandbox]
		return counted && p.ObservedAt.UnixMilli() > first
	})
}

func activitySandbox(ev Event) string {
	if ev.Container == nil {
		return ""
	}
	if ev.Container.UID != "" {
		return ev.Container.UID
	}
	return ev.Container.Name
}

func boundedActivityText(s string) string {
	if len(s) <= maxActivityText {
		return s
	}
	return strings.ToValidUTF8(s[:maxActivityText], "")
}

func activityExplanation(ev ActivityEvidence) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Policy adherence %d/100; window %s to %s; samples are policy evaluations by phase, not unique requests.", *ev.Score, ev.WindowStart, ev.WindowEnd)
	groups := []struct {
		name   string
		counts DecisionCounts
	}{
		{name: "httpInitial", counts: ev.Measurements.HTTPInitial},
		{name: "postRewrite", counts: ev.Measurements.PostRewriteEvaluations},
		{name: "websocket", counts: ev.Measurements.WebSocketEvaluations},
		{name: "connections", counts: ev.Measurements.Connections},
	}
	for _, group := range groups {
		fmt.Fprintf(&out, " %s allowed=%d denied=%d audited=%d.", group.name, group.counts.Allowed, group.counts.Denied, group.counts.Audited)
	}
	if ev.PolicyUnknown {
		out.WriteString(" Policy context unknown.")
	}
	out.WriteString(activityPolicySummary(ev))
	// Bound the explanation; full finding details remain in the separate structured output.
	const summaryLimit = 8
	// Middleware and type come from audit records; quoting keeps them from reading as explanation text.
	for _, f := range ev.Findings[:min(len(ev.Findings), summaryLimit)] {
		fmt.Fprintf(&out, " Finding origin=%s middleware=%q type=%q severity=%d records=%d matches=%d; evidence only.",
			f.Origin, boundedActivityText(f.Middleware), boundedActivityText(f.Type), f.Severity, f.Records, f.Occurrences)
	}
	if len(ev.Findings) > summaryLimit {
		fmt.Fprintf(&out, " %d additional finding groups in local evidence.", len(ev.Findings)-summaryLimit)
	}
	return out.String()
}

// activityPolicySummary names the policies behind the counts, so consumers
// compare scores only under the same policy.
func activityPolicySummary(ev ActivityEvidence) string {
	const (
		policyLimit     = 4
		shortHashLength = 12
	)
	var out strings.Builder
	if ev.PolicyChanged {
		out.WriteString(" A policy was loaded after counting began; counts may span more than one policy.")
	}
	// Hashes and versions come from audit records; quoting keeps them from reading as explanation text.
	for _, p := range ev.Policies[:min(len(ev.Policies), policyLimit)] {
		hash := strings.ToValidUTF8(p.Hash[:min(len(p.Hash), shortHashLength)], "")
		fmt.Fprintf(&out, " Policy hash=%q version=%q.", hash, p.Version)
	}
	if len(ev.Policies) > policyLimit {
		fmt.Fprintf(&out, " %d additional policies in local evidence.", len(ev.Policies)-policyLimit)
	}
	return out.String()
}
