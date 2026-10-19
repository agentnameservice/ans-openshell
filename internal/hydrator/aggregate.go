package hydrator

import "time"

// maxDenyReasons caps the distinct status_detail values kept per agent;
// further values are summed under denyReasonOther.
const maxDenyReasons = 50

// maxDistinctDestinations bounds the per-agent destination set so a flood of
// unique hosts in the audit stream cannot grow memory without limit; the
// reported distinct-destination count saturates at this value.
const maxDistinctDestinations = 10_000

const (
	denyReasonUnspecified = "unspecified"
	denyReasonOther       = "other"
)

// Window is the observation period, inclusive at both ends.
type Window struct {
	Start time.Time
	End   time.Time
}

// Contains reports whether t falls inside the window.
func (w Window) Contains(t time.Time) bool {
	return !t.Before(w.Start) && !t.After(w.End)
}

type agentStats struct {
	mapping      AgentMapping
	events       int
	total        int
	denied       int
	classes      map[int]int
	denyReasons  map[string]int
	destinations map[string]struct{}
	findings     map[int]int
}

func newAgentStats(mapping AgentMapping) *agentStats {
	return &agentStats{
		mapping:      mapping,
		classes:      map[int]int{ClassNetworkActivity: 0, ClassHTTPActivity: 0},
		denyReasons:  map[string]int{},
		destinations: map[string]struct{}{},
		findings:     map[int]int{},
	}
}

func (s *agentStats) add(ev Event) {
	s.events++
	switch {
	case ev.IsNetwork():
		s.addNetwork(ev)
	case ev.ClassUID == ClassDetectionFinding:
		s.findings[ev.SeverityID]++
	}
}

func (s *agentStats) addNetwork(ev Event) {
	s.total++
	s.classes[ev.ClassUID]++
	if dst := ev.Destination(); dst != "" {
		if len(s.destinations) < maxDistinctDestinations {
			s.destinations[dst] = struct{}{}
		}
	}
	if !ev.Denied() {
		return
	}
	s.denied++
	s.denyReasons[s.denyReasonKey(ev.StatusDetail)]++
}

func (s *agentStats) denyReasonKey(detail string) string {
	if detail == "" {
		detail = denyReasonUnspecified
	}
	if _, known := s.denyReasons[detail]; known || len(s.denyReasons) < maxDenyReasons {
		return detail
	}
	return denyReasonOther
}

func (s *agentStats) rate() float64 {
	if s.total == 0 {
		return 0
	}
	return float64(s.denied) / float64(s.total)
}

// aggregator attributes events to agents and tracks the input window.
type aggregator struct {
	agents      AgentMap
	window      *Window
	earliest    time.Time
	latest      time.Time
	stats       map[string]*agentStats
	unmapped    int
	noContainer int
	outOfWindow int
}

func newAggregator(agents AgentMap, window *Window) *aggregator {
	return &aggregator{agents: agents, window: window, stats: map[string]*agentStats{}}
}

func (a *aggregator) add(ev Event) {
	ts, hasTime := ev.Timestamp()
	if a.window != nil {
		if !hasTime || !a.window.Contains(ts) {
			a.outOfWindow++
			return
		}
	} else if hasTime {
		a.extend(ts)
	}
	mapping, ok := a.agents.Lookup(ev)
	if !ok {
		a.unmapped++
		if ev.Container == nil {
			a.noContainer++
		}
		return
	}
	st, seen := a.stats[mapping.AgentID]
	if !seen {
		st = newAgentStats(mapping)
		a.stats[mapping.AgentID] = st
	}
	st.add(ev)
}

func (a *aggregator) extend(ts time.Time) {
	if a.earliest.IsZero() || ts.Before(a.earliest) {
		a.earliest = ts
	}
	if ts.After(a.latest) {
		a.latest = ts
	}
}

// resolveWindow returns the explicit window, else the span of event times,
// else a window collapsed onto now when no event carried a timestamp.
func (a *aggregator) resolveWindow(now time.Time) Window {
	if a.window != nil {
		return *a.window
	}
	if a.latest.IsZero() {
		now = now.UTC()
		return Window{Start: now, End: now}
	}
	return Window{Start: a.earliest, End: a.latest}
}
