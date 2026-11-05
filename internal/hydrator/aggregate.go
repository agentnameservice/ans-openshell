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

// statsConsumer receives every event that resolved to a configured agent and
// fell inside the window.
type statsConsumer interface {
	add(mapping AgentMapping, ev Event)
}

// policyObserver is an optional statsConsumer extension for attributed policy
// load records outside the window, since a policy loaded before the window
// still governs the decisions inside it.
type policyObserver interface {
	addPolicy(mapping AgentMapping, ev Event)
}

// attributedAgent is a configured agent with at least one attributed event.
type attributedAgent struct {
	mapping AgentMapping
	events  int
}

// attributor attributes events to agents, tracks the input window and fans
// each attributed event out to the registered stats consumers.
type attributor struct {
	agents      AgentMap
	window      *Window
	consumers   []statsConsumer
	earliest    time.Time
	latest      time.Time
	seen        map[string]*attributedAgent
	unmapped    int
	noContainer int
	outOfWindow int
	attributed  int
}

func newAttributor(agents AgentMap, window *Window, consumers ...statsConsumer) *attributor {
	return &attributor{agents: agents, window: window, consumers: consumers, seen: map[string]*attributedAgent{}}
}

func (a *attributor) add(ev Event) {
	ts, hasTime := ev.Timestamp()
	if a.window != nil {
		if !hasTime || !a.window.Contains(ts) {
			a.outOfWindow++
			a.observeOutOfWindowPolicy(ev)
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
	a.attributed++
	agent, seen := a.seen[mapping.AgentID]
	if !seen {
		agent = &attributedAgent{mapping: mapping}
		a.seen[mapping.AgentID] = agent
	}
	agent.events++
	for _, consumer := range a.consumers {
		consumer.add(mapping, ev)
	}
}

// observeOutOfWindowPolicy forwards an attributed out-of-window policy load
// record to the consumers that track policy context. It does not change the
// attribution counters, so the record still counts only as out of window.
func (a *attributor) observeOutOfWindowPolicy(ev Event) {
	if ev.ClassUID != ClassDeviceConfigChange {
		return
	}
	mapping, ok := a.agents.Lookup(ev)
	if !ok {
		return
	}
	for _, consumer := range a.consumers {
		if observer, tracksPolicy := consumer.(policyObserver); tracksPolicy {
			observer.addPolicy(mapping, ev)
		}
	}
}

// legacyAggregator accumulates the payload of the legacy policy-violation-rate
// and protocol-adherence signals. It is registered only when one of them is
// emitted.
type legacyAggregator struct {
	stats map[string]*agentStats
}

func newLegacyAggregator() *legacyAggregator {
	return &legacyAggregator{stats: map[string]*agentStats{}}
}

func (l *legacyAggregator) add(mapping AgentMapping, ev Event) {
	st, seen := l.stats[mapping.AgentID]
	if !seen {
		st = newAgentStats(mapping)
		l.stats[mapping.AgentID] = st
	}
	st.add(ev)
}

func (a *attributor) extend(ts time.Time) {
	if a.earliest.IsZero() || ts.Before(a.earliest) {
		a.earliest = ts
	}
	if ts.After(a.latest) {
		a.latest = ts
	}
}

// resolveWindow returns the explicit window, else the span of event times,
// else a window collapsed onto now when no event carried a timestamp.
func (a *attributor) resolveWindow(now time.Time) Window {
	if a.window != nil {
		return *a.window
	}
	if a.latest.IsZero() {
		now = now.UTC()
		return Window{Start: now, End: now}
	}
	return Window{Start: a.earliest, End: a.latest}
}
