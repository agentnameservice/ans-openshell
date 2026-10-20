package hydrator

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestAggregatorNetworkMath(t *testing.T) {
	t.Parallel()
	agg := newAggregator(mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"sb"}}), nil)
	events := []Event{
		netEvent(ClassNetworkActivity, "sb", false, "", "api.github.com", "", 1000),
		netEvent(ClassNetworkActivity, "sb", true, "transparent_tcp_policy_denied", "github.com", "198.18.0.2", 2000),
		{ClassUID: ClassNetworkActivity, Container: &Container{UID: "sb"}, StatusID: deniedID, DstEndpoint: &Endpoint{IP: "198.18.0.3"}},
		{ClassUID: ClassHTTPActivity, Container: &Container{UID: "sb"}, DispositionID: deniedID, DstEndpoint: &Endpoint{Domain: "api.github.com"}},
		netEvent(ClassHTTPActivity, "sb", false, "", "", "", 3000),
		{ClassUID: ClassDetectionFinding, Container: &Container{UID: "sb"}, SeverityID: 3},
		{ClassUID: ClassDetectionFinding, Container: &Container{UID: "sb"}, SeverityID: 3},
		{ClassUID: ClassDetectionFinding, Container: &Container{UID: "sb"}, SeverityID: 5},
		{ClassUID: ClassProcessActivity, Container: &Container{UID: "sb"}, StatusID: deniedID},
	}
	for _, ev := range events {
		agg.add(ev)
	}
	st := agg.stats["a"]
	if st == nil {
		t.Fatal("no stats for agent a")
	}
	if st.events != 9 || st.total != 5 || st.denied != 3 {
		t.Fatalf("events/total/denied = %d/%d/%d, want 9/5/3", st.events, st.total, st.denied)
	}
	if want := map[int]int{ClassNetworkActivity: 3, ClassHTTPActivity: 2}; !reflect.DeepEqual(st.classes, want) {
		t.Fatalf("classes = %v, want %v", st.classes, want)
	}
	if want := map[string]int{"transparent_tcp_policy_denied": 1, denyReasonUnspecified: 2}; !reflect.DeepEqual(st.denyReasons, want) {
		t.Fatalf("denyReasons = %v, want %v", st.denyReasons, want)
	}
	if len(st.destinations) != 3 {
		t.Fatalf("destinations = %v, want 3 distinct", st.destinations)
	}
	if want := map[int]int{3: 2, 5: 1}; !reflect.DeepEqual(st.findings, want) {
		t.Fatalf("findings = %v, want %v", st.findings, want)
	}
	if got := st.rate(); got != 0.6 {
		t.Fatalf("rate() = %v, want 0.6", got)
	}
	if agg.unmapped != 0 || agg.outOfWindow != 0 || agg.attributed != 9 {
		t.Fatalf("unmapped/outOfWindow/attributed = %d/%d/%d, want 0/0/9", agg.unmapped, agg.outOfWindow, agg.attributed)
	}
}

func TestAgentStatsRateWithoutTraffic(t *testing.T) {
	t.Parallel()
	st := newAgentStats(AgentMapping{AgentID: "a"})
	st.add(Event{ClassUID: ClassDetectionFinding, SeverityID: 1})
	if st.total != 0 || st.rate() != 0 {
		t.Fatalf("total/rate = %d/%v, want 0/0", st.total, st.rate())
	}
}

func TestAgentStatsDenyReasonCap(t *testing.T) {
	t.Parallel()
	st := newAgentStats(AgentMapping{AgentID: "a"})
	for i := range maxDenyReasons + 10 {
		st.add(netEvent(ClassNetworkActivity, "", true, fmt.Sprintf("reason_%02d", i), "h", "", 0))
	}
	st.add(netEvent(ClassNetworkActivity, "", true, "reason_00", "h", "", 0))
	if len(st.denyReasons) != maxDenyReasons+1 {
		t.Fatalf("len(denyReasons) = %d, want %d distinct plus %q", len(st.denyReasons), maxDenyReasons, denyReasonOther)
	}
	if st.denyReasons[denyReasonOther] != 10 {
		t.Fatalf("denyReasons[other] = %d, want 10", st.denyReasons[denyReasonOther])
	}
	if st.denyReasons["reason_00"] != 2 {
		t.Fatalf("denyReasons[reason_00] = %d, want 2 (known keys keep counting after the cap)", st.denyReasons["reason_00"])
	}
	if _, kept := st.denyReasons[fmt.Sprintf("reason_%02d", maxDenyReasons)]; kept {
		t.Fatal("a reason beyond the cap was kept as its own key")
	}
	if st.denied != maxDenyReasons+11 {
		t.Fatalf("denied = %d", st.denied)
	}
}

func TestAggregatorDerivedWindow(t *testing.T) {
	t.Parallel()
	agg := newAggregator(mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"sb"}}), nil)
	agg.add(netEvent(ClassNetworkActivity, "sb", false, "", "h", "", 3000))
	agg.add(netEvent(ClassNetworkActivity, "", false, "", "h", "", 1000))
	agg.add(netEvent(ClassNetworkActivity, "other", false, "", "h", "", 5000))
	agg.add(netEvent(ClassNetworkActivity, "sb", false, "", "h", "", 0))
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	want := Window{Start: time.UnixMilli(1000).UTC(), End: time.UnixMilli(5000).UTC()}
	if got := agg.resolveWindow(now); got != want {
		t.Fatalf("resolveWindow() = %v, want %v", got, want)
	}
	if agg.unmapped != 2 || agg.noContainer != 1 || agg.outOfWindow != 0 {
		t.Fatalf("unmapped/noContainer/outOfWindow = %d/%d/%d, want 2/1/0", agg.unmapped, agg.noContainer, agg.outOfWindow)
	}
	if agg.stats["a"].events != 2 {
		t.Fatalf("events for a = %d, want 2 (timestamp-less events count)", agg.stats["a"].events)
	}
}

func TestAggregatorExplicitWindow(t *testing.T) {
	t.Parallel()
	window := Window{Start: time.UnixMilli(2000).UTC(), End: time.UnixMilli(4000).UTC()}
	agg := newAggregator(mustAgentMap(t, AgentMapping{AgentID: "a", SandboxUIDs: []string{"sb"}}), &window)
	for _, ms := range []int64{1000, 2000, 4000, 5000, 0} {
		agg.add(netEvent(ClassNetworkActivity, "sb", false, "", "h", "", ms))
	}
	if agg.outOfWindow != 3 || agg.attributed != 2 {
		t.Fatalf("outOfWindow/attributed = %d/%d, want 3/2", agg.outOfWindow, agg.attributed)
	}
	if agg.stats["a"].total != 2 {
		t.Fatalf("total = %d, want 2", agg.stats["a"].total)
	}
	if got := agg.resolveWindow(time.Now()); got != window {
		t.Fatalf("resolveWindow() = %v, want %v", got, window)
	}
}

func TestAggregatorWindowFallsBackToNow(t *testing.T) {
	t.Parallel()
	agg := newAggregator(AgentMap{}, nil)
	agg.add(Event{ClassUID: ClassBaseEvent})
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("x", 3600))
	got := agg.resolveWindow(now)
	if !got.Start.Equal(now) || !got.End.Equal(now) || got.Start.Location() != time.UTC {
		t.Fatalf("resolveWindow() = %v, want collapsed onto %v in UTC", got, now)
	}
}

func TestWindowContains(t *testing.T) {
	t.Parallel()
	w := Window{Start: time.UnixMilli(2000), End: time.UnixMilli(4000)}
	for ms, want := range map[int64]bool{1999: false, 2000: true, 3000: true, 4000: true, 4001: false} {
		if got := w.Contains(time.UnixMilli(ms)); got != want {
			t.Errorf("Contains(%d) = %v, want %v", ms, got, want)
		}
	}
}
