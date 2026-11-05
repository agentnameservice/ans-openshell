package hydrator

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestReaderRead(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     func(t *testing.T) string
		wantStats ParseStats
		check     func(t *testing.T, events []Event)
	}{
		{
			name:      "jsonl allowed example",
			input:     func(*testing.T) string { return allowedExampleJSON + "\n" },
			wantStats: ParseStats{Lines: 1, Events: 1},
			check:     checkAllowedExample,
		},
		{
			name:      "jsonl denied example",
			input:     func(*testing.T) string { return deniedExampleJSON + "\n" },
			wantStats: ParseStats{Lines: 1, Events: 1},
			check:     checkDeniedExample,
		},
		{
			name: "supervisor stderr with shorthand lines",
			input: func(*testing.T) string {
				return stderrTimestamp + " OCSF NET:OPEN [MED] DENIED github.com:443\n" +
					stderrLine(deniedExampleJSON) + "\n" +
					stderrTimestamp + " INFO supervisor ready\n"
			},
			wantStats: ParseStats{Lines: 3, Events: 1, Skipped: 2},
			check: func(t *testing.T, events []Event) {
				if events[0].Container == nil || events[0].Container.UID != deniedExampleUID {
					t.Fatalf("event = %+v", events[0])
				}
			},
		},
		{
			name: "collector timestamp prefixed stderr",
			input: func(*testing.T) string {
				return "2026-10-07T23:21:19.123456789Z " + stderrLine(allowedExampleJSON) + "\n"
			},
			wantStats: ParseStats{Lines: 1, Events: 1},
			check: func(t *testing.T, events []Event) {
				if events[0].ClassUID != ClassNetworkActivity {
					t.Fatalf("ClassUID = %d", events[0].ClassUID)
				}
			},
		},
		{
			name: "blank and malformed lines are skipped",
			input: func(*testing.T) string {
				return "\n   \nnot json\n{\"class_uid\":\n[1,2]\nnull\n\"str\"\n" + allowedExampleJSON + "\n"
			},
			wantStats: ParseStats{Lines: 8, Events: 1, Skipped: 7},
		},
		{
			name:      "field type mismatch is skipped",
			input:     func(*testing.T) string { return `{"class_uid":"4001"}` + "\n" },
			wantStats: ParseStats{Lines: 1, Skipped: 1},
		},
		{
			name: "unknown class and fields decode",
			input: func(*testing.T) string {
				return `{"class_uid":6002,"status_detail":"restart","unknown":{"deep":[1,2]}}` + "\n"
			},
			wantStats: ParseStats{Lines: 1, Events: 1},
			check: func(t *testing.T, events []Event) {
				if events[0].ClassUID != ClassAppLifecycle || events[0].StatusDetail != "restart" {
					t.Fatalf("event = %+v", events[0])
				}
			},
		},
		{
			name: "downgraded record without container",
			input: func(t *testing.T) string {
				fields := exampleFields(t, deniedExampleJSON)
				delete(fields, "container")
				fields["unmapped"] = map[string]any{"downgraded_from": "1.8.0"}
				return jsonLine(t, fields) + "\n"
			},
			wantStats: ParseStats{Lines: 1, Events: 1},
			check: func(t *testing.T, events []Event) {
				if events[0].Container != nil || !events[0].Denied() {
					t.Fatalf("event = %+v", events[0])
				}
			},
		},
		{
			name: "record copies outside the supervisor framing",
			input: func(*testing.T) string {
				return stderrTimestamp + " OCSF NET:OPEN [MED] DENIED example.com:443 [reason:rule_methods=OCSF-JSON " + allowedExampleJSON + "\n" +
					stderrTimestamp + " xOCSF-JSON " + allowedExampleJSON + "\n" +
					stderrTimestamp + " OCSF-JSON" + allowedExampleJSON + "\n"
			},
			wantStats: ParseStats{Lines: 3, Skipped: 3},
		},
		{
			name: "marker without an object payload",
			input: func(*testing.T) string {
				return stderrLine("[1]") + "\n" + stderrLine("") + "\n" + stderrTimestamp + " OCSF-JSON\n"
			},
			wantStats: ParseStats{Lines: 3, Skipped: 3},
		},
		{
			name:      "final line without newline",
			input:     func(*testing.T) string { return allowedExampleJSON },
			wantStats: ParseStats{Lines: 1, Events: 1},
		},
		{
			name:      "crlf line endings",
			input:     func(*testing.T) string { return allowedExampleJSON + "\r\n" + deniedExampleJSON + "\r\n" },
			wantStats: ParseStats{Lines: 2, Events: 2},
		},
		{
			name: "oversized line is skipped and parsing continues",
			input: func(*testing.T) string {
				return strings.Repeat("x", MaxLineBytes) + "\n" + allowedExampleJSON + "\n"
			},
			wantStats: ParseStats{Lines: 2, Events: 1, Skipped: 1, Oversized: 1},
		},
		{
			name: "oversized json object is skipped",
			input: func(*testing.T) string {
				return `{"class_uid":4001,"message":"` + strings.Repeat("a", MaxLineBytes) + `"}` + "\n"
			},
			wantStats: ParseStats{Lines: 1, Skipped: 1, Oversized: 1},
		},
		{
			name:      "oversized final line without newline",
			input:     func(*testing.T) string { return strings.Repeat("x", MaxLineBytes+5) },
			wantStats: ParseStats{Lines: 1, Skipped: 1, Oversized: 1},
		},
		{
			name:      "line exactly at the limit is read",
			input:     func(*testing.T) string { return strings.Repeat("x", MaxLineBytes-1) + "\n" },
			wantStats: ParseStats{Lines: 1, Skipped: 1},
		},
		{
			name: "line longer than one read chunk but under the limit",
			input: func(*testing.T) string {
				return `{"class_uid":4001,"message":"` + strings.Repeat("a", 3*readChunkBytes) + `"}` + "\n" + deniedExampleJSON + "\n"
			},
			wantStats: ParseStats{Lines: 2, Events: 2},
			check: func(t *testing.T, events []Event) {
				if len(events[0].Message) != 3*readChunkBytes {
					t.Fatalf("len(Message) = %d", len(events[0].Message))
				}
				if events[1].Container == nil {
					t.Fatal("second event lost after a long line")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			events, stats := parseAll(t, tt.input(t))
			if stats != tt.wantStats {
				t.Fatalf("Stats() = %+v, want %+v", stats, tt.wantStats)
			}
			if len(events) != tt.wantStats.Events {
				t.Fatalf("len(events) = %d, want %d", len(events), tt.wantStats.Events)
			}
			if tt.check != nil {
				tt.check(t, events)
			}
		})
	}
}

func checkAllowedExample(t *testing.T, events []Event) {
	t.Helper()
	ev := events[0]
	if ev.ClassUID != ClassNetworkActivity || ev.ActivityID != 1 || ev.ActionID != 1 || ev.DispositionID != 1 || ev.StatusID != 1 {
		t.Fatalf("ids = %+v", ev)
	}
	if ev.Denied() {
		t.Fatal("Denied() = true for the allowed example")
	}
	if ev.Container != nil {
		t.Fatalf("Container = %+v, want nil (the example carries none)", ev.Container)
	}
	if got := ev.Destination(); got != "api.github.com" {
		t.Fatalf("Destination() = %q", got)
	}
	ts, ok := ev.Timestamp()
	if !ok || !ts.Equal(time.UnixMilli(allowedExampleTime)) || ts.Location() != time.UTC {
		t.Fatalf("Timestamp() = %v, %v", ts, ok)
	}
	if ev.Metadata.Product.Version != "0.1.4" || ev.Metadata.Version != "1.8.0" || ev.Metadata.Product.Name != "OpenShell Sandbox Supervisor" {
		t.Fatalf("Metadata = %+v", ev.Metadata)
	}
	if ev.FirewallRule == nil || ev.FirewallRule.Name != "github_api" || ev.FirewallRule.Type != "opa" {
		t.Fatalf("FirewallRule = %+v", ev.FirewallRule)
	}
	if ev.Actor == nil || ev.Actor.Process == nil || ev.Actor.Process.Name != "/usr/bin/curl" || ev.Actor.Process.PID != 57 {
		t.Fatalf("Actor = %+v", ev.Actor)
	}
	if ev.DstEndpoint.Port != 443 || ev.Message != "CONNECT allowed api.github.com:443" {
		t.Fatalf("endpoint/message = %+v %q", ev.DstEndpoint, ev.Message)
	}
}

func checkDeniedExample(t *testing.T, events []Event) {
	t.Helper()
	ev := events[0]
	if !ev.Denied() || ev.ActionID != 2 || ev.DispositionID != 2 || ev.StatusID != 2 || ev.SeverityID != 3 {
		t.Fatalf("denied fields = %+v", ev)
	}
	if ev.StatusDetail != "transparent_tcp_policy_denied" {
		t.Fatalf("StatusDetail = %q", ev.StatusDetail)
	}
	if ev.Container == nil || ev.Container.UID != deniedExampleUID || ev.Container.Name != deniedExampleName {
		t.Fatalf("Container = %+v", ev.Container)
	}
	if got := ev.Destination(); got != "github.com" {
		t.Fatalf("Destination() = %q", got)
	}
	if ev.DstEndpoint.IP != "198.18.0.2" || ev.DstEndpoint.Port != 443 {
		t.Fatalf("DstEndpoint = %+v", ev.DstEndpoint)
	}
	if ev.Metadata.UID != "b885957d-124a-4af7-9eef-75cc410ff070" {
		t.Fatalf("Metadata.UID = %q", ev.Metadata.UID)
	}
	ts, ok := ev.Timestamp()
	if !ok || ts.UnixMilli() != deniedExampleTime {
		t.Fatalf("Timestamp() = %v, %v", ts, ok)
	}
}

func TestReaderUnderlyingError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")

	t.Run("immediately", func(t *testing.T) {
		t.Parallel()
		r := NewReader(iotest.ErrReader(boom))
		if _, err := r.Read(); !errors.Is(err, boom) {
			t.Fatalf("Read() error = %v, want %v", err, boom)
		}
	})
	t.Run("after one line", func(t *testing.T) {
		t.Parallel()
		r := NewReader(io.MultiReader(strings.NewReader(allowedExampleJSON+"\n"), iotest.ErrReader(boom)))
		if _, err := r.Read(); err != nil {
			t.Fatalf("first Read() error = %v", err)
		}
		if _, err := r.Read(); !errors.Is(err, boom) {
			t.Fatalf("second Read() error = %v, want %v", err, boom)
		}
		if stats := r.Stats(); stats != (ParseStats{Lines: 1, Events: 1}) {
			t.Fatalf("Stats() = %+v", stats)
		}
	})
}

func TestEventTimestamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		ms     int64
		wantOK bool
	}{
		{name: "missing", ms: 0},
		{name: "negative", ms: -5},
		{name: "present", ms: deniedExampleTime, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts, ok := Event{Time: tt.ms}.Timestamp()
			if ok != tt.wantOK {
				t.Fatalf("Timestamp() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (ts.UnixMilli() != tt.ms || ts.Location() != time.UTC) {
				t.Fatalf("Timestamp() = %v", ts)
			}
			if !ok && !ts.IsZero() {
				t.Fatalf("Timestamp() = %v, want zero", ts)
			}
		})
	}
}

func TestEventDenied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   Event
		want bool
	}{
		{name: "all allowed", ev: Event{ActionID: 1, DispositionID: 1, StatusID: 1}},
		{name: "no ids", ev: Event{}},
		{name: "action denied", ev: Event{ActionID: 2, DispositionID: 1, StatusID: 1}, want: true},
		{name: "disposition blocked", ev: Event{ActionID: 1, DispositionID: 2, StatusID: 1}, want: true},
		{name: "status failure", ev: Event{ActionID: 1, DispositionID: 1, StatusID: 2}, want: true},
		{name: "other disposition values", ev: Event{ActionID: 1, DispositionID: 3, StatusID: 99}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ev.Denied(); got != tt.want {
				t.Fatalf("Denied() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventDestination(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   Event
		want string
	}{
		{name: "no endpoint", ev: Event{}},
		{name: "empty endpoint", ev: Event{DstEndpoint: &Endpoint{Port: 443}}},
		{name: "domain preferred", ev: Event{DstEndpoint: &Endpoint{Domain: "github.com", IP: "198.18.0.2"}}, want: "github.com"},
		{name: "ip fallback", ev: Event{DstEndpoint: &Endpoint{IP: "198.18.0.2"}}, want: "198.18.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ev.Destination(); got != tt.want {
				t.Fatalf("Destination() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventIsNetwork(t *testing.T) {
	t.Parallel()
	for class, want := range map[int]bool{
		ClassNetworkActivity: true, ClassHTTPActivity: true,
		ClassSSHActivity: false, ClassDetectionFinding: false, ClassBaseEvent: false,
	} {
		if got := (Event{ClassUID: class}).IsNetwork(); got != want {
			t.Errorf("IsNetwork() for class %d = %v, want %v", class, got, want)
		}
	}
}
