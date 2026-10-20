package vetting

import "testing"

func TestParseMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{in: "", want: ModeOff},
		{in: "off", want: ModeOff},
		{in: " Observe ", want: ModeObserve},
		{in: "require_registered", want: ModeRequire},
		{in: "REQUIRE_REGISTERED", want: ModeRequire},
		{in: "require", wantErr: true},
		{in: "deny", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseMode(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseMode(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseMode(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestStringers(t *testing.T) {
	t.Parallel()
	statuses := map[Status]string{
		StatusUnknown: "unknown", StatusRegistered: "registered", StatusUnregistered: "unregistered",
		StatusRevoked: "revoked", StatusUntrustedTL: "untrusted_tl", StatusBelowThreshold: "below_threshold",
		StatusError: "error", StatusExempt: "exempt", Status(42): "status(42)",
	}
	for s, want := range statuses {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", int(s), got, want)
		}
	}
	modes := map[Mode]string{ModeOff: "off", ModeObserve: "observe", ModeRequire: "require_registered", Mode(9): "mode(9)"}
	for m, want := range modes {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", int(m), got, want)
		}
	}
}

func TestDecide(t *testing.T) {
	t.Parallel()
	all := []Status{StatusUnknown, StatusRegistered, StatusUnregistered, StatusRevoked,
		StatusUntrustedTL, StatusBelowThreshold, StatusError, StatusExempt, Status(99)}
	for _, mode := range []Mode{ModeOff, ModeObserve} {
		for _, s := range all {
			if d := Decide(mode, Verdict{Status: s}); d.Deny || d.ReasonCode != "" {
				t.Errorf("Decide(%v, %v) = %+v, want allow", mode, s, d)
			}
		}
	}
	tests := []struct {
		status Status
		deny   bool
		code   string
	}{
		{status: StatusRegistered},
		{status: StatusExempt},
		{status: StatusUnregistered, deny: true, code: ReasonUnregistered},
		{status: StatusRevoked, deny: true, code: ReasonRevoked},
		{status: StatusUntrustedTL, deny: true, code: ReasonUntrustedTL},
		{status: StatusBelowThreshold, deny: true, code: ReasonBelowThreshold},
		{status: StatusUnknown, deny: true, code: ReasonUnverified},
		{status: StatusError, deny: true, code: ReasonUnverified},
		{status: Status(99), deny: true, code: ReasonUnverified},
	}
	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			t.Parallel()
			d := Decide(ModeRequire, Verdict{Status: tt.status})
			if d.Deny != tt.deny || d.ReasonCode != tt.code {
				t.Fatalf("Decide(require, %v) = %+v, want deny=%v code=%q", tt.status, d, tt.deny, tt.code)
			}
		})
	}
}

func TestReasonCodeGrammar(t *testing.T) {
	t.Parallel()
	for _, code := range []string{ReasonUnregistered, ReasonRevoked, ReasonUntrustedTL, ReasonBelowThreshold, ReasonUnverified} {
		if len(code) > 64 || code[0] < 'a' || code[0] > 'z' {
			t.Errorf("reason code %q violates the OpenShell grammar", code)
		}
		for _, r := range code {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				t.Errorf("reason code %q contains %q", code, r)
			}
		}
	}
}
