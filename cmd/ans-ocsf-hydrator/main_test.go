package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/hydrator"
)

func TestEmptyRunError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		report     hydrator.Report
		allowEmpty bool
		wantErr    error
	}{
		{name: "empty input", report: hydrator.Report{}},
		{name: "lines without events", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 3, Skipped: 3}}, wantErr: errNoEvents},
		{name: "lines without events but allowed", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 3, Skipped: 3}}, allowEmpty: true},
		{name: "every event unmapped", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 2, Events: 2}, Unmapped: 2}, wantErr: errNothingAttributed},
		{name: "every event unmapped but allowed", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 2, Events: 2}, Unmapped: 2}, allowEmpty: true},
		{name: "attributed events without network activity", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 1, Events: 1}, Attributed: 1}},
		{name: "mixed attribution", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 3, Events: 3}, Attributed: 1, Unmapped: 2, Observations: 2, Posted: true}},
		{name: "every event out of the window", report: hydrator.Report{Parse: hydrator.ParseStats{Lines: 2, Events: 2}, OutOfWindow: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := emptyRunError(tt.report, tt.allowEmpty); !errors.Is(err, tt.wantErr) {
				t.Fatalf("emptyRunError() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDegradedRunError(t *testing.T) {
	t.Parallel()
	score := 100
	degraded := hydrator.ActivityEvidence{Unavailable: "interpretation_incomplete"}
	quiet := hydrator.ActivityEvidence{Unavailable: "no_eligible_decisions"}
	scored := hydrator.ActivityEvidence{Score: &score}
	tests := []struct {
		name         string
		report       hydrator.Report
		emitActivity bool
		allow        bool
		wantErr      error
	}{
		{name: "legacy only", report: hydrator.Report{}},
		{name: "unreadable audit records", report: hydrator.Report{UnreadableAuditRecords: 1}, emitActivity: true, wantErr: errUnreadableAudit},
		{name: "unreadable audit records in evidence-only run", report: hydrator.Report{UnreadableAuditRecords: 1}, wantErr: errUnreadableAudit},
		{name: "unreadable audit records accepted", report: hydrator.Report{UnreadableAuditRecords: 1}, emitActivity: true, allow: true},
		{name: "every score withheld", report: hydrator.Report{Activity: []hydrator.ActivityEvidence{degraded, degraded}}, emitActivity: true, wantErr: errActivityWithheld},
		{name: "every score withheld accepted", report: hydrator.Report{Activity: []hydrator.ActivityEvidence{degraded}}, emitActivity: true, allow: true},
		{name: "every score withheld in evidence-only run", report: hydrator.Report{Activity: []hydrator.ActivityEvidence{degraded}}},
		{name: "one score posted", report: hydrator.Report{Activity: []hydrator.ActivityEvidence{degraded, scored}}, emitActivity: true},
		{name: "quiet agents are not withheld", report: hydrator.Report{Activity: []hydrator.ActivityEvidence{degraded, quiet}}, emitActivity: true},
		{name: "no activity evidence", report: hydrator.Report{}, emitActivity: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := degradedRunError(tt.report, tt.emitActivity, tt.allow); !errors.Is(err, tt.wantErr) {
				t.Fatalf("degradedRunError() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestWindowFlags(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 19, 16, 0, 0, 0, time.FixedZone("x", -5*3600))
	tests := []struct {
		name    string
		flags   flags
		want    *hydrator.Window
		wantErr string
	}{
		{name: "no window", flags: flags{}},
		{name: "trailing window ends now in UTC", flags: flags{windowLast: 15 * time.Minute},
			want: &hydrator.Window{Start: now.UTC().Add(-15 * time.Minute), End: now.UTC()}},
		{name: "explicit window", flags: flags{windowStart: "2026-10-19T10:00:00Z", windowEnd: "2026-10-19T11:00:00Z"},
			want: &hydrator.Window{Start: time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 19, 11, 0, 0, 0, time.UTC)}},
		{name: "explicit window needs both ends", flags: flags{windowStart: "2026-10-19T10:00:00Z"}, wantErr: "together"},
		{name: "trailing and explicit are exclusive", flags: flags{windowLast: time.Minute, windowEnd: "2026-10-19T11:00:00Z"}, wantErr: "cannot be combined"},
		{name: "negative trailing window", flags: flags{windowLast: -time.Minute}, wantErr: "positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := windowFlags(tt.flags, now)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("windowFlags() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("windowFlags() error = %v", err)
			}
			if (got == nil) != (tt.want == nil) || (got != nil && (!got.Start.Equal(tt.want.Start) || !got.End.Equal(tt.want.End))) {
				t.Fatalf("windowFlags() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
