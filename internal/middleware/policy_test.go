package middleware

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

func structOf(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("NewStruct(%v): %v", m, err)
	}
	return s
}

func TestParsePolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      map[string]any
		nilIn   bool
		want    PolicyConfig
		wantErr string
	}{
		{name: "nil struct", nilIn: true, wantErr: "config is required"},
		{name: "empty defaults to sign", in: map[string]any{}, want: PolicyConfig{Mode: ModeSign}},
		{name: "sign with identity", in: map[string]any{"mode": "sign", "identity": " payments-agent "},
			want: PolicyConfig{Mode: ModeSign, Identity: "payments-agent"}},
		{name: "identity only", in: map[string]any{"identity": "payments-agent"},
			want: PolicyConfig{Mode: ModeSign, Identity: "payments-agent"}},
		{name: "strip case-insensitive", in: map[string]any{"mode": " STRIP "}, want: PolicyConfig{Mode: ModeStrip}},
		{name: "destination observe", in: map[string]any{"identity": "a", "destination_policy": "observe"},
			want: PolicyConfig{Mode: ModeSign, Identity: "a", DestinationPolicy: vetting.ModeObserve}},
		{name: "destination require", in: map[string]any{"identity": "a", "destination_policy": "require_registered"},
			want: PolicyConfig{Mode: ModeSign, Identity: "a", DestinationPolicy: vetting.ModeRequire}},
		{name: "destination off", in: map[string]any{"identity": "a", "destination_policy": "off"},
			want: PolicyConfig{Mode: ModeSign, Identity: "a"}},
		{name: "unknown key", in: map[string]any{"identity": "a", "identtity": "b"}, wantErr: `unknown field "identtity"`},
		{name: "non-string mode", in: map[string]any{"mode": 1}, wantErr: "mode must be a string"},
		{name: "null identity", in: map[string]any{"identity": nil}, wantErr: "identity must be a string"},
		{name: "unknown mode", in: map[string]any{"mode": "observe"}, wantErr: `unknown mode "observe"`},
		{name: "unknown destination policy", in: map[string]any{"destination_policy": "deny"}, wantErr: "unknown destination_policy"},
		{name: "errors reported in key order", in: map[string]any{"zzz": true, "mode": 5}, wantErr: "mode must be a string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var in *structpb.Struct
			if !tt.nilIn {
				in = structOf(t, tt.in)
			}
			got, err := ParsePolicy(in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParsePolicy() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePolicy() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParsePolicy() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
