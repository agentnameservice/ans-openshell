package capability_test

import (
	"testing"

	"github.com/agentnameservice/ans-openshell/internal/capability"
)

func TestRequirement_Needs(t *testing.T) {
	tests := []struct {
		name string
		req  capability.Requirement
		cap  capability.Capability
		want bool
	}{
		{
			name: "capability present",
			req: capability.Requirement{
				Capabilities: []capability.Capability{"mandate", "dpop_proof"},
			},
			cap:  "mandate",
			want: true,
		},
		{
			name: "capability absent",
			req: capability.Requirement{
				Capabilities: []capability.Capability{"mandate"},
			},
			cap:  "dpop_proof",
			want: false,
		},
		{
			name: "empty capabilities list",
			req: capability.Requirement{
				Capabilities: []capability.Capability{},
			},
			cap:  "mandate",
			want: false,
		},
		{
			name: "nil capabilities list",
			req: capability.Requirement{
				Capabilities: nil,
			},
			cap:  "mandate",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.Needs(tt.cap); got != tt.want {
				t.Errorf("Requirement.Needs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequirement_Empty(t *testing.T) {
	tests := []struct {
		name string
		req  capability.Requirement
		want bool
	}{
		{
			name: "empty requirement - no tool and no capabilities",
			req: capability.Requirement{
				Tool:         "",
				Capabilities: nil,
			},
			want: true,
		},
		{
			name: "empty requirement - empty string tool and empty slice",
			req: capability.Requirement{
				Tool:         "",
				Capabilities: []capability.Capability{},
			},
			want: true,
		},
		{
			name: "not empty - has tool",
			req: capability.Requirement{
				Tool:         "mcp_tool",
				Capabilities: nil,
			},
			want: false,
		},
		{
			name: "not empty - has capability",
			req: capability.Requirement{
				Tool:         "",
				Capabilities: []capability.Capability{"mandate"},
			},
			want: false,
		},
		{
			name: "not empty - has both tool and capability",
			req: capability.Requirement{
				Tool:         "mcp_tool",
				Capabilities: []capability.Capability{"mandate"},
			},
			want: false,
		},
		{
			name: "empty with DPoP set - DPoP ignored for emptiness",
			req: capability.Requirement{
				Tool:         "",
				Capabilities: nil,
				DPoP: &capability.DPoPParams{
					Alg: "ES256",
					Ath: "hash",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.Empty(); got != tt.want {
				t.Errorf("Requirement.Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOutcomeKind_ZeroValueIsPassthrough(t *testing.T) {
	var o capability.OutcomeKind
	if o != capability.Passthrough {
		t.Errorf("zero value of OutcomeKind = %v, want Passthrough", o)
	}
}

func TestOutcomeKind_ConstOrder(t *testing.T) {
	if capability.Passthrough != 0 {
		t.Errorf("Passthrough = %d, want 0", capability.Passthrough)
	}
	if capability.Deny != 1 {
		t.Errorf("Deny = %d, want 1", capability.Deny)
	}
	if capability.Allow != 2 {
		t.Errorf("Allow = %d, want 2", capability.Allow)
	}
}
