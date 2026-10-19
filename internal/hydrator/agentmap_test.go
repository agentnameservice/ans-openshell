package hydrator

import (
	"strings"
	"testing"
)

func TestNewAgentMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mappings []AgentMapping
		wantLen  int
		wantErr  string
	}{
		{
			name: "two agents",
			mappings: []AgentMapping{
				{AgentID: "a", SandboxUIDs: []string{"u1", "u2"}, SandboxNames: []string{"n1"}},
				{AgentID: "b", SandboxNames: []string{"n2"}},
			},
			wantLen: 4,
		},
		{name: "empty", mappings: nil, wantLen: 0},
		{name: "missing agent id", mappings: []AgentMapping{{SandboxUIDs: []string{"u1"}}}, wantErr: "agents[0]: agent_id is required"},
		{
			name:     "duplicate agent id",
			mappings: []AgentMapping{{AgentID: "a", SandboxUIDs: []string{"u1"}}, {AgentID: "a", SandboxUIDs: []string{"u2"}}},
			wantErr:  `agent "a" is mapped more than once`,
		},
		{name: "no sandboxes", mappings: []AgentMapping{{AgentID: "a"}}, wantErr: "names no sandbox_uids or sandbox_names"},
		{name: "empty uid", mappings: []AgentMapping{{AgentID: "a", SandboxUIDs: []string{""}}}, wantErr: "empty sandbox uid"},
		{name: "empty name", mappings: []AgentMapping{{AgentID: "a", SandboxNames: []string{""}}}, wantErr: "empty sandbox name"},
		{
			name:     "uid shared by two agents",
			mappings: []AgentMapping{{AgentID: "a", SandboxUIDs: []string{"u1"}}, {AgentID: "b", SandboxUIDs: []string{"u1"}}},
			wantErr:  `sandbox uid "u1" is mapped to both "a" and "b"`,
		},
		{
			name:     "name shared by two agents",
			mappings: []AgentMapping{{AgentID: "a", SandboxNames: []string{"n"}}, {AgentID: "b", SandboxNames: []string{"n"}}},
			wantErr:  `sandbox name "n" is mapped to both "a" and "b"`,
		},
		{name: "uid repeated within one agent", mappings: []AgentMapping{{AgentID: "a", SandboxUIDs: []string{"u", "u"}}}, wantErr: "mapped to both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := NewAgentMap(tt.mappings)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewAgentMap() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewAgentMap() error = %v", err)
			}
			if m.Len() != tt.wantLen {
				t.Fatalf("Len() = %d, want %d", m.Len(), tt.wantLen)
			}
		})
	}
}

func TestAgentMapLookup(t *testing.T) {
	t.Parallel()
	m := mustAgentMap(t,
		AgentMapping{AgentID: "a", AnsName: "ans://v1.0.0.a.example.com", SandboxUIDs: []string{"u-a"}, SandboxNames: []string{"n-a"}},
		AgentMapping{AgentID: "b", SandboxNames: []string{"n-b"}},
	)
	tests := []struct {
		name      string
		m         AgentMap
		container *Container
		wantID    string
	}{
		{name: "by uid", m: m, container: &Container{UID: "u-a", Name: "renamed"}, wantID: "a"},
		{name: "by name when uid unknown", m: m, container: &Container{UID: "other", Name: "n-a"}, wantID: "a"},
		{name: "uid wins over another agent's name", m: m, container: &Container{UID: "u-a", Name: "n-b"}, wantID: "a"},
		{name: "name only", m: m, container: &Container{Name: "n-b"}, wantID: "b"},
		{name: "unknown sandbox", m: m, container: &Container{UID: "x", Name: "y"}},
		{name: "empty container", m: m, container: &Container{}},
		{name: "no container", m: m},
		{name: "zero map", m: AgentMap{}, container: &Container{UID: "u-a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tt.m.Lookup(Event{Container: tt.container})
			if ok != (tt.wantID != "") {
				t.Fatalf("Lookup() ok = %v, want %v", ok, tt.wantID != "")
			}
			if got.AgentID != tt.wantID {
				t.Fatalf("Lookup() agent = %q, want %q", got.AgentID, tt.wantID)
			}
			if ok && tt.wantID == "a" && got.AnsName != "ans://v1.0.0.a.example.com" {
				t.Fatalf("Lookup() mapping = %+v, lost ans_name", got)
			}
		})
	}
}
