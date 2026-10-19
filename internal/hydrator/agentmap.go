package hydrator

import (
	"errors"
	"fmt"
)

// AgentMapping attributes one ANS agent to the OpenShell sandboxes it runs in.
// The YAML tags match the hydrator's configuration block.
type AgentMapping struct {
	AgentID      string   `yaml:"agent_id"`
	AnsName      string   `yaml:"ans_name"`
	SandboxUIDs  []string `yaml:"sandbox_uids"`
	SandboxNames []string `yaml:"sandbox_names"`
}

// AgentMap resolves events to agents. The zero value maps nothing.
type AgentMap struct {
	byUID  map[string]AgentMapping
	byName map[string]AgentMapping
}

// NewAgentMap validates the mappings and indexes them. Every mapping needs a
// non-empty agent_id and at least one sandbox uid or name; an agent_id, a
// sandbox uid or a sandbox name may appear only once.
func NewAgentMap(mappings []AgentMapping) (AgentMap, error) {
	m := AgentMap{
		byUID:  make(map[string]AgentMapping, len(mappings)),
		byName: make(map[string]AgentMapping, len(mappings)),
	}
	seenAgents := make(map[string]struct{}, len(mappings))
	for i, mapping := range mappings {
		if mapping.AgentID == "" {
			return AgentMap{}, fmt.Errorf("hydrator: agents[%d]: agent_id is required", i)
		}
		if _, dup := seenAgents[mapping.AgentID]; dup {
			return AgentMap{}, fmt.Errorf("hydrator: agent %q is mapped more than once", mapping.AgentID)
		}
		seenAgents[mapping.AgentID] = struct{}{}
		if len(mapping.SandboxUIDs) == 0 && len(mapping.SandboxNames) == 0 {
			return AgentMap{}, fmt.Errorf("hydrator: agent %q names no sandbox_uids or sandbox_names", mapping.AgentID)
		}
		if err := index(m.byUID, "sandbox uid", mapping.SandboxUIDs, mapping); err != nil {
			return AgentMap{}, err
		}
		if err := index(m.byName, "sandbox name", mapping.SandboxNames, mapping); err != nil {
			return AgentMap{}, err
		}
	}
	return m, nil
}

// Lookup resolves the event's sandbox to an agent, by container.uid first and
// container.name second. Events without a container never resolve.
func (m AgentMap) Lookup(ev Event) (AgentMapping, bool) {
	if ev.Container == nil {
		return AgentMapping{}, false
	}
	if ev.Container.UID != "" {
		if mapping, ok := m.byUID[ev.Container.UID]; ok {
			return mapping, true
		}
	}
	if ev.Container.Name != "" {
		if mapping, ok := m.byName[ev.Container.Name]; ok {
			return mapping, true
		}
	}
	return AgentMapping{}, false
}

// Len returns the number of sandbox keys (uids and names) the map resolves.
func (m AgentMap) Len() int {
	return len(m.byUID) + len(m.byName)
}

func index(into map[string]AgentMapping, kind string, keys []string, mapping AgentMapping) error {
	for _, key := range keys {
		if key == "" {
			return errors.New("hydrator: agent " + mapping.AgentID + ": empty " + kind)
		}
		if prev, dup := into[key]; dup {
			return fmt.Errorf("hydrator: %s %q is mapped to both %q and %q", kind, key, prev.AgentID, mapping.AgentID)
		}
		into[key] = mapping
	}
	return nil
}
