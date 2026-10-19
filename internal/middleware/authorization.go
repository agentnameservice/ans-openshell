package middleware

import (
	"errors"
	"fmt"
	"maps"
	"strings"
)

// IdentityAuthorizer grants a sandbox access to a signing identity.
type IdentityAuthorizer interface {
	Allows(sandboxID, identityName string) bool
}

// SandboxIdentities holds operator-approved, exact sandbox identity bindings.
type SandboxIdentities struct {
	bindings map[string]string
}

// NewSandboxIdentities validates and copies bindings. An empty map denies all signing.
func NewSandboxIdentities(bindings map[string]string, identities IdentityLookup) (*SandboxIdentities, error) {
	if identities == nil {
		return nil, errors.New("sandbox_identities: identity lookup is required")
	}
	for sandboxID, name := range bindings {
		if sandboxID == "" || strings.TrimSpace(sandboxID) != sandboxID || sandboxID == "*" {
			return nil, fmt.Errorf("sandbox_identities: invalid sandbox id %q", sandboxID)
		}
		if _, ok := identities.Identity(name); !ok {
			return nil, fmt.Errorf("sandbox_identities: sandbox %q names unknown identity %q", sandboxID, name)
		}
	}
	return &SandboxIdentities{bindings: maps.Clone(bindings)}, nil
}

// Allows implements IdentityAuthorizer without wildcard or default grants.
func (s *SandboxIdentities) Allows(sandboxID, identityName string) bool {
	name, ok := s.bindings[sandboxID]
	return ok && name == identityName
}
