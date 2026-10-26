// Package capability defines the vocabulary for the capability-negotiation egress layer.
// It provides types for expressing what capabilities a request needs (Requirement),
// how transforms can satisfy those needs (Transform interface), and what outcomes
// result from applying transforms (Outcome).
package capability

import "context"

// Capability represents a capability identifier from the card vocabulary
// (e.g., "mandate", "dpop_proof") or an extension URI.
type Capability string

// DPoPParams holds parameters for DPoP proof generation.
type DPoPParams struct {
	Alg    string   `json:"alg"`
	Ath    string   `json:"ath"`
	Htm    string   `json:"htm"`
	Htu    string   `json:"htu"`
	Typ    string   `json:"typ"`
	Claims []string `json:"claims"`
}

// Requirement describes what an egress request needs: which MCP tool it calls,
// what capabilities it requires, and optional DPoP parameters.
type Requirement struct {
	Tool         string
	Capabilities []Capability
	DPoP         *DPoPParams
}

// Needs returns true if the given capability is present in this requirement's
// capabilities list.
func (r Requirement) Needs(c Capability) bool {
	for _, cap := range r.Capabilities {
		if cap == c {
			return true
		}
	}
	return false
}

// Empty returns true when this requirement carries no tool and no capabilities.
// DPoP is ignored for emptiness checks.
func (r Requirement) Empty() bool {
	return r.Tool == "" && len(r.Capabilities) == 0
}

// OutcomeKind describes what action a Transform's Apply method decided.
type OutcomeKind int

const (
	// Passthrough means the transform did not handle the request; try the next transform.
	// Must be the zero value.
	Passthrough OutcomeKind = iota
	// Deny means the transform rejected the request; stop processing and return an error.
	Deny
	// Allow means the transform approved the request and potentially modified the body.
	Allow
)

// Outcome is the result of applying a Transform to a request.
// Body is set only for Allow outcomes (the potentially modified request body).
// Reason is set only for Deny outcomes (why the request was rejected).
type Outcome struct {
	Kind   OutcomeKind
	Body   []byte // Set only for Allow
	Reason string // Set only for Deny
}

// Target describes the request being evaluated: the destination (Host, Method, Path)
// and the MCP Tool name extracted from the request body (may be empty).
type Target struct {
	Host   string
	Method string
	Path   string
	Tool   string // MCP tool name extracted from request body by caller, may be ""
}

// Transform is a pluggable component that can inspect an egress request,
// check if it can satisfy the required capabilities, and either pass through,
// deny, or allow (with optional body modification).
type Transform interface {
	// Provides returns the list of capabilities this transform can satisfy.
	Provides() []Capability

	// Apply evaluates the request against this transform's logic.
	// Returns Passthrough if this transform doesn't handle the request,
	// Deny with a reason if the request should be rejected,
	// or Allow with an optionally modified body if the request should proceed.
	Apply(ctx context.Context, target Target, req Requirement, body []byte) Outcome
}
