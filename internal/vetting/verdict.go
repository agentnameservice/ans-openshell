// Package vetting decides whether a destination host is a registered ANS agent
// and what a policy mode makes of that answer. The Verifier does the lookups
// (DNS _ans-badge record, trusted-TL allowlist, badge status, optional Trust
// Index score) with a cache so the request path never waits on the network for
// a host it has seen before; Decide maps a Verdict and a Mode to an allow or
// deny with a stable reason code shared by the middleware and the interceptor.
package vetting

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Status is the outcome of vetting one destination host.
type Status int

const (
	// StatusUnknown means no verdict is available yet: the lookup has not run
	// or is still in flight.
	StatusUnknown Status = iota
	// StatusRegistered means the host publishes an _ans-badge record pointing
	// at a trusted transparency log whose badge is ACTIVE, WARNING or
	// DEPRECATED.
	StatusRegistered
	// StatusUnregistered means the host publishes no _ans-badge record.
	StatusUnregistered
	// StatusRevoked means the badge status is EXPIRED or REVOKED.
	StatusRevoked
	// StatusUntrustedTL means the _ans-badge URL names a transparency log that
	// is not in the operator's trusted-TL allowlist.
	StatusUntrustedTL
	// StatusBelowThreshold means the host is registered but its Trust Index
	// score is below the configured minimum.
	StatusBelowThreshold
	// StatusError means the lookup failed (DNS or TL error) and no cached
	// verdict exists.
	StatusError
	// StatusExempt means the operator excluded the host from vetting
	// (vetting.exempt_hosts); it is never denied and never looked up.
	StatusExempt
)

// String returns the lowercase snake_case label used in findings and logs.
func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusRegistered:
		return "registered"
	case StatusUnregistered:
		return "unregistered"
	case StatusRevoked:
		return "revoked"
	case StatusUntrustedTL:
		return "untrusted_tl"
	case StatusBelowThreshold:
		return "below_threshold"
	case StatusError:
		return "error"
	case StatusExempt:
		return "exempt"
	}
	return fmt.Sprintf("status(%d)", int(s))
}

// Verdict is the vetting result for one host.
type Verdict struct {
	Host   string
	Status Status
	// AnsName and AgentID come from the badge when the host is registered.
	AnsName string
	AgentID string
	// BadgeStatus is the badge's lifecycle status (ACTIVE, REVOKED, ...).
	BadgeStatus string
	// Detail is a short audit-safe explanation; it never echoes request content.
	Detail string
}

// Verifier answers whether a host is a registered ANS agent.
type Verifier interface {
	// Lookup returns the verdict for host. A cached verdict returns at once. On
	// a miss the lookup starts in the background and, when wait is positive,
	// Lookup blocks up to wait (bounded by ctx) for it; otherwise it returns
	// StatusUnknown and the next call finds the cached result.
	Lookup(ctx context.Context, host string, wait time.Duration) Verdict
}

// Mode is the destination policy a sandbox policy selects.
type Mode int

const (
	// ModeOff performs no vetting.
	ModeOff Mode = iota
	// ModeObserve vets every destination and reports findings but never denies.
	ModeObserve
	// ModeRequire denies destinations that are not registered ANS agents.
	ModeRequire
)

// ParseMode parses the policy spelling of a Mode: "off", "observe" or
// "require_registered". The empty string is ModeOff.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return ModeOff, nil
	case "observe":
		return ModeObserve, nil
	case "require_registered":
		return ModeRequire, nil
	}
	return ModeOff, fmt.Errorf("unknown destination_policy %q (want off, observe or require_registered)", s)
}

// String returns the policy spelling of the mode.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeObserve:
		return "observe"
	case ModeRequire:
		return "require_registered"
	}
	return fmt.Sprintf("mode(%d)", int(m))
}

// Reason codes returned to OpenShell on a destination denial. They follow the
// HttpRequestResult.reason_code grammar: lowercase ASCII, digits and
// underscores, at most 64 bytes.
const (
	ReasonUnregistered   = "ans_destination_unregistered"
	ReasonRevoked        = "ans_destination_revoked"
	ReasonUntrustedTL    = "ans_destination_untrusted_tl"
	ReasonBelowThreshold = "ans_destination_below_threshold"
	ReasonUnverified     = "ans_destination_unverified"
)

// Decision is what a Mode makes of a Verdict.
type Decision struct {
	Deny       bool
	ReasonCode string
}

// Decide applies mode to v. Only ModeRequire ever denies; an unknown or errored
// verdict denies as unverified so a lookup that has not finished can never
// let an unregistered destination through.
func Decide(mode Mode, v Verdict) Decision {
	if mode != ModeRequire {
		return Decision{}
	}
	switch v.Status {
	case StatusRegistered, StatusExempt:
		return Decision{}
	case StatusUnregistered:
		return Decision{Deny: true, ReasonCode: ReasonUnregistered}
	case StatusRevoked:
		return Decision{Deny: true, ReasonCode: ReasonRevoked}
	case StatusUntrustedTL:
		return Decision{Deny: true, ReasonCode: ReasonUntrustedTL}
	case StatusBelowThreshold:
		return Decision{Deny: true, ReasonCode: ReasonBelowThreshold}
	case StatusUnknown, StatusError:
		return Decision{Deny: true, ReasonCode: ReasonUnverified}
	}
	return Decision{Deny: true, ReasonCode: ReasonUnverified}
}
