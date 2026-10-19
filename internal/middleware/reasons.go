// Package middleware implements the OpenShell supervisor middleware that gives
// a sandboxed agent its ANS identity: at PRE_CREDENTIALS it signs each allowed
// outbound HTTP request with the policy-selected identity's DPoP proof and
// attaches the identity's SCITT receipt and status token (ANS-6 Method B), or
// strips those headers, and optionally vets the destination host.
package middleware

// Reason codes returned with a DENY. They follow the HttpRequestResult
// reason_code grammar (lowercase ASCII, digits and underscores, at most 64
// bytes) and OpenShell may relay them to the sandbox. Destination codes are
// shared with the interceptor and live in package vetting.
const (
	// ReasonUnsupportedPhase is returned when the evaluation phase is not
	// PRE_CREDENTIALS.
	ReasonUnsupportedPhase = "ans_unsupported_phase"
	// ReasonCallerUnauthenticated is returned when the service requires an
	// authenticated caller and the call carried none.
	ReasonCallerUnauthenticated = "ans_caller_unauthenticated"
	// ReasonCallerNotSupervisor is returned when the authenticated caller is
	// not a sandbox supervisor; only supervisors evaluate requests.
	ReasonCallerNotSupervisor = "ans_caller_not_supervisor"
	// ReasonCallerSandboxMismatch is returned when the supervisor credential
	// names a different sandbox than the request context.
	ReasonCallerSandboxMismatch = "ans_caller_sandbox_mismatch"
	// ReasonPolicyInvalid is returned when the policy config would not pass
	// ValidateConfig; OpenShell validates at policy creation so this guards
	// against a config that bypassed it.
	ReasonPolicyInvalid = "ans_policy_invalid"
	// ReasonTargetInvalid is returned when the request target has no usable
	// method, scheme or host.
	ReasonTargetInvalid = "ans_target_invalid"
	// ReasonIdentityUnknown is returned when the policy names an identity the
	// service does not hold.
	ReasonIdentityUnknown = "ans_identity_unknown"
	// ReasonIdentityUnauthorized denies an identity absent from the sandbox binding.
	ReasonIdentityUnauthorized = "ans_identity_unauthorized"
	// ReasonRequestRewriteUnsupported denies content OpenShell could rewrite after signing.
	ReasonRequestRewriteUnsupported = "ans_credential_rewrite_unsupported"
	// ReasonStatusTokenUnavailable is returned when the identity has no
	// unexpired status token (ANS-6 section 9.4, fail closed).
	ReasonStatusTokenUnavailable = "ans_status_token_unavailable"
	// ReasonReceiptUnavailable is returned when the identity has no receipt.
	ReasonReceiptUnavailable = "ans_receipt_unavailable"
	// ReasonSignFailed is returned when the identity's signer failed.
	ReasonSignFailed = "ans_sign_failed"
)

// Finding types and metadata keys attached to results.
const (
	// FindingIdentityAttached reports that the proof and artifacts were
	// written.
	FindingIdentityAttached = "ans_identity_attached"
	// FindingIdentityStripped reports that the identity headers were removed.
	FindingIdentityStripped = "ans_identity_stripped"
	// FindingDestinationPrefix precedes the vetting status of the destination
	// host: ans_destination_registered, ans_destination_unregistered and so on.
	FindingDestinationPrefix = "ans_destination_"
	// MetadataIdentity carries the policy's identity name.
	MetadataIdentity = "ans.identity"
	// MetadataAnsName carries the identity's ans:// name.
	MetadataAnsName = "ans.name"
	// MetadataAgentID carries the identity's agent id.
	MetadataAgentID = "ans.agent_id"
	// MetadataDestinationStatus carries the destination's vetting status.
	MetadataDestinationStatus = "ans.destination_status"
)
