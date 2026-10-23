// Package hydrator turns OpenShell's OCSF audit export into behavioral
// observations for the ANS Trust Index.
//
// The input is OpenShell's OCSF JSON export in either of its two forms: a
// JSONL file with one OCSF v1.8.0 object per line, or supervisor stderr where
// each record appears as "<timestamp> OCSF-JSON {...}" among shorthand lines
// that are ignored. Every line is untrusted: lines are bounded by
// MaxLineBytes, unknown fields are ignored, missing fields are tolerated and a
// malformed line is counted and skipped, never fatal.
//
// Events are attributed to agents through their sandbox (container.uid, then
// container.name). Records that OpenShell downgraded to OCSF 1.1 or 1.3 have
// the container stripped and therefore cannot be attributed; they are counted
// as unmapped.
//
// Per agent and input window the package aggregates Network Activity (4001)
// and HTTP Activity (4002) events into two observations. An event counts as
// denied when any of action_id, disposition_id or status_id equals 2 (Denied,
// Blocked, Failure). A record with status_id Failure therefore counts as denied
// even when its action says Allowed. This is the legacy over-reporting rule;
// an HTTP response code such as 503 does not itself supply status_id Failure.
//
// The signal identifiers for these observations are not yet registered in the
// Trust Index. They are configurable through SignalConfig and default to
// "openshell.policyViolationRate" and "openshell.protocolAdherence"; a Trust
// Index deployment must register signals under those identifiers (or the
// configured ones) before it accepts the import.
//
// The optional openshell.behavior.activity output uses corrected policy
// decisions and the reference implementation's generic numeric score value.
// It keeps connection, initial HTTP, post-rewrite and WebSocket checks separate;
// execution status, sessions, operational failures and findings are not policy
// decisions. Findings remain evidence and never change this score. Unknown
// policy syntax or exhausted evidence limits suppress the affected new score.
// Options.Evidence writes structured JSONL even without a numeric assessment.
// The legacy signals retain their existing formats and behavior.
//
// Register the new signal before enabling its output and keep its profile
// weight at zero: the reference implementation retains old scores when a new
// report is skipped, without automatic expiry. See docs/hydrator-activity.md.
//
// Batches are posted to the Trust Index import API
// (POST /v1/internal/observations/import) with the admin key presented as
// "Authorization: Bearer <key>". A batch may additionally be signed with the
// operator's ANS identity key through a provenance.BatchSigner: a compact
// ES256 JWS over the request body that the sink sends in the
// BatchSignatureHeader header. This signature format is a proposal pending
// Trust Index support; the Trust Index currently ignores the header, and
// pkg/provenance ships Verify so it can adopt the format.
package hydrator
