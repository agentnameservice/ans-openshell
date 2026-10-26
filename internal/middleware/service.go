package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/capability"
	"github.com/agentnameservice/ans-openshell/internal/commerce"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// Manifest identity and the protocol contract this service negotiates.
const (
	// ManifestName is the diagnostic service name in the manifest.
	ManifestName = "ans-openshell-middleware"
	// ImplementationName identifies this implementation to the gateway.
	ImplementationName = "agentnameservice/ans-openshell"
	// CapabilityContract is the supervisor-middleware contract capability.
	CapabilityContract = "openshell.supervisor-middleware.contract"
	// ProtocolMajor and ProtocolMinor form the supported protocol version.
	ProtocolMajor uint32 = 1
	ProtocolMinor uint32 = 0
)

// Defaults applied by NewService to zero Config fields.
const (
	// DefaultMaxPayloadBytes is OpenShell's 4 MiB platform cap on request
	// bodies.
	DefaultMaxPayloadBytes uint64 = 4 << 20
	// DefaultVettingBudget bounds the wait for an in-flight destination lookup
	// under require_registered.
	DefaultVettingBudget = 150 * time.Millisecond
)

// Finding attributes.
const (
	findingCount   uint32 = 1
	confidenceHigh        = "high"
	confidenceLow         = "low"
	severityInfo          = "info"
	severityLow           = "low"
	severityMedium        = "medium"
)

// Config tunes the service.
type Config struct {
	// Audience is the exact JWT audience this service verifies on inbound
	// calls; it is returned as expected_audience so the gateway refuses a
	// mis-registered service.
	Audience string
	// MaxPayloadBytes is the largest request body the binding accepts. Zero
	// selects DefaultMaxPayloadBytes.
	MaxPayloadBytes uint64
	// RequestTimeout, when positive, is advertised as the binding's
	// request_timeout (OpenShell accepts 10ms to 30s).
	RequestTimeout time.Duration
	// ImplementationVersion is the build version reported for diagnostics.
	ImplementationVersion string
	// VettingBudget bounds the wait for an in-flight destination lookup under
	// require_registered; observe never waits. Zero selects
	// DefaultVettingBudget.
	VettingBudget time.Duration
	// RequireAuthenticatedCaller denies evaluations that carry no
	// authenticated caller. Set it whenever extension authentication is on;
	// leave it off only with allow_insecure_no_auth.
	RequireAuthenticatedCaller bool
}

func (c Config) withDefaults() Config {
	if c.MaxPayloadBytes == 0 {
		c.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if c.VettingBudget <= 0 {
		c.VettingBudget = DefaultVettingBudget
	}
	return c
}

// IdentityLookup resolves the identity a policy names.
type IdentityLookup interface {
	Identity(name string) (*identity.Identity, bool)
}

// Service implements openshell.middleware.v1.SupervisorMiddleware. The
// WebSocket stream RPC is not implemented and the manifest does not advertise
// it.
type Service struct {
	middlewarev1.UnimplementedSupervisorMiddlewareServer
	ids        IdentityLookup
	authz      IdentityAuthorizer
	vet        vetting.Verifier
	cfg        Config
	log        *slog.Logger
	rewriters  []capability.Transform
	discoverer capability.Discoverer
}

// NewService builds the service. vet may be nil when destination vetting is not
// configured; policies then may not set destination_policy. A nil logger
// discards.
func NewService(ids IdentityLookup, authz IdentityAuthorizer, vet vetting.Verifier, cfg Config, logger *slog.Logger) *Service {
	if ids == nil {
		panic("middleware.NewService: nil IdentityLookup")
	}
	if authz == nil {
		panic("middleware.NewService: nil IdentityAuthorizer")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{ids: ids, authz: authz, vet: vet, cfg: cfg.withDefaults(), log: logger}
}

// AddTransform appends a Transform to the service's rewriter chain.
func (s *Service) AddTransform(t capability.Transform) *Service {
	s.rewriters = append(s.rewriters, t)
	return s
}

// WithDiscoverer sets the capability discoverer for the service.
func (s *Service) WithDiscoverer(d capability.Discoverer) *Service {
	s.discoverer = d
	return s
}

// Describe negotiates the protocol with the gateway and returns the manifest:
// one HTTP_REQUEST binding at PRE_CREDENTIALS. A gateway on another major
// protocol version or requiring a capability this service lacks gets
// FailedPrecondition.
func (s *Service) Describe(ctx context.Context,
	req *middlewarev1.MiddlewareDescribeRequest) (*middlewarev1.MiddlewareManifest, error) {
	gw := req.GetGateway()
	if err := negotiate(gw); err != nil {
		s.log.WarnContext(ctx, "describe rejected", "gateway", gw.GetImplementationName(),
			"gateway_version", gw.GetImplementationVersion(), "reason", err.Error())
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	s.log.InfoContext(ctx, "describe", "gateway", gw.GetImplementationName(),
		"gateway_version", gw.GetImplementationVersion())
	binding := &middlewarev1.MiddlewareBinding{
		Operation:       middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
		Phase:           middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		MaxPayloadBytes: s.cfg.MaxPayloadBytes,
	}
	if s.cfg.RequestTimeout > 0 {
		binding.RequestTimeout = durationpb.New(s.cfg.RequestTimeout)
	}
	responseBinding := &middlewarev1.MiddlewareBinding{
		Operation:       middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE,
		Phase:           middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN,
		MaxPayloadBytes: s.cfg.MaxPayloadBytes,
	}
	if s.cfg.RequestTimeout > 0 {
		responseBinding.RequestTimeout = durationpb.New(s.cfg.RequestTimeout)
	}
	return &middlewarev1.MiddlewareManifest{
		Name:             ManifestName,
		ServiceVersion:   s.cfg.ImplementationVersion,
		Bindings:         []*middlewarev1.MiddlewareBinding{binding, responseBinding},
		ExpectedAudience: s.cfg.Audience,
		Extension: &extensionv1.PeerMetadata{
			ProtocolVersion:       &extensionv1.ProtocolVersion{Major: ProtocolMajor, Minor: ProtocolMinor},
			ImplementationName:    ImplementationName,
			ImplementationVersion: s.cfg.ImplementationVersion,
			SupportedCapabilities: []string{CapabilityContract},
		},
	}, nil
}

func negotiate(gw *extensionv1.PeerMetadata) error {
	if major := gw.GetProtocolVersion().GetMajor(); major != ProtocolMajor {
		return fmt.Errorf("gateway protocol version %d.%d is not supported (want %d.x)",
			major, gw.GetProtocolVersion().GetMinor(), ProtocolMajor)
	}
	for _, c := range gw.GetRequiredCapabilities() {
		if c != CapabilityContract {
			return fmt.Errorf("gateway requires capability %q, which this middleware does not support", c)
		}
	}
	return nil
}

// ValidateConfig checks a policy's config block when the policy is created:
// unknown keys, unknown mode or destination_policy values, a sign policy
// without a known identity, a strip policy naming one, or a destination
// policy without vetting configured are invalid. An absent config struct is
// InvalidArgument.
func (s *Service) ValidateConfig(ctx context.Context,
	req *middlewarev1.ValidateConfigRequest) (*middlewarev1.ValidateConfigResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}
	p, err := s.parsePolicy(req.GetConfig())
	if err == nil && p.Mode == ModeSign {
		if _, ok := s.ids.Identity(p.Identity); !ok {
			err = fmt.Errorf("unknown identity %q", p.Identity)
		}
	}
	if err != nil {
		s.log.InfoContext(ctx, "policy config rejected", "middleware", req.GetMiddlewareName(), "reason", err.Error())
		return &middlewarev1.ValidateConfigResponse{Valid: false, Reason: err.Error()}, nil
	}
	return &middlewarev1.ValidateConfigResponse{Valid: true}, nil
}

// parsePolicy parses cfg and checks its shape against this service: sign needs
// an identity name, strip must not name one, and a destination policy needs
// a vetting verifier.
func (s *Service) parsePolicy(cfg *structpb.Struct) (PolicyConfig, error) {
	p, err := ParsePolicy(cfg)
	if err != nil {
		return PolicyConfig{}, err
	}
	if p.Mode == ModeSign && p.Identity == "" {
		return PolicyConfig{}, errors.New("identity is required in sign mode")
	}
	if p.Mode == ModeStrip && p.Identity != "" {
		return PolicyConfig{}, errors.New("identity must not be set in strip mode")
	}
	if p.DestinationPolicy != vetting.ModeOff && s.vet == nil {
		return PolicyConfig{}, fmt.Errorf("destination_policy %s requires destination vetting, which is not configured",
			p.DestinationPolicy)
	}
	return p, nil
}

// EvaluateHttpRequest decides one buffered request. It never returns a gRPC
// error: every failure is a DENY with a stable reason code so the decision does
// not depend on the policy's on_error setting. Header values and bodies are
// never logged.
func (s *Service) EvaluateHttpRequest(ctx context.Context, //nolint:revive,staticcheck // the generated gRPC interface fixes the name
	req *middlewarev1.HttpRequestEvaluation) (*middlewarev1.HttpRequestResult, error) {
	res := s.evaluate(ctx, req)
	attrs := []slog.Attr{
		slog.String("request_id", req.GetContext().GetRequestId()),
		slog.String("sandbox_id", req.GetContext().GetSandboxId()),
		slog.String("method", req.GetTarget().GetMethod()),
		slog.String("host", req.GetTarget().GetHost()),
	}
	if res.GetDecision() == middlewarev1.Decision_DECISION_DENY {
		attrs = append(attrs, slog.String("reason_code", res.GetReasonCode()), slog.String("reason", res.GetReason()))
		s.log.LogAttrs(ctx, denialLevel(res.GetReasonCode()), "request denied", attrs...)
	} else {
		attrs = append(attrs,
			slog.String("identity", res.GetMetadata()[MetadataIdentity]),
			slog.String("ans_name", res.GetMetadata()[MetadataAnsName]),
			slog.Int("findings", len(res.GetFindings())))
		s.log.LogAttrs(ctx, slog.LevelInfo, "request signed", attrs...)
	}
	return res, nil
}

func (s *Service) evaluate(ctx context.Context, req *middlewarev1.HttpRequestEvaluation) *middlewarev1.HttpRequestResult {
	out := &outcome{}
	if phase := req.GetPhase(); phase != middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS {
		return out.deny(&denial{ReasonUnsupportedPhase, "phase " + phase.String() + " is not bound; only PRE_CREDENTIALS is"})
	}
	if d := checkCaller(ctx, req.GetContext().GetSandboxId(), s.cfg.RequireAuthenticatedCaller); d != nil {
		return out.deny(d)
	}
	policy, err := s.parsePolicy(req.GetConfig())
	if err != nil {
		return out.deny(&denial{ReasonPolicyInvalid, "policy config: " + err.Error()})
	}
	method, target, err := requestTarget(req.GetTarget())
	if err != nil {
		return out.deny(&denial{ReasonTargetInvalid, err.Error()})
	}
	if policy.DestinationPolicy != vetting.ModeOff {
		if d := s.vetDestination(ctx, policy.DestinationPolicy, req.GetTarget().GetHost(), out); d != nil {
			return out.deny(d)
		}
	}
	if policy.Mode == ModeStrip {
		out.strip()
		return out.allow()
	}
	id, ok := s.ids.Identity(policy.Identity)
	if !ok {
		return out.deny(&denial{ReasonIdentityUnknown, fmt.Sprintf("identity %q is not configured", policy.Identity)})
	}
	if !s.authz.Allows(req.GetContext().GetSandboxId(), policy.Identity) {
		return out.deny(&denial{ReasonIdentityUnauthorized, "sandbox is not authorized to use the selected identity"})
	}

	// R1 pipeline: compute signBody, run transform chain, guard on rewritten bytes, then sign.
	signBody := req.GetBody()

	// Build target for transforms
	tool := extractToolName(signBody)
	capTarget := capability.Target{
		Host:   req.GetTarget().GetHost(),
		Method: method,
		Path:   req.GetTarget().GetPath(),
		Tool:   tool,
	}

	// Discover requirements (best-effort)
	var requirement capability.Requirement
	if s.discoverer != nil {
		requirement = s.discoverer.Discover(ctx, capTarget)
	}

	// Run transform chain
	var signURL string
	for _, t := range s.rewriters {
		tr := t.Apply(ctx, capTarget, requirement, signBody)
		switch tr.Kind {
		case capability.Deny:
			return out.deny(&denial{ReasonRewriteDenied, "rewrite denied: " + tr.Reason})
		case capability.Allow:
			signBody = tr.Body
			out.setBody(tr.Body)
			// G1: capture SignURL from transforms (last writer wins).
			signURL = tr.SignURL
			// Observability only: when debug is on, decode and log the artifacts
			// the transform attached (proof claims + mandate summary). Never
			// affects control flow; decoding is skipped unless debug is enabled.
			s.narrateArtifacts(ctx, tr)
		case capability.Passthrough:
			// Continue to next transform
		}
	}

	// Credential marker guard runs on signBody (post-chain bytes)
	if containsCredentialMarker(signBody) || containsCredentialMarker([]byte(req.GetTarget().GetPath())) {
		return out.deny(&denial{ReasonRequestRewriteUnsupported, "credential placeholders in a signed body or path require signing after credential rewriting"})
	}

	// Sign the (potentially rewritten) body with signURL (if set) or target (G1: external URL binding).
	htu := target
	if signURL != "" {
		htu = signURL
	}
	if d := s.attach(ctx, id, method, htu, signBody, out); d != nil {
		return out.deny(d)
	}
	return out.allow()
}

// denialLevel separates expected policy outcomes (INFO) from denials that mean
// the service or its dependencies are broken (WARN).
func denialLevel(code string) slog.Level {
	switch code {
	case ReasonSignFailed, ReasonStatusTokenUnavailable, ReasonReceiptUnavailable, ReasonIdentityUnknown, ReasonPolicyInvalid:
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// checkCaller binds the evaluation to its caller: only a sandbox supervisor
// evaluates requests, and only for the sandbox its credential was minted for.
// An unauthenticated call is denied when the service requires authentication
// and otherwise carries no binding to check (insecure transport mode).
func checkCaller(ctx context.Context, sandboxID string, require bool) *denial {
	c, ok := extauth.CallerFromContext(ctx)
	if !ok {
		if require {
			return &denial{ReasonCallerUnauthenticated, "no authenticated caller on an evaluation"}
		}
		return nil
	}
	if c.Kind != extauth.CallerSupervisor {
		return &denial{ReasonCallerNotSupervisor, fmt.Sprintf("caller kind %q may not evaluate requests", c.Kind)}
	}
	if c.SandboxID != sandboxID {
		return &denial{ReasonCallerSandboxMismatch,
			fmt.Sprintf("supervisor credential is for sandbox %q but the request context names %q", c.SandboxID, sandboxID)}
	}
	return nil
}

// requestTarget returns the method and bound URL of the target.
func requestTarget(t *middlewarev1.HttpRequestTarget) (string, string, error) {
	if t.GetMethod() == "" {
		return "", "", errors.New("target method is required")
	}
	target, err := TargetURL(t)
	if err != nil {
		return "", "", err
	}
	return t.GetMethod(), target, nil
}

// vetDestination records the host's verdict as a finding and denies when the
// policy mode says so. Only require_registered waits for an in-flight lookup.
func (s *Service) vetDestination(ctx context.Context, mode vetting.Mode, host string, out *outcome) *denial {
	var wait time.Duration
	if mode == vetting.ModeRequire {
		wait = s.cfg.VettingBudget
	}
	v := s.vet.Lookup(ctx, host, wait)
	label := v.Status.String()
	out.finding(FindingDestinationPrefix+label, "ANS destination "+label, destinationConfidence(v.Status), destinationSeverity(v.Status))
	out.meta(MetadataDestinationStatus, label)
	if d := vetting.Decide(mode, v); d.Deny {
		return &denial{d.ReasonCode, fmt.Sprintf("destination %s is %s under %s: %s", host, label, mode, v.Detail)}
	}
	return nil
}

// attach signs the request as id and writes the three identity headers with
// OVERWRITE, so nothing the workload sent under those names survives.
func (s *Service) attach(ctx context.Context, id *identity.Identity, method, target string, body []byte,
	out *outcome) *denial {
	arts := id.Artifacts().Current()
	if arts.StatusTokenBase64 == "" {
		return &denial{ReasonStatusTokenUnavailable, fmt.Sprintf("identity %q has no unexpired status token", id.Name())}
	}
	if arts.ReceiptBase64 == "" {
		return &denial{ReasonReceiptUnavailable, fmt.Sprintf("identity %q has no receipt", id.Name())}
	}
	proof, err := id.Signer().Sign(ctx, method, target, sha256.Sum256(body))
	if err != nil {
		return &denial{ReasonSignFailed, fmt.Sprintf("identity %q: sign: %v", id.Name(), err)}
	}
	out.write(pop.DPoPHeader, proof)
	out.write(scitt.HeaderReceipt, arts.ReceiptBase64)
	out.write(scitt.HeaderStatusToken, arts.StatusTokenBase64)
	out.finding(FindingIdentityAttached, "ANS identity attached", confidenceHigh, severityInfo)
	out.meta(MetadataIdentity, id.Name())
	out.meta(MetadataAnsName, id.AnsName())
	out.meta(MetadataAgentID, id.AgentID())
	return nil
}

// narrateArtifacts logs, at DEBUG only, the decoded artifacts a transform
// attached to an Allow'd request: the minted DPoP proof's claims and the
// authority mandate's summary. It is observability for the demo narrator and
// has no effect on the request. Decoding is skipped entirely unless the logger
// is at debug, so there is no cost (and nothing is emitted) in normal operation.
func (s *Service) narrateArtifacts(ctx context.Context, tr capability.Outcome) {
	if !s.log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	if tr.DPoPProof != "" {
		if c, err := commerce.DecodeDPoPClaims(tr.DPoPProof); err == nil {
			s.log.DebugContext(ctx, "dpop proof minted",
				"htm", c.Htm, "htu", c.Htu, "ath", c.Ath, "iat", c.Iat, "jti", c.Jti)
		}
	}
	if len(tr.MandateBytes) > 0 {
		if m, err := commerce.SummarizeMandate(tr.MandateBytes); err == nil {
			s.log.DebugContext(ctx, "mandate attached",
				"mandate_id", m.MandateID, "scope", m.Scope,
				"max_amount", m.MaxAmount, "currency", m.Currency,
				"jkt", m.JKT, "subject_ans", m.SubjectANS,
				"authority_ans", m.AuthorityANS,
				"not_before", m.NotBefore, "not_after", m.NotAfter)
		}
	}
}

func destinationSeverity(st vetting.Status) string {
	switch st {
	case vetting.StatusRegistered, vetting.StatusExempt:
		return severityInfo
	case vetting.StatusUnknown, vetting.StatusError:
		return severityLow
	case vetting.StatusUnregistered, vetting.StatusRevoked, vetting.StatusUntrustedTL, vetting.StatusBelowThreshold:
		return severityMedium
	}
	return severityMedium
}

func destinationConfidence(st vetting.Status) string {
	if st == vetting.StatusUnknown || st == vetting.StatusError {
		return confidenceLow
	}
	return confidenceHigh
}

// denial is a fail-closed decision: the stable reason code OpenShell may relay
// and the free-text reason it never does.
type denial struct {
	code   string
	reason string
}

// outcome accumulates the findings, metadata and header mutations of one
// evaluation and renders the result.
type outcome struct {
	findings  []*middlewarev1.Finding
	metadata  map[string]string
	mutations []*middlewarev1.HeaderMutation
	body      []byte
	hasBody   bool
}

func (o *outcome) finding(typ, label, confidence, severity string) {
	o.findings = append(o.findings, &middlewarev1.Finding{
		Type: typ, Label: label, Count: findingCount, Confidence: confidence, Severity: severity,
	})
}

func (o *outcome) meta(key, value string) {
	if o.metadata == nil {
		o.metadata = make(map[string]string)
	}
	o.metadata[key] = value
}

func (o *outcome) write(name, value string) {
	o.mutations = append(o.mutations, &middlewarev1.HeaderMutation{
		Operation: &middlewarev1.HeaderMutation_Write{Write: &middlewarev1.WriteHeader{
			Name:       name,
			Value:      value,
			OnExisting: middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE,
		}},
	})
}

func (o *outcome) setBody(b []byte) {
	o.body = b
	o.hasBody = true
}

// strip removes the identity headers and records the finding.
func (o *outcome) strip() {
	for _, name := range []string{pop.DPoPHeader, scitt.HeaderReceipt, scitt.HeaderStatusToken} {
		o.mutations = append(o.mutations, &middlewarev1.HeaderMutation{
			Operation: &middlewarev1.HeaderMutation_Remove{Remove: &middlewarev1.RemoveHeader{Name: name}},
		})
	}
	o.finding(FindingIdentityStripped, "ANS identity headers stripped", confidenceHigh, severityInfo)
}

func (o *outcome) allow() *middlewarev1.HttpRequestResult {
	res := &middlewarev1.HttpRequestResult{
		Decision:        middlewarev1.Decision_DECISION_ALLOW,
		HeaderMutations: o.mutations,
		Findings:        o.findings,
		Metadata:        o.metadata,
	}
	if o.hasBody {
		res.Body = o.body
		res.HasBody = true
	}
	return res
}

func (o *outcome) deny(d *denial) *middlewarev1.HttpRequestResult {
	return &middlewarev1.HttpRequestResult{
		Decision:   middlewarev1.Decision_DECISION_DENY,
		Reason:     d.reason,
		ReasonCode: d.code,
		Findings:   o.findings,
		Metadata:   o.metadata,
	}
}

// extractToolName attempts to extract the MCP tool name from a JSON-RPC request body.
// Returns empty string on any parse error or if method != "tools/call".
func extractToolName(body []byte) string {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	if req.Method != "tools/call" {
		return ""
	}
	return req.Params.Name
}
