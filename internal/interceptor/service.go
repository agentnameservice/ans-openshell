// Package interceptor implements the OpenShell gateway interceptor that vets
// the destination hosts in proposed sandbox policies and Advisor proposals
// against ANS registration before the gateway commits them.
package interceptor

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agentnameservice/ans-openshell/gen/openshell/extensionv1"
	"github.com/agentnameservice/ans-openshell/gen/openshell/interceptorv1"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

const (
	manifestName       = "ans-openshell-interceptor"
	implementationName = "agentnameservice/ans-openshell"
	contractCapability = "openshell.gateway-interceptor.contract"
	failClosed         = "fail_closed"
	protocolMajor      = 1
	protocolMinor      = 0

	statusPermissionDenied   = "PERMISSION_DENIED"
	statusFailedPrecondition = "FAILED_PRECONDITION"

	// defaultLookupWait stays under OpenShell's default 500 ms interceptor
	// timeout; the gateway does not propagate its deadline on the RPC.
	defaultLookupWait = 300 * time.Millisecond
	deadlineMargin    = 50 * time.Millisecond
	maxReasonHosts    = 10
	maxVerdictsBytes  = 1024
	maxHostLogBytes   = 64
	// maxHosts bounds the destinations one operation may name; beyond it the
	// operation is denied under require_registered rather than vetted
	// piecemeal, and only the first maxHosts are vetted under observe.
	maxHosts = 64

	annotationOutcome  = "ans.vetting"
	annotationMode     = "ans.vetting.mode"
	annotationVerdicts = "ans.vetting.verdicts"
	annotationDenied   = "ans.vetting.denied"

	outcomeSkippedPhase  = "skipped_phase"
	outcomeUnboundMethod = "unbound_method"
	outcomeDecodeError   = "decode_error"
	outcomeVettingOff    = "vetting_off"
	outcomeCallerDenied  = "caller_denied"
	outcomeTooManyHosts  = "too_many_hosts"
)

// Config selects the vetting policy the interceptor applies.
type Config struct {
	// Audience is the exact JWT audience this service verifies; it is returned
	// as expected_audience so a mis-registered gateway refuses to start.
	Audience string
	// Mode is the destination policy: off, observe or require_registered.
	Mode vetting.Mode
	// ImplementationVersion is reported to the gateway for diagnostics.
	ImplementationVersion string
	// LookupWait bounds how long one evaluation waits, in total, for cold
	// lookups under require_registered; observe never waits. Zero selects
	// 300 ms. It must stay below the registration's timeout in the gateway
	// configuration, which the gateway does not propagate as a deadline.
	LookupWait time.Duration
}

// Service implements openshell.gateway_interceptor.v1.GatewayInterceptor.
type Service struct {
	interceptorv1.UnimplementedGatewayInterceptorServer
	vet      vetting.Verifier
	cfg      Config
	logger   *slog.Logger
	bindings []binding
}

// NewService builds the interceptor around vet.
func NewService(vet vetting.Verifier, cfg Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if cfg.LookupWait <= 0 {
		cfg.LookupWait = defaultLookupWait
	}
	return &Service{
		vet:      vet,
		cfg:      cfg,
		logger:   logger,
		bindings: newBindings(),
	}
}

// Describe negotiates the protocol and returns the manifest.
func (s *Service) Describe(ctx context.Context, req *interceptorv1.DescribeRequest) (*interceptorv1.InterceptorManifest, error) {
	gw := req.GetGateway()
	if gw == nil {
		return nil, status.Error(codes.FailedPrecondition, "gateway protocol metadata is required")
	}
	version := gw.GetProtocolVersion()
	if version.GetMajor() != protocolMajor {
		return nil, status.Errorf(codes.FailedPrecondition,
			"unsupported gateway-interceptor protocol major %d, want %d", version.GetMajor(), protocolMajor)
	}
	for _, capability := range gw.GetRequiredCapabilities() {
		if capability != contractCapability {
			return nil, status.Errorf(codes.FailedPrecondition, "gateway requires unsupported capability %q", capability)
		}
	}
	s.logger.InfoContext(ctx, "gateway negotiated",
		"implementation", gw.GetImplementationName(),
		"version", gw.GetImplementationVersion(),
		"protocol", fmt.Sprintf("%d.%d", version.GetMajor(), version.GetMinor()))
	return s.manifest(), nil
}

// Evaluate vets the hosts of a validate-phase operation. Other phases, unbound
// methods and a service with vetting off are allowed untouched; an undecodable
// operation is denied because the binding is fail-closed, and only the gateway
// may evaluate.
func (s *Service) Evaluate(ctx context.Context, req *interceptorv1.InterceptorEvaluation) (*interceptorv1.InterceptorResult, error) {
	started := time.Now()
	if c, ok := extauth.CallerFromContext(ctx); ok && c.Kind != extauth.CallerGateway {
		s.logger.WarnContext(ctx, "denied evaluation from a non-gateway caller", "caller_kind", string(c.Kind), "method", req.GetMethod())
		return &interceptorv1.InterceptorResult{
			StatusCode:     statusPermissionDenied,
			Reason:         "ans destination vetting: only the gateway may evaluate operations",
			LogAnnotations: map[string]string{annotationOutcome: outcomeCallerDenied},
		}, nil
	}
	validate := req.GetValidate()
	if validate == nil {
		return s.skipped(ctx, req, outcomeSkippedPhase), nil
	}
	b, ok := s.binding(req.GetService(), req.GetMethod())
	if !ok {
		return s.skipped(ctx, req, outcomeUnboundMethod), nil
	}
	if s.cfg.Mode == vetting.ModeOff {
		return s.skipped(ctx, req, outcomeVettingOff), nil
	}
	hosts, err := b.extract(validate.GetProposedOperation())
	if err != nil {
		s.logger.WarnContext(ctx, "denied undecodable operation",
			"method", req.GetMethod(), "binding", req.GetBindingId(), "err", err)
		return &interceptorv1.InterceptorResult{
			StatusCode:     statusFailedPrecondition,
			Reason:         "ans destination vetting: proposed " + req.GetMethod() + " operation could not be decoded",
			LogAnnotations: map[string]string{annotationOutcome: outcomeDecodeError},
		}, nil
	}
	hosts = normalizeHosts(hosts)
	tooMany := len(hosts) > maxHosts
	if tooMany {
		hosts = hosts[:maxHosts]
	}
	verdicts := s.vetAll(ctx, hosts)
	denied := s.denials(hosts, verdicts)
	if tooMany && s.cfg.Mode == vetting.ModeRequire {
		denied = append(denied, fmt.Sprintf("operation names more than %d destinations", maxHosts))
	}
	result := &interceptorv1.InterceptorResult{
		Allowed: len(denied) == 0,
		LogAnnotations: map[string]string{
			annotationMode:     s.cfg.Mode.String(),
			annotationVerdicts: verdictsAnnotation(hosts, verdicts),
			annotationDenied:   strconv.FormatBool(len(denied) > 0),
		},
	}
	if tooMany {
		result.LogAnnotations[annotationOutcome] = outcomeTooManyHosts
	}
	if len(denied) > 0 {
		result.StatusCode = statusPermissionDenied
		result.Reason = denialReason(denied)
	}
	s.logger.InfoContext(ctx, "destination vetting evaluated",
		"method", req.GetMethod(), "binding", req.GetBindingId(), "mode", s.cfg.Mode.String(),
		"hosts", len(hosts), "denied", len(denied), "denied_hosts", denialReason(denied),
		"duration_ms", time.Since(started).Milliseconds())
	return result, nil
}

func (s *Service) skipped(ctx context.Context, req *interceptorv1.InterceptorEvaluation, outcome string) *interceptorv1.InterceptorResult {
	s.logger.InfoContext(ctx, "operation not vetted",
		"method", req.GetMethod(), "service", req.GetService(), "binding", req.GetBindingId(), "outcome", outcome)
	return &interceptorv1.InterceptorResult{
		Allowed:        true,
		LogAnnotations: map[string]string{annotationOutcome: outcome},
	}
}

// binding selects the binding whose rpc selector names the evaluated
// service and method.
func (s *Service) binding(service, method string) (binding, bool) {
	if service == "" || method == "" {
		return binding{}, false
	}
	rpc := service + "/" + method
	for _, b := range s.bindings {
		if b.rpc == rpc {
			return b, true
		}
	}
	return binding{}, false
}

func (s *Service) manifest() *interceptorv1.InterceptorManifest {
	bindings := make([]*interceptorv1.InterceptorBinding, 0, len(s.bindings))
	for _, b := range s.bindings {
		bindings = append(bindings, &interceptorv1.InterceptorBinding{
			Id:       b.id,
			Selector: &interceptorv1.InterceptorSelector{Rpc: b.rpc},
			Phases:   []interceptorv1.GatewayInterceptorPhase{interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE},
		})
	}
	return &interceptorv1.InterceptorManifest{
		Name:             manifestName,
		Bindings:         bindings,
		FailurePolicy:    failClosed,
		ProviderProfiles: false,
		ExpectedAudience: s.cfg.Audience,
		Extension: &extensionv1.PeerMetadata{
			ProtocolVersion:       &extensionv1.ProtocolVersion{Major: protocolMajor, Minor: protocolMinor},
			ImplementationName:    implementationName,
			ImplementationVersion: s.cfg.ImplementationVersion,
			SupportedCapabilities: []string{contractCapability},
		},
	}
}

// vetAll starts every cold lookup with a zero wait so they run concurrently.
// Under require_registered it then waits for the ones still unknown within one
// shared LookupWait budget; observe returns at once and the background lookups
// warm the cache for the next evaluation.
func (s *Service) vetAll(ctx context.Context, hosts []string) []vetting.Verdict {
	verdicts := make([]vetting.Verdict, len(hosts))
	for i, host := range hosts {
		verdicts[i] = s.vet.Lookup(ctx, host, 0)
	}
	if s.cfg.Mode != vetting.ModeRequire {
		return verdicts
	}
	deadline := time.Now().Add(s.lookupWait(ctx))
	for i, host := range hosts {
		if verdicts[i].Status != vetting.StatusUnknown {
			continue
		}
		if wait := time.Until(deadline); wait > 0 {
			verdicts[i] = s.vet.Lookup(ctx, host, wait)
		}
	}
	return verdicts
}

func (s *Service) lookupWait(ctx context.Context) time.Duration {
	wait := s.cfg.LookupWait
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)-deadlineMargin)
	}
	return max(wait, 0)
}

func (s *Service) denials(hosts []string, verdicts []vetting.Verdict) []string {
	var denied []string
	for i, v := range verdicts {
		if d := vetting.Decide(s.cfg.Mode, v); d.Deny {
			denied = append(denied, clip(hosts[i])+" "+d.ReasonCode)
		}
	}
	return denied
}

func denialReason(denied []string) string {
	if len(denied) == 0 {
		return ""
	}
	shown := denied
	if len(shown) > maxReasonHosts {
		shown = shown[:maxReasonHosts]
	}
	reason := "ans destination vetting: " + strings.Join(shown, ", ")
	if extra := len(denied) - len(shown); extra > 0 {
		reason += fmt.Sprintf(" (+%d more)", extra)
	}
	return reason
}

func verdictsAnnotation(hosts []string, verdicts []vetting.Verdict) string {
	var b strings.Builder
	for i, v := range verdicts {
		entry := clip(hosts[i]) + "=" + v.Status.String()
		if b.Len() > 0 {
			entry = "," + entry
		}
		if b.Len()+len(entry) > maxVerdictsBytes {
			if b.Len() > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "+%d more", len(verdicts)-i)
			break
		}
		b.WriteString(entry)
	}
	return b.String()
}

// clip bounds a host string in diagnostics; hosts are operator or agent
// authored and may be arbitrarily long.
func clip(host string) string {
	if len(host) <= maxHostLogBytes {
		return host
	}
	return host[:maxHostLogBytes] + "..."
}
