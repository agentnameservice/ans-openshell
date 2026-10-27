package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/agentnameservice/ans-openshell/internal/capability"
	"github.com/agentnameservice/ans-openshell/internal/commerce"
)

// commerceRewriter implements capability.Transform with discovery-aware + lenient fallback logic.
type commerceRewriter struct {
	deps       commerce.Deps
	cfg        commerce.Config
	sellerHost string
	logger     *slog.Logger
}

// NewCommerceRewriter creates a capability.Transform that applies commerce when
// (a) the requirement needs mandate + dpop_proof (discovery-driven), OR
// (b) the requirement is empty AND the static gate matches (lenient fallback).
// sellerHost is derived from cfg.SellerMCPURL's host.
func NewCommerceRewriter(deps commerce.Deps, cfg commerce.Config, sellerHost string, logger *slog.Logger) capability.Transform {
	return &commerceRewriter{deps: deps, cfg: cfg, sellerHost: sellerHost, logger: logger}
}

// Provides implements capability.Transform.
func (r *commerceRewriter) Provides() []capability.Capability {
	// Commerce rewriter provides mandate and dpop_proof capabilities
	return []capability.Capability{"mandate", "dpop_proof"}
}

// Apply implements capability.Transform.
func (r *commerceRewriter) Apply(ctx context.Context, target capability.Target, req capability.Requirement, body []byte) capability.Outcome {
	// Compute static gate match
	static := target.Host == r.sellerHost &&
		target.Method == http.MethodPost &&
		(target.Path == "/mcp/" || target.Path == "/a2a" || target.Path == "/a2a/")

	// Two-trigger logic (lenient):
	// (a) Discovery: req needs mandate + dpop_proof
	// (b) Fallback: req is empty AND static gate matches
	discoveryMatch := req.Needs("mandate") && req.Needs("dpop_proof")
	fallbackMatch := req.Empty() && static

	if !discoveryMatch && !fallbackMatch {
		return capability.Outcome{Kind: capability.Passthrough}
	}

	// WARN-log on fallback trigger
	if fallbackMatch && !discoveryMatch {
		r.logger.WarnContext(ctx, "commerce static fallback: discovery returned empty, using static host/path gate",
			"host", target.Host, "path", target.Path)
	}

	// Extract discovered htu if present
	var htuOverride string
	if req.DPoP != nil && req.DPoP.Htu != "" {
		htuOverride = req.DPoP.Htu
	}

	// Delegate to commerce.RewriteBookFlight with discovered htu
	outcome := commerce.RewriteBookFlight(ctx, body, r.deps, r.cfg, htuOverride)
	out := capability.Outcome{
		Kind:    capability.OutcomeKind(outcome.Kind),
		Body:    outcome.Body,
		Reason:  outcome.Reason,
		SignURL: outcome.SignURL,
	}
	// Stash the attached artifacts for observability (narration only). The core
	// treats Artifacts as opaque; r.Narrate decodes them.
	if outcome.Kind == commerce.Allow {
		out.Artifacts = map[string]any{
			artifactMandateBytes: outcome.MandateBytes,
			artifactDPoPProof:    outcome.DPoPProof,
		}
	}
	return out
}

// Artifact keys stashed in capability.Outcome.Artifacts for narration.
const (
	artifactMandateBytes = "mandate_bytes"
	artifactDPoPProof    = "dpop_proof"
)

// Narrate implements capability.Narratable: at debug level, it decodes and logs
// the DPoP proof claims and mandate summary this transform attached. It is
// observability only and never affects the request.
func (r *commerceRewriter) Narrate(ctx context.Context, out capability.Outcome, log *slog.Logger) {
	if !log.Enabled(ctx, slog.LevelDebug) || out.Artifacts == nil {
		return
	}
	if proof, ok := out.Artifacts[artifactDPoPProof].(string); ok && proof != "" {
		if c, err := commerce.DecodeDPoPClaims(proof); err == nil {
			log.DebugContext(ctx, "dpop proof minted",
				"htm", c.Htm, "htu", c.Htu, "ath", c.Ath, "iat", c.Iat, "jti", c.Jti)
		}
	}
	if mb, ok := out.Artifacts[artifactMandateBytes].([]byte); ok && len(mb) > 0 {
		if m, err := commerce.SummarizeMandate(mb); err == nil {
			log.DebugContext(ctx, "mandate attached",
				"mandate_id", m.MandateID, "scope", m.Scope,
				"max_amount", m.MaxAmount, "currency", m.Currency,
				"jkt", m.JKT, "subject_ans", m.SubjectANS,
				"authority_ans", m.AuthorityANS,
				"not_before", m.NotBefore, "not_after", m.NotAfter)
		}
	}
}

// ParseSellerHost extracts the host from the seller MCP URL.
func ParseSellerHost(sellerMCPURL string) (string, error) {
	u, err := url.Parse(sellerMCPURL)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}
