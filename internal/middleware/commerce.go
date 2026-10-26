package middleware

import (
	"context"
	"net/url"

	"github.com/agentnameservice/ans-openshell/internal/commerce"
)

// commerceRewriter implements CommerceRewriter with a host/path/method gate.
type commerceRewriter struct {
	deps       commerce.Deps
	cfg        commerce.Config
	sellerHost string
}

// NewCommerceRewriter creates a CommerceRewriter that gates on host==sellerHost,
// method=="POST", and path in {"/mcp/", "/a2a", "/a2a/"}.
// sellerHost is derived from cfg.SellerMCPURL's host.
func NewCommerceRewriter(deps commerce.Deps, cfg commerce.Config, sellerHost string) CommerceRewriter {
	return &commerceRewriter{deps: deps, cfg: cfg, sellerHost: sellerHost}
}

// Rewrite implements CommerceRewriter.
func (r *commerceRewriter) Rewrite(ctx context.Context, host, method, path string, body []byte) CommerceOutcome {
	// Gate: host == sellerHost && method == POST && path in {"/mcp/", "/a2a", "/a2a/"}
	if host != r.sellerHost {
		return CommerceOutcome{Kind: CommercePassthrough}
	}
	if method != "POST" {
		return CommerceOutcome{Kind: CommercePassthrough}
	}
	if path != "/mcp/" && path != "/a2a" && path != "/a2a/" {
		return CommerceOutcome{Kind: CommercePassthrough}
	}

	// Delegate to commerce.RewriteBookFlight
	outcome := commerce.RewriteBookFlight(ctx, body, r.deps, r.cfg)
	return CommerceOutcome{
		Kind:   CommerceKind(outcome.Kind),
		Body:   outcome.Body,
		Reason: outcome.Reason,
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
