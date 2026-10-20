package vetting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TrustIndexClient reads the Trust Index value the threshold check compares
// against vetting.min_trust_score.
type TrustIndexClient interface {
	// LowestDimension returns the agent's lowest Trust Vector dimension, or
	// ErrNoTrustRecord when the Trust Index has no record for agentID.
	LowestDimension(ctx context.Context, agentID string) (float64, error)
}

// ErrNoTrustRecord reports that the Trust Index has no record for the agent.
// The lookup treats it as a score of nothing: below any positive minimum.
var ErrNoTrustRecord = errors.New("trust index: no record for agent")

const (
	maxTrustIndexResponseBytes = 1 << 20
	trustIndexDetailPath       = "/v1/ans/registered-agents/"
)

type trustVector struct {
	Integrity int `json:"integrity"`
	Identity  int `json:"identity"`
	Solvency  int `json:"solvency"`
	Behavior  int `json:"behavior"`
	Safety    int `json:"safety"`
}

type trustEvaluation struct {
	TrustVector *trustVector `json:"trustVector"`
}

type agentDetail struct {
	TrustEvaluation *trustEvaluation `json:"trustEvaluation"`
}

// HTTPTrustIndexClient reads GET /v1/ans/registered-agents/{agentId} from a
// Trust Index deployment. The detail response carries no composite score,
// only the Trust Vector's five dimensions (integrity, identity, solvency,
// behavior, safety; each an integer 0-100), so the threshold is a floor every
// dimension must clear.
type HTTPTrustIndexClient struct {
	base   string
	client *http.Client
}

// NewHTTPTrustIndexClient targets the Trust Index at baseURL. A nil client
// gets a 5 s timeout.
func NewHTTPTrustIndexClient(baseURL string, client *http.Client) (*HTTPTrustIndexClient, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("trust index: invalid base url %q: %w", baseURL, err)
	}
	if (u.Scheme != httpsScheme && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("trust index: base url %q must be http(s) with a host", baseURL)
	}
	return &HTTPTrustIndexClient{base: strings.TrimRight(u.String(), "/"), client: withoutRedirects(client)}, nil
}

// LowestDimension fetches the agent's detail record and returns the smallest of
// its five Trust Vector dimensions.
func (c *HTTPTrustIndexClient) LowestDimension(ctx context.Context, agentID string) (float64, error) {
	if agentID == "" {
		return 0, errors.New("trust index: empty agent id")
	}
	target := c.base + trustIndexDetailPath + url.PathEscape(agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, fmt.Errorf("trust index: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req) //nolint:gosec // G704: base URL is operator configuration; the agent id is path-escaped
	if err != nil {
		return 0, fmt.Errorf("trust index: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return 0, ErrNoTrustRecord
	case resp.StatusCode != http.StatusOK:
		return 0, fmt.Errorf("trust index: unexpected status %d", resp.StatusCode)
	}
	var detail agentDetail
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTrustIndexResponseBytes)).Decode(&detail); err != nil {
		return 0, fmt.Errorf("trust index: decode response: %w", err)
	}
	if detail.TrustEvaluation == nil || detail.TrustEvaluation.TrustVector == nil {
		return 0, errors.New("trust index: response has no trust vector")
	}
	tv := detail.TrustEvaluation.TrustVector
	return float64(min(tv.Integrity, tv.Identity, tv.Solvency, tv.Behavior, tv.Safety)), nil
}
