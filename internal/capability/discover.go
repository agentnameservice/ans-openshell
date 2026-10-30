package capability

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultDiscoveryTTL = 10 * time.Minute
	negativeCacheTTL    = 1 * time.Minute
)

// Discoverer fetches and parses a target agent's requirements from its agent card
// and MCP tools/list. All failures yield an empty Requirement (never an error return).
type Discoverer interface {
	Discover(ctx context.Context, target Target) Requirement
}

// HTTPDiscoverer is a caching HTTP-based implementation of Discoverer.
type HTTPDiscoverer struct {
	client *http.Client
	ttl    time.Duration

	mu    sync.RWMutex
	cache map[cacheKey]cacheEntry
}

type cacheKey struct {
	host string
	tool string
}

type cacheEntry struct {
	requirement Requirement
	expiresAt   time.Time
}

// NewHTTPDiscoverer creates an HTTPDiscoverer with the given HTTP client and cache TTL.
// A default TTL of 10 minutes is used if ttl is zero.
// Negative cache entries (empty requirements from failed fetches) are cached for 1 minute.
func NewHTTPDiscoverer(client *http.Client, ttl time.Duration) *HTTPDiscoverer {
	if ttl == 0 {
		ttl = defaultDiscoveryTTL
	}
	return &HTTPDiscoverer{
		client: client,
		ttl:    ttl,
		cache:  make(map[cacheKey]cacheEntry),
	}
}

// Discover fetches the agent card and MCP tools/list for the target, returning
// a Requirement with the tool's capabilities and DPoP parameters.
// Any failure returns an empty Requirement.
func (d *HTTPDiscoverer) Discover(ctx context.Context, target Target) Requirement {
	// Short-circuit: discovery only matters for MCP tool calls
	if target.Tool == "" {
		return Requirement{}
	}

	// Normalize host for caching (strip scheme if present)
	scheme := "https"
	host := target.Host
	if strings.HasPrefix(host, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	key := cacheKey{host: host, tool: target.Tool}

	// Check cache
	d.mu.RLock()
	entry, found := d.cache[key]
	d.mu.RUnlock()
	if found && time.Now().Before(entry.expiresAt) {
		return entry.requirement
	}

	// Fetch agent card
	cardURL := fmt.Sprintf("%s://%s/.well-known/agent-card.json", scheme, host)
	cardBody, err := d.fetchURL(ctx, cardURL)
	if err != nil {
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: failed to fetch agent card", "url", cardURL, "error", err)
		return d.cacheEmpty(key)
	}

	// Verify card JWS (returns true only when positively verified against fetched jku key)
	verified := verifyCardJWS(cardBody)

	// Parse DPoP params from card (only trust htu if card was positively verified)
	dpopParams, err := parseCardDPoP(cardBody)
	if err != nil {
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: failed to parse DPoP from card", "host", target.Host, "error", err)
		// DPoP is optional; continue without it
		dpopParams = nil
	} else if !verified {
		// Card not positively verified → do NOT trust discovered htu (would reach signed DPoP)
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: card not verified, clearing discovered htu", "host", target.Host)
		dpopParams = nil
	}

	// Derive MCP endpoint URL from card
	mcpURL, err := extractMCPURL(cardBody)
	if err != nil {
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: failed to extract MCP URL from card", "host", target.Host, "error", err)
		return d.cacheEmpty(key)
	}

	// Fetch MCP tools/list
	toolsList, err := d.fetchToolsList(ctx, mcpURL)
	if err != nil {
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: failed to fetch tools/list", "url", mcpURL, "error", err)
		return d.cacheEmpty(key)
	}

	// Parse required capabilities
	capabilities, err := parseToolsListRequired(toolsList, target.Tool)
	if err != nil {
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: failed to parse tools/list for tool", "tool", target.Tool, "error", err)
		return d.cacheEmpty(key)
	}

	// Confirmatory check: parse prerequisites from card skills
	prereqCaps := d.parsePrerequisitesFromCard(cardBody, target.Tool)
	if prereqCaps != nil && !capsEqual(capabilities, prereqCaps) {
		//nolint:sloglint // best-effort discovery logging
		slog.Info("discover: prerequisite mismatch (preferring structured)", "tool", target.Tool, "structured", capabilities, "confirmatory", prereqCaps)
	}

	// Build and cache requirement
	req := Requirement{
		Tool:         target.Tool,
		Capabilities: capabilities,
		DPoP:         dpopParams,
	}
	d.cacheRequirement(key, req, d.ttl)
	return req
}

func (d *HTTPDiscoverer) fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(req) //nolint:gosec // G704: url is derived from the egress target host (policy-scoped), not request input
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (d *HTTPDiscoverer) fetchToolsList(ctx context.Context, mcpURL string) ([]byte, error) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, strings.NewReader(string(reqBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req) //nolint:gosec // G704: mcpURL is derived from the egress target host (policy-scoped), not request input
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract result from JSON-RPC response
	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  interface{}     `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error: %v", rpcResp.Error)
	}
	return rpcResp.Result, nil
}

func (d *HTTPDiscoverer) parsePrerequisitesFromCard(cardBody []byte, tool string) []Capability {
	var card struct {
		Skills []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(cardBody, &card); err != nil {
		return nil
	}

	// Map tool name to skill ID (tool=book_flight may match skill id=checkout)
	// For simplicity, search both exact matches and description matches
	for _, skill := range card.Skills {
		// Try matching by description content (looking for the tool name)
		if strings.Contains(skill.Description, tool) || skill.ID == tool {
			return parsePrerequisites(skill.Description)
		}
	}
	return nil
}

func (d *HTTPDiscoverer) cacheEmpty(key cacheKey) Requirement {
	// Cache empty requirement for 1 minute (negative cache)
	d.cacheRequirement(key, Requirement{}, negativeCacheTTL)
	return Requirement{}
}

func (d *HTTPDiscoverer) cacheRequirement(key cacheKey, req Requirement, ttl time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[key] = cacheEntry{
		requirement: req,
		expiresAt:   time.Now().Add(ttl),
	}
}

// parseToolsListRequired extracts the required capabilities from an MCP tools/list response
// for the given tool name.
func parseToolsListRequired(body []byte, tool string) ([]Capability, error) {
	var toolsList struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Required []string `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &toolsList); err != nil {
		return nil, err
	}

	for _, t := range toolsList.Tools {
		if t.Name == tool {
			if len(t.InputSchema.Required) == 0 {
				return nil, nil
			}
			caps := make([]Capability, len(t.InputSchema.Required))
			for i, r := range t.InputSchema.Required {
				caps[i] = Capability(r)
			}
			return caps, nil
		}
	}
	return nil, fmt.Errorf("tool %q not found", tool)
}

// parseCardDPoP extracts DPoP parameters from an agent card's capabilities.extensions.
func parseCardDPoP(card []byte) (*DPoPParams, error) {
	var cardData struct {
		Capabilities struct {
			Extensions []struct {
				URI    string     `json:"uri"`
				Params DPoPParams `json:"params"`
			} `json:"extensions"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(card, &cardData); err != nil {
		return nil, err
	}

	for _, ext := range cardData.Capabilities.Extensions {
		if ext.URI == "https://ans.dev/ext/dpop/v1" {
			return &ext.Params, nil
		}
	}
	return nil, errors.New("DPoP extension not found")
}

// verifyCardJWS verifies the EdDSA detached-JWS signature on an agent card.
// Returns true only when the signature was positively verified against a successfully-fetched jku key.
// Returns false for: no signatures block, jku fetch failure, or signature verification failure.
//
// Current implementation: structural validation + Ed25519 signature verification
// against the key extracted from the card's trust card (jku).
// Full jku fetch + trust chain verification is deferred to a follow-up (tracked).
func verifyCardJWS(card []byte) bool {
	var cardData struct {
		Signatures []struct {
			Header    map[string]interface{} `json:"header"`
			Protected string                 `json:"protected"`
			Signature string                 `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(card, &cardData); err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: invalid card JSON", "error", err)
		return false
	}

	if len(cardData.Signatures) == 0 {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: no signatures block found (allowed but unverified)")
		return false
	}

	sig := cardData.Signatures[0]

	// Decode protected header
	protectedBytes, err := base64.RawURLEncoding.DecodeString(sig.Protected)
	if err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: invalid protected header base64", "error", err)
		return false
	}

	var protectedHeader struct {
		Alg string `json:"alg"`
		Jku string `json:"jku"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: invalid protected header JSON", "error", err)
		return false
	}

	// Check algorithm
	if protectedHeader.Alg != "EdDSA" {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: unsupported signature algorithm", "alg", protectedHeader.Alg)
		return false
	}

	// Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig.Signature)
	if err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: invalid signature base64", "error", err)
		return false
	}

	// Reconstruct the JWS signing input (detached payload)
	// For agent-card+jws, the signing input is: protected || '.' || '' (empty payload, detached)
	// However, the ACTUAL card body (without signatures) is what was signed.
	// We need to reconstruct the canonical card body without the signatures field.

	// Remove signatures field from card
	var cardMap map[string]interface{}
	if err := json.Unmarshal(card, &cardMap); err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: failed to parse card for signature verification", "error", err)
		return false
	}
	delete(cardMap, "signatures")

	// Re-serialize to canonical JSON (compact, sorted keys)
	canonicalCard, err := json.Marshal(cardMap)
	if err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: failed to canonicalize card", "error", err)
		return false
	}

	// Base64url-encode the payload
	payloadB64 := base64.RawURLEncoding.EncodeToString(canonicalCard)

	// JWS signing input: protected.payload
	signingInput := sig.Protected + "." + payloadB64

	// Fetch the public key from jku (trust card)
	// Return false if jku fetch fails (not positively verified)
	pubKey, err := fetchEdDSAPublicKey(protectedHeader.Jku, protectedHeader.Kid)
	if err != nil {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: failed to fetch public key", "jku", protectedHeader.Jku, "kid", protectedHeader.Kid, "error", err)
		return false
	}

	// Verify Ed25519 signature
	if !ed25519.Verify(pubKey, []byte(signingInput), sigBytes) {
		//nolint:sloglint // best-effort JWS verification logging
		slog.Info("verifyCardJWS: signature verification failed")
		return false
	}

	// Positively verified
	return true
}

// fetchEdDSAPublicKey fetches the Ed25519 public key from a JWK Set URL.
// This is a best-effort implementation for v1.
func fetchEdDSAPublicKey(jkuURL, kid string) (ed25519.PublicKey, error) {
	// For v1, we'll fetch the key but won't do full trust chain validation.
	// That's a follow-up task.
	//nolint:gosec,noctx // v1 best-effort key fetch; context propagation deferred
	resp, err := http.Get(jkuURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "OKP" && key.Crv == "Ed25519" {
			xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
			if err != nil {
				return nil, fmt.Errorf("invalid key X coordinate: %w", err)
			}
			if len(xBytes) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid Ed25519 key size: %d", len(xBytes))
			}
			return ed25519.PublicKey(xBytes), nil
		}
	}
	return nil, fmt.Errorf("key %s not found in JWK Set", kid)
}

// parsePrerequisites extracts capability names from a skill description's "Prerequisites:" clause.
// Returns nil if the clause is absent or unparseable. Never panics.
func parsePrerequisites(desc string) []Capability {
	idx := strings.Index(desc, "Prerequisites:")
	if idx == -1 {
		return nil
	}

	// Extract the substring after "Prerequisites:"
	remainder := desc[idx+len("Prerequisites:"):]

	// Find the end (period or end of string)
	endIdx := strings.Index(remainder, ".")
	if endIdx != -1 {
		remainder = remainder[:endIdx]
	}

	// Split on ", " and trim spaces
	parts := strings.Split(remainder, ",")
	var caps []Capability
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			caps = append(caps, Capability(part))
		}
	}
	return caps
}

// extractMCPURL extracts the MCP endpoint URL from an agent card.
func extractMCPURL(card []byte) (string, error) {
	// Try extensions first (preferred)
	var cardData struct {
		Capabilities struct {
			Extensions []struct {
				URI    string `json:"uri"`
				Params struct {
					Endpoint string `json:"endpoint"`
				} `json:"params"`
			} `json:"extensions"`
		} `json:"capabilities"`
		SupportedInterfaces []struct {
			ProtocolBinding string `json:"protocolBinding"`
			URL             string `json:"url"`
		} `json:"supportedInterfaces"`
	}
	if err := json.Unmarshal(card, &cardData); err != nil {
		return "", err
	}

	// Check for MCP extension
	for _, ext := range cardData.Capabilities.Extensions {
		if ext.URI == "https://modelcontextprotocol.io/ext/server/v1" && ext.Params.Endpoint != "" {
			return ext.Params.Endpoint, nil
		}
	}

	// Fallback to supportedInterfaces
	for _, iface := range cardData.SupportedInterfaces {
		if strings.Contains(iface.ProtocolBinding, "modelcontextprotocol.io") {
			return iface.URL, nil
		}
	}

	return "", errors.New("MCP URL not found in card")
}

// capsEqual checks if two capability slices contain the same elements (order-independent).
func capsEqual(a, b []Capability) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[Capability]bool)
	for _, cap := range a {
		aMap[cap] = true
	}
	for _, cap := range b {
		if !aMap[cap] {
			return false
		}
	}
	return true
}
