// Package callee is a reference ANS-6 Method B callee: an HTTP service that
// authenticates callers with the SDK's pop.Middleware and reports the proven
// identity. It exists to show, end to end, that a request signed by the
// OpenShell middleware verifies at an ordinary agent endpoint.
//
// # Live Transparency Log Configuration
//
// When TLBaseURL is set, the callee fetches and refreshes root keys from the
// transparency log at runtime. The first live run must confirm that
// scitt.FetchRootKeys against https://transparency.ans.godaddy.com returns
// parseable C2SP keys; on divergence, that's an SDK fix/bump, not a redesign.
// The static --root-keys-file flag provides an offline-rehearsal fallback.
// The --require-receipt=false flag enables rehearsal mode: under the current TL
// implementation (which returns an empty receipt), Agent A still passes on its
// valid status-token and binding, while a rogue still fails on its status token.
package callee

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const maxBodyBytes = 262144 // 256 KiB

// Config wires a Handler.
type Config struct {
	// RootKeys are the transparency log's trusted signing keys in C2SP format.
	RootKeys []string
	// TrustedHosts are the externally visible authorities this callee answers
	// on, the authority the proof's htu must name (pop.WithTrustedHosts).
	TrustedHosts []string
	// MaxReplayEntries bounds the single-use proof cache; zero selects the SDK
	// default.
	MaxReplayEntries int
	// AllowedAnsNames, when set, pins the callers this callee accepts.
	AllowedAnsNames []string
	// TLBaseURL is the transparency log's base URL for live key fetching.
	// When set, New fetches root keys from the TL and refreshes them in the
	// background.
	TLBaseURL string
	// SellerURL is the seller endpoint for receipt validation (Task 3).
	SellerURL string
	// RequireReceipt controls whether receipts are mandatory (Task 2).
	RequireReceipt bool
}

// Response is the JSON body returned to an authenticated caller.
type Response struct {
	Caller      string `json:"caller"`
	AgentID     string `json:"agentId"`
	Fingerprint string `json:"fingerprint"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	BodyBytes   int64  `json:"bodyBytes"`
}

// ReadRootKeys parses newline-delimited C2SP keys, skipping blank lines and
// lines starting with '#'.
func ReadRootKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open root keys: %w", err)
	}
	defer f.Close()
	return ParseRootKeys(f)
}

// ParseRootKeys reads newline-delimited C2SP keys from r.
func ParseRootKeys(r io.Reader) ([]string, error) {
	var keys []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read root keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("no root keys found")
	}
	return keys, nil
}

// Handler authenticates every request and echoes the caller identity (or
// forwards to a seller when SellerURL is configured).
type Handler struct {
	chain        http.Handler
	stop         func()
	logger       *slog.Logger
	sellerURL    string
	sellerClient *http.Client
}

type keystoreResult struct {
	lookup        scitt.KeyLookup
	cancelRefresh func()
}

// buildKeystore constructs either a live-TL refreshable keystore or a static one.
func buildKeystore(ctx context.Context, cfg Config) (keystoreResult, error) {
	if cfg.TLBaseURL != "" {
		return buildLiveKeystore(ctx, cfg)
	}
	store, err := scitt.NewKeyStore(cfg.RootKeys)
	if err != nil {
		return keystoreResult{}, fmt.Errorf("root keys: %w", err)
	}
	return keystoreResult{lookup: store}, nil
}

func buildLiveKeystore(ctx context.Context, cfg Config) (keystoreResult, error) {
	// For development/test: allow http:// URLs (production must use https).
	var clientOpts []scitt.HTTPClientOption
	if strings.HasPrefix(cfg.TLBaseURL, "http://") {
		clientOpts = append(clientOpts, scitt.WithAllowInsecureTransport())
	}
	client, err := scitt.NewHTTPClient(cfg.TLBaseURL, clientOpts...)
	if err != nil {
		return keystoreResult{}, fmt.Errorf("create TL client: %w", err)
	}
	keyStrings, err := client.FetchRootKeys(ctx)
	if err != nil {
		return keystoreResult{}, fmt.Errorf("fetch root keys from TL: %w", err)
	}
	// Fail loud if TL yields no keys and no static fallback.
	if len(keyStrings) == 0 && len(cfg.RootKeys) == 0 {
		return keystoreResult{}, errors.New("TL returned no root keys and no static RootKeys configured")
	}
	// Merge TL keys with any static keys for robustness.
	allKeys := make([]string, 0, len(keyStrings)+len(cfg.RootKeys))
	allKeys = append(allKeys, keyStrings...)
	allKeys = append(allKeys, cfg.RootKeys...)
	store, err := scitt.NewKeyStore(allKeys)
	if err != nil {
		return keystoreResult{}, fmt.Errorf("build keystore: %w", err)
	}
	rks := scitt.NewRefreshableKeyStore(store, client)
	cancel := rks.StartBackgroundRefreshDefault(ctx)
	return keystoreResult{lookup: rks, cancelRefresh: cancel}, nil
}

// New builds a Handler. Close releases the replay cache.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Handler, error) {
	if cfg.TLBaseURL == "" && len(cfg.RootKeys) == 0 {
		return nil, errors.New("callee: at least one transparency log root key is required (via TLBaseURL or RootKeys)")
	}
	if len(cfg.TrustedHosts) == 0 {
		return nil, errors.New("callee: at least one trusted host is required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	ks, err := buildKeystore(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("callee: %w", err)
	}

	replayCtx, cancel := context.WithCancel(ctx)
	replay := pop.NewMemoryReplayCache(replayCtx, cfg.MaxReplayEntries)
	// Build caller options: always include RequireReceipt, conditionally add AllowedAnsNames.
	callerOpts := []pop.CallerOption{pop.WithRequireReceipt(cfg.RequireReceipt)}
	if len(cfg.AllowedAnsNames) > 0 {
		callerOpts = append(callerOpts, pop.WithAllowedAnsNames(cfg.AllowedAnsNames...))
	}

	// Choose htu verification strategy and terminal handler based on SellerURL.
	var opts []pop.MiddlewareOption
	var terminalHandler http.Handler
	h := &Handler{
		stop: func() {
			if ks.cancelRefresh != nil {
				ks.cancelRefresh()
			}
			cancel()
			replay.Close()
		},
		logger:       logger,
		sellerURL:    cfg.SellerURL,
		sellerClient: http.DefaultClient,
	}

	if cfg.SellerURL != "" {
		// Forward mode: pin htu to seller URL (G1). WithExternalURL requires
		// appending r.URL.RequestURI() to bind the full request target.
		opts = []pop.MiddlewareOption{
			pop.WithExternalURL(func(r *http.Request) string {
				return cfg.SellerURL + r.URL.RequestURI()
			}),
			pop.WithMiddlewareLogger(logger),
			pop.WithMiddlewareCallerOptions(callerOpts...),
		}
		terminalHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forwardToSeller(w, r, h.sellerURL, h.sellerClient, h.logger)
		})
	} else {
		// Echo mode: verify against trusted hosts.
		opts = []pop.MiddlewareOption{
			pop.WithTrustedHosts(cfg.TrustedHosts...),
			pop.WithMiddlewareLogger(logger),
			pop.WithMiddlewareCallerOptions(callerOpts...),
		}
		terminalHandler = http.HandlerFunc(echo)
	}

	h.chain = pop.Middleware(ks.lookup, replay, opts...)(terminalHandler)
	// Wrap chain with body guard as the outermost layer.
	h.chain = bodyGuard(h.chain)
	return h, nil
}

// bodyGuard is an outer http.Handler that rejects oversize bodies with 400
// BEFORE they reach verification or the seller (matching the Rust ingress
// verifier's 256 KiB cap → 400).
func bodyGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fast path: known Content-Length > maxBodyBytes → reject immediately.
		if r.ContentLength > maxBodyBytes {
			http.Error(w, "request body too large", http.StatusBadRequest)
			return
		}

		// Unknown length (ContentLength == -1 or 0): buffer up to maxBodyBytes+1
		// to detect overflow.
		if r.ContentLength < 0 {
			buf := make([]byte, maxBodyBytes+1)
			n, err := io.ReadFull(r.Body, buf)
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				// Read error other than EOF/UnexpectedEOF (expected when body < buffer).
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			// If we read maxBodyBytes+1 bytes, the body is oversize.
			if n > maxBodyBytes {
				http.Error(w, "request body too large", http.StatusBadRequest)
				return
			}
			// Body is within limit: reset r.Body to the buffered bytes for downstream.
			r.Body = io.NopCloser(bytes.NewReader(buf[:n]))
			r.ContentLength = int64(n)
		}

		// Body is within limit (or zero): pass through to the chain.
		next.ServeHTTP(w, r)
	})
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.chain.ServeHTTP(w, r)
}

// Close releases background resources.
func (h *Handler) Close() { h.stop() }

// echo runs behind pop.Middleware, which only calls it with a verified caller
// in the context.
func echo(w http.ResponseWriter, r *http.Request) {
	id, _ := pop.CallerFromContext(r.Context())
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := Response{
		Caller:      id.AnsName,
		AgentID:     id.AgentID,
		Fingerprint: id.FingerprintHex(),
		Method:      r.Method,
		Path:        r.URL.Path,
		BodyBytes:   n,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Echo handler has no logger; use default.
		slog.Default().WarnContext(r.Context(), "encode response", "err", err)
	}
}

// forwardToSeller forwards a verified request to the seller endpoint, relaying
// the body, Content-Type, and response. It runs behind pop.Middleware (caller
// is already verified). On transport error, returns 502; on upstream error,
// relays the status as-is.
func forwardToSeller(w http.ResponseWriter, r *http.Request, sellerURL string, client *http.Client, logger *slog.Logger) {
	// Read the body (middleware has buffered and reset r.Body to the verified bytes).
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Build the upstream request with the same body and Content-Type.
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, sellerURL, bytes.NewReader(body))
	if err != nil {
		logger.ErrorContext(r.Context(), "build upstream request", "err", err)
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upstreamReq.Header.Set("Content-Type", ct)
	}

	// Send to the seller.
	upstreamResp, err := client.Do(upstreamReq)
	if err != nil {
		// Transport error (unreachable) → 502.
		logger.ErrorContext(r.Context(), "forward to seller", "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstreamResp.Body.Close()

	// Relay the seller's response status and body.
	upstreamBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		logger.ErrorContext(r.Context(), "read upstream response", "err", err)
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Copy upstream headers (at least Content-Type).
	if ct := upstreamResp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(upstreamResp.StatusCode)
	if _, err := w.Write(upstreamBody); err != nil {
		logger.WarnContext(r.Context(), "write upstream response", "err", err)
	}
}
