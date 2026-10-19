// Package callee is a reference ANS-6 Method B callee: an HTTP service that
// authenticates callers with the SDK's pop.Middleware and reports the proven
// identity. It exists to show, end to end, that a request signed by the
// OpenShell middleware verifies at an ordinary agent endpoint.
package callee

import (
	"bufio"
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

// Handler authenticates every request and echoes the caller identity.
type Handler struct {
	chain  http.Handler
	stop   func()
	logger *slog.Logger
}

// New builds a Handler. Close releases the replay cache.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Handler, error) {
	if len(cfg.RootKeys) == 0 {
		return nil, errors.New("callee: at least one transparency log root key is required")
	}
	if len(cfg.TrustedHosts) == 0 {
		return nil, errors.New("callee: at least one trusted host is required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	keys, err := scitt.NewKeyStore(cfg.RootKeys)
	if err != nil {
		return nil, fmt.Errorf("callee: root keys: %w", err)
	}
	replayCtx, cancel := context.WithCancel(ctx)
	replay := pop.NewMemoryReplayCache(replayCtx, cfg.MaxReplayEntries)
	opts := []pop.MiddlewareOption{
		pop.WithTrustedHosts(cfg.TrustedHosts...),
		pop.WithMiddlewareLogger(logger),
	}
	if len(cfg.AllowedAnsNames) > 0 {
		opts = append(opts, pop.WithMiddlewareCallerOptions(pop.WithAllowedAnsNames(cfg.AllowedAnsNames...)))
	}
	h := &Handler{
		stop: func() {
			cancel()
			replay.Close()
		},
		logger: logger,
	}
	h.chain = pop.Middleware(keys, replay, opts...)(http.HandlerFunc(h.echo))
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.chain.ServeHTTP(w, r)
}

// Close releases background resources.
func (h *Handler) Close() { h.stop() }

// echo runs behind pop.Middleware, which only calls it with a verified caller
// in the context.
func (h *Handler) echo(w http.ResponseWriter, r *http.Request) {
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
		h.logger.WarnContext(r.Context(), "encode response", "err", err)
	}
}
