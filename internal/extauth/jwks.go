package extauth

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
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const (
	maxJWKSBytes              = 64 << 10
	defaultUnknownKeyCooldown = 30 * time.Second
)

var (
	// ErrNoUsableKeys reports a JWKS document without any Ed25519 signing key.
	ErrNoUsableKeys = errors.New("extauth: jwks contains no usable Ed25519 key")
	// ErrJWKSTooLarge reports a jwks_url response over the 64 KiB cap.
	ErrJWKSTooLarge = errors.New("extauth: jwks response exceeds 64 KiB")
	// ErrInsecureJWKSURL reports a jwks_url that is not https; keys fetched
	// over plaintext could be replaced by anyone on the path.
	ErrInsecureJWKSURL = errors.New("extauth: jwks_url must use https")
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func (k jwk) publicKey() (ed25519.PublicKey, string) {
	switch {
	case k.Kty != "OKP" || k.Crv != "Ed25519":
		return nil, "not an Ed25519 OKP key"
	case k.Kid == "":
		return nil, "missing kid"
	case k.Alg != "" && k.Alg != algEdDSA:
		return nil, "alg is not EdDSA"
	case k.Use != "" && k.Use != "sig":
		return nil, "use is not sig"
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "x is not a base64url Ed25519 public key"
	}
	return ed25519.PublicKey(raw), ""
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type skippedKey struct {
	kid    string
	reason string
}

// parseJWKS returns the Ed25519 verification keys in data indexed by kid and
// the entries it skipped.
func parseJWKS(data []byte) (map[string]ed25519.PublicKey, []skippedKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, nil, fmt.Errorf("extauth: parse jwks: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	var skipped []skippedKey
	for _, k := range set.Keys {
		pub, reason := k.publicKey()
		if _, dup := keys[k.Kid]; reason == "" && dup {
			reason = "duplicate kid"
		}
		if reason != "" {
			skipped = append(skipped, skippedKey{kid: k.Kid, reason: reason})
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, skipped, ErrNoUsableKeys
	}
	return keys, skipped, nil
}

// keyStore holds the operator-provisioned keys from jwks_file, which are
// trusted for the life of the process, and the latest key set fetched from
// jwks_url, which every successful refresh replaces.
type keyStore struct {
	logger   *slog.Logger
	client   *http.Client
	now      func() time.Time
	url      string
	cooldown time.Duration

	mu        sync.Mutex
	static    map[string]ed25519.PublicKey
	remote    map[string]ed25519.PublicKey
	lastFetch time.Time
}

func newKeyStore(cfg config.Auth, logger *slog.Logger, s settings) (*keyStore, error) {
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	store := &keyStore{
		logger:   logger,
		client:   &client,
		now:      s.now,
		url:      cfg.JWKSURL,
		cooldown: defaultUnknownKeyCooldown,
		static:   map[string]ed25519.PublicKey{},
	}
	if cfg.JWKSURL != "" {
		u, err := url.Parse(cfg.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("extauth: jwks_url: %w", err)
		}
		if u.Scheme != "https" {
			return nil, ErrInsecureJWKSURL
		}
	}
	if cfg.JWKSFile == "" {
		return store, nil
	}
	data, err := os.ReadFile(cfg.JWKSFile)
	if err != nil {
		return nil, fmt.Errorf("extauth: read jwks_file: %w", err)
	}
	keys, skipped, err := parseJWKS(data)
	for _, sk := range skipped {
		logger.Warn("ignoring jwks_file entry", "kid", sk.kid, "reason", sk.reason)
	}
	if err != nil {
		return nil, fmt.Errorf("extauth: jwks_file: %w", err)
	}
	store.static = keys
	return store, nil
}

// lookup returns the key for kid, fetching jwks_url once per cooldown when
// the kid is not already known.
func (s *keyStore) lookup(ctx context.Context, kid string) (ed25519.PublicKey, bool) {
	if pub, ok := s.get(kid); ok {
		return pub, true
	}
	if !s.beginOnDemandFetch() {
		return nil, false
	}
	if err := s.refresh(ctx); err != nil {
		s.logger.WarnContext(ctx, "jwks fetch for unknown kid failed", "err", err)
		return nil, false
	}
	return s.get(kid)
}

// count returns the number of keys held across both sets.
func (s *keyStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.static) + len(s.remote)
}

func (s *keyStore) get(kid string) (ed25519.PublicKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pub, ok := s.static[kid]; ok {
		return pub, true
	}
	pub, ok := s.remote[kid]
	return pub, ok
}

// beginOnDemandFetch reports whether an unknown kid may trigger a fetch now
// and records the attempt, so concurrent misses inside the cooldown share one
// fetch instead of each starting their own.
func (s *keyStore) beginOnDemandFetch() bool {
	if s.url == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.lastFetch.IsZero() && now.Sub(s.lastFetch) < s.cooldown {
		return false
	}
	s.lastFetch = now
	return true
}

// refresh fetches jwks_url and replaces the remote key set on success.
func (s *keyStore) refresh(ctx context.Context) error {
	s.mu.Lock()
	s.lastFetch = s.now()
	s.mu.Unlock()
	body, err := s.fetch(ctx)
	if err != nil {
		return err
	}
	keys, skipped, err := parseJWKS(body)
	for _, sk := range skipped {
		s.logger.WarnContext(ctx, "ignoring jwks_url entry", "kid", sk.kid, "reason", sk.reason)
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.remote = keys
	s.mu.Unlock()
	s.logger.InfoContext(ctx, "gateway jwks refreshed", "keys", len(keys))
	return nil
}

func (s *keyStore) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, fmt.Errorf("extauth: jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req) //nolint:gosec // G704: jwks_url is operator configuration, restricted to https at construction
	if err != nil {
		return nil, fmt.Errorf("extauth: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("extauth: fetch jwks: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("extauth: read jwks: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, ErrJWKSTooLarge
	}
	return body, nil
}
