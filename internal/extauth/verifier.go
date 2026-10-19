package extauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

const (
	algEdDSA  = "EdDSA"
	headerTyp = "openshell-ext+jwt"

	maxTokenBytes          = 8 << 10
	jwsSegments            = 3
	clockSkew              = 30 * time.Second
	maxLifetime            = time.Hour
	defaultRefreshInterval = 5 * time.Minute
	minRefreshInterval     = 30 * time.Second
	defaultHTTPTimeout     = 5 * time.Second
)

var (
	// ErrTokenTooLarge reports a token over the 8 KiB cap.
	ErrTokenTooLarge = errors.New("extauth: token exceeds 8 KiB")
	// ErrMalformedToken reports a token that is not a three-segment compact
	// JWS with a JSON header.
	ErrMalformedToken = errors.New("extauth: malformed token")
	// ErrUnsupportedAlg reports a header alg other than EdDSA.
	ErrUnsupportedAlg = errors.New("extauth: unsupported alg")
	// ErrUnexpectedTokenType reports a header typ other than openshell-ext+jwt.
	ErrUnexpectedTokenType = errors.New("extauth: unexpected typ")
	// ErrUnknownKey reports a missing kid or one that no trusted key set holds.
	ErrUnknownKey = errors.New("extauth: unknown signing key")
	// ErrInvalidSignature reports a signature that does not verify.
	ErrInvalidSignature = errors.New("extauth: invalid signature")
	// ErrInvalidClaims reports claims that are missing, empty or of the wrong
	// JSON type.
	ErrInvalidClaims = errors.New("extauth: invalid claims")
	// ErrIssuerMismatch reports an iss other than the configured gateway issuer.
	ErrIssuerMismatch = errors.New("extauth: issuer mismatch")
	// ErrAudienceMismatch reports an aud other than the configured audience.
	ErrAudienceMismatch = errors.New("extauth: audience mismatch")
	// ErrTokenExpired reports an exp in the past beyond the clock skew.
	ErrTokenExpired = errors.New("extauth: token expired")
	// ErrTokenNotYetValid reports an iat in the future beyond the clock skew.
	ErrTokenNotYetValid = errors.New("extauth: token issued in the future")
	// ErrTokenLifetime reports a lifetime that is not positive or exceeds one hour.
	ErrTokenLifetime = errors.New("extauth: token lifetime out of bounds")
	// ErrInvalidCaller reports an unknown caller_kind or a sandbox_id that
	// does not match the caller kind.
	ErrInvalidCaller = errors.New("extauth: invalid caller_kind or sandbox_id")
)

type settings struct {
	now             func() time.Time
	client          *http.Client
	refreshInterval time.Duration
}

// Option adjusts a Verifier.
type Option func(*settings)

// WithClock replaces the wall clock used for claim checks and the fetch cooldown.
func WithClock(now func() time.Time) Option {
	return func(s *settings) { s.now = now }
}

// WithHTTPClient replaces the client that fetches jwks_url.
func WithHTTPClient(c *http.Client) Option {
	return func(s *settings) { s.client = c }
}

// WithRefreshInterval overrides the jwks_url polling interval used by Run.
func WithRefreshInterval(d time.Duration) Option {
	return func(s *settings) { s.refreshInterval = d }
}

// Verifier authenticates OpenShell extension tokens against the gateway's
// signing keys.
type Verifier struct {
	logger          *slog.Logger
	issuer          string
	audience        string
	insecure        bool
	now             func() time.Time
	refreshInterval time.Duration
	keys            *keyStore
}

// NewVerifier loads the trust anchor from cfg.JWKSFile and prepares refresh
// from cfg.JWKSURL. With cfg.AllowInsecureNoAuth the interceptors pass every
// call through unauthenticated, which is logged once here.
func NewVerifier(cfg config.Auth, logger *slog.Logger, opts ...Option) (*Verifier, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := settings{
		now:             time.Now,
		client:          &http.Client{Timeout: defaultHTTPTimeout},
		refreshInterval: defaultRefreshInterval,
	}
	if cfg.JWKSRefreshInterval > 0 {
		s.refreshInterval = max(cfg.JWKSRefreshInterval, minRefreshInterval)
	}
	for _, opt := range opts {
		opt(&s)
	}
	v := &Verifier{
		logger:          logger,
		issuer:          cfg.GatewayIssuer,
		audience:        cfg.Audience,
		insecure:        cfg.AllowInsecureNoAuth,
		now:             s.now,
		refreshInterval: s.refreshInterval,
	}
	if v.insecure {
		logger.Warn("extension authentication disabled: allow_insecure_no_auth is set, every caller is trusted")
		v.keys = &keyStore{logger: logger, now: s.now}
		return v, nil
	}
	keys, err := newKeyStore(cfg, logger, s)
	if err != nil {
		return nil, err
	}
	v.keys = keys
	return v, nil
}

// Run refreshes the keys from jwks_url now and then every refresh interval.
// It blocks until ctx is done; without a jwks_url it only waits.
func (v *Verifier) Run(ctx context.Context) {
	if v.keys.url == "" {
		<-ctx.Done()
		return
	}
	v.refreshKeys(ctx)
	ticker := time.NewTicker(v.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.refreshKeys(ctx)
		}
	}
}

// Verify checks token and returns the caller it proves.
func (v *Verifier) Verify(ctx context.Context, token string) (Caller, error) {
	if len(token) > maxTokenBytes {
		return Caller{}, ErrTokenTooLarge
	}
	parts := strings.Split(token, ".")
	if len(parts) != jwsSegments {
		return Caller{}, fmt.Errorf("%w: expected %d segments", ErrMalformedToken, jwsSegments)
	}
	kid, err := checkHeader(parts[0])
	if err != nil {
		return Caller{}, err
	}
	pub, ok := v.keys.lookup(ctx, kid)
	if !ok {
		return Caller{}, ErrUnknownKey
	}
	sig, err := decodeSegment(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Caller{}, ErrInvalidSignature
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Caller{}, ErrInvalidSignature
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return Caller{}, fmt.Errorf("%w: payload is not base64url", ErrMalformedToken)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Caller{}, fmt.Errorf("%w: payload is not a claims object", ErrInvalidClaims)
	}
	return c.caller(v.issuer, v.audience, v.now())
}

func (v *Verifier) refreshKeys(ctx context.Context) {
	err := v.keys.refresh(ctx)
	switch {
	case err == nil:
	case v.keys.count() == 0:
		v.logger.ErrorContext(ctx, "scheduled jwks refresh failed and no verification key is held; every call is rejected", "err", err)
	default:
		v.logger.WarnContext(ctx, "scheduled jwks refresh failed; continuing with the keys held", "err", err)
	}
}

// Ready reports whether the verifier can accept a call: it is in insecure
// mode or holds at least one verification key.
func (v *Verifier) Ready() bool {
	return v.insecure || v.keys.count() > 0
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// checkHeader decodes the JOSE header and returns its kid once alg and typ
// match the OpenShell extension token contract.
func checkHeader(segment string) (string, error) {
	raw, err := decodeSegment(segment)
	if err != nil {
		return "", fmt.Errorf("%w: header is not base64url", ErrMalformedToken)
	}
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", fmt.Errorf("%w: header is not a JSON object", ErrMalformedToken)
	}
	switch {
	case h.Alg != algEdDSA:
		return "", ErrUnsupportedAlg
	case h.Typ != headerTyp:
		return "", ErrUnexpectedTokenType
	case h.Kid == "":
		return "", fmt.Errorf("%w: kid is required", ErrUnknownKey)
	}
	return h.Kid, nil
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

type claims struct {
	Issuer     string `json:"iss"`
	Audience   string `json:"aud"`
	Subject    string `json:"sub"`
	IssuedAt   *int64 `json:"iat"`
	ExpiresAt  *int64 `json:"exp"`
	ID         string `json:"jti"`
	CallerKind string `json:"caller_kind"`
	SandboxID  string `json:"sandbox_id"`
}

func (c claims) caller(issuer, audience string, now time.Time) (Caller, error) {
	if err := c.checkPresence(); err != nil {
		return Caller{}, err
	}
	if c.Issuer != issuer {
		return Caller{}, ErrIssuerMismatch
	}
	if c.Audience != audience {
		return Caller{}, ErrAudienceMismatch
	}
	if err := checkTimes(*c.IssuedAt, *c.ExpiresAt, now); err != nil {
		return Caller{}, err
	}
	kind := CallerKind(c.CallerKind)
	switch kind {
	case CallerGateway:
		if c.SandboxID != "" {
			return Caller{}, fmt.Errorf("%w: sandbox_id is only valid for supervisor callers", ErrInvalidCaller)
		}
	case CallerSupervisor:
		if c.SandboxID == "" {
			return Caller{}, fmt.Errorf("%w: supervisor callers require sandbox_id", ErrInvalidCaller)
		}
	default:
		return Caller{}, fmt.Errorf("%w: unknown caller_kind", ErrInvalidCaller)
	}
	return Caller{Kind: kind, Issuer: c.Issuer, Subject: c.Subject, SandboxID: c.SandboxID}, nil
}

func (c claims) checkPresence() error {
	switch {
	case c.IssuedAt == nil || c.ExpiresAt == nil:
		return fmt.Errorf("%w: iat and exp are required", ErrInvalidClaims)
	case *c.IssuedAt < 0 || *c.ExpiresAt < 0:
		return fmt.Errorf("%w: iat and exp must not be negative", ErrInvalidClaims)
	case c.Subject == "":
		return fmt.Errorf("%w: sub is required", ErrInvalidClaims)
	case c.ID == "":
		return fmt.Errorf("%w: jti is required", ErrInvalidClaims)
	}
	return nil
}

func checkTimes(iat, exp int64, now time.Time) error {
	unix := now.Unix()
	skew := int64(clockSkew.Seconds())
	switch {
	case unix >= exp+skew:
		return ErrTokenExpired
	case iat > unix+skew:
		return ErrTokenNotYetValid
	case exp <= iat || exp-iat > int64(maxLifetime.Seconds()):
		return ErrTokenLifetime
	}
	return nil
}
