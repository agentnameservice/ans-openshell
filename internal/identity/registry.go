package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/config"
)

// Config is one identities[<name>] block of the service configuration.
type Config struct {
	// AnsName is the registered ans:// name; it must equal the certificate's
	// ans:// URI SAN.
	AnsName string `yaml:"ans_name"`
	// AgentID is the registration's agent id, the key under which the
	// transparency log serves the receipt and status token.
	AgentID string `yaml:"agent_id"`
	// KeyFile holds the PEM-encoded P-256 private key (PKCS#8 or SEC1).
	KeyFile string `yaml:"key_file"`
	// CertFile holds the PEM-encoded ANS identity certificate.
	CertFile string `yaml:"cert_file"`
	// ReceiptFile and StatusTokenFile pin raw COSE_Sign1 artifacts instead of
	// fetching them from the transparency log. Both or neither must be set.
	ReceiptFile     string `yaml:"receipt_file"`
	StatusTokenFile string `yaml:"status_token_file"`
	// DevMode builds the identity from self-signed components (NewSelfSignedSigner
	// and NewSelfSignedArtifacts) instead of loading keys and certificates from
	// files. When true, KeyFile, CertFile, ReceiptFile and StatusTokenFile must
	// not be set.
	DevMode bool `yaml:"dev_mode"`
}

// Identity is one ANS identity the middleware can sign as.
type Identity struct {
	name      string
	ansName   string
	agentID   string
	signer    Signer
	artifacts ArtifactSource
}

// NewIdentity binds a signer and an artifact source to the registration they
// prove. ansName must parse as an ans:// name and agentID must be set.
func NewIdentity(name, ansName, agentID string, signer Signer, artifacts ArtifactSource) (*Identity, error) {
	if name == "" {
		return nil, errors.New("identity name must not be empty")
	}
	if _, err := verify.ParseAnsName(ansName); err != nil {
		return nil, fmt.Errorf("identity %q: ans_name: %w", name, err)
	}
	if agentID == "" {
		return nil, fmt.Errorf("identity %q: agent_id must not be empty", name)
	}
	if signer == nil {
		return nil, fmt.Errorf("identity %q: signer must not be nil", name)
	}
	if artifacts == nil {
		return nil, fmt.Errorf("identity %q: artifact source must not be nil", name)
	}
	return &Identity{name: name, ansName: ansName, agentID: agentID, signer: signer, artifacts: artifacts}, nil
}

// Name is the configuration name a policy selects the identity by.
func (i *Identity) Name() string { return i.name }

// AnsName is the registered ans:// name.
func (i *Identity) AnsName() string { return i.ansName }

// AgentID is the registration's agent id.
func (i *Identity) AgentID() string { return i.agentID }

// Signer mints the identity's DPoP proofs.
func (i *Identity) Signer() Signer { return i.signer }

// Artifacts supplies the identity's receipt and status token.
func (i *Identity) Artifacts() ArtifactSource { return i.artifacts }

// Registry is the set of identities the service holds, by configuration name.
type Registry struct {
	ids       map[string]*Identity
	closers   []func()
	closeOnce sync.Once
}

// NewRegistryFromIdentities builds a Registry from identities constructed in
// memory, for tests and demos. Names must be unique.
func NewRegistryFromIdentities(ids ...*Identity) (*Registry, error) {
	r := &Registry{ids: make(map[string]*Identity, len(ids))}
	for _, id := range ids {
		if id == nil {
			return nil, errors.New("nil identity")
		}
		if _, dup := r.ids[id.name]; dup {
			return nil, fmt.Errorf("duplicate identity %q", id.name)
		}
		r.ids[id.name] = id
	}
	return r, nil
}

// NewRegistry loads every configured identity and fails closed on the first it
// cannot prove: an ans_name that does not parse, a certificate whose ans:// SAN
// differs from it, an unusable key, or artifacts that cannot be fetched and
// verified against the pinned transparency-log root keys. Identities that pin
// receipt_file and status_token_file never touch the log; the others share one
// log client whose root keys refresh in the background. Close releases the
// background work.
func NewRegistry(ctx context.Context, identities map[string]Config, tl config.TransparencyLog,
	logger *slog.Logger) (*Registry, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	r := &Registry{ids: make(map[string]*Identity, len(identities))}
	l := &loader{tl: tl, log: logger, registry: r}
	for _, name := range slices.Sorted(maps.Keys(identities)) {
		id, err := l.identity(ctx, name, identities[name])
		if err != nil {
			r.Close()
			return nil, err
		}
		r.ids[name] = id
	}
	return r, nil
}

// Identity returns the identity registered under name.
func (r *Registry) Identity(name string) (*Identity, bool) {
	id, ok := r.ids[name]
	return id, ok
}

// Names lists the identity names in sorted order.
func (r *Registry) Names() []string {
	return slices.Sorted(maps.Keys(r.ids))
}

// Healthy reports whether every identity's artifact source is healthy.
func (r *Registry) Healthy() bool {
	return len(r.Unhealthy()) == 0
}

// Unhealthy lists, in sorted order, the identities whose artifact source
// cannot currently supply a complete, unexpired set of artifacts.
func (r *Registry) Unhealthy() []string {
	var names []string
	for name, id := range r.ids {
		if !id.artifacts.Healthy() {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// Close stops the background refresh of artifacts and root keys. It is safe to
// call more than once.
func (r *Registry) Close() {
	r.closeOnce.Do(func() {
		for _, c := range r.closers {
			c()
		}
	})
}

// loader builds identities from configuration, sharing one transparency-log
// client across those that fetch their artifacts.
type loader struct {
	tl       config.TransparencyLog
	log      *slog.Logger
	registry *Registry
	store    *scitt.KeyStore
	client   *scitt.HTTPClient
	keys     *scitt.RefreshableKeyStore
	refresh  *keyRefresher
}

func (l *loader) identity(ctx context.Context, name string, cfg Config) (*Identity, error) {
	ansName, err := verify.ParseAnsName(cfg.AnsName)
	if err != nil {
		return nil, fmt.Errorf("identity %q: ans_name: %w", name, err)
	}
	if cfg.AgentID == "" {
		return nil, fmt.Errorf("identity %q: agent_id must not be empty", name)
	}

	// Dev-mode path: build identity from self-signed components
	if cfg.DevMode {
		// Reject config that sets both dev_mode and file paths
		if cfg.KeyFile != "" || cfg.CertFile != "" {
			return nil, fmt.Errorf("identity %q: dev_mode must not set key_file/cert_file", name)
		}
		if cfg.ReceiptFile != "" || cfg.StatusTokenFile != "" {
			return nil, fmt.Errorf("identity %q: dev_mode must not set receipt_file/status_token_file", name)
		}

		// Build self-signed signer
		signer, _, cert, signerErr := NewSelfSignedSigner(cfg.AnsName)
		if signerErr != nil {
			return nil, fmt.Errorf("identity %q: self-signed signer: %w", name, signerErr)
		}

		// Build self-signed artifacts
		artifacts, artifactsErr := NewSelfSignedArtifacts(cert, cfg.AnsName, cfg.AgentID)
		if artifactsErr != nil {
			return nil, fmt.Errorf("identity %q: self-signed artifacts: %w", name, artifactsErr)
		}

		// Wrap with certificate-validity gate
		artifacts = &certificateSource{ArtifactSource: artifacts, cert: cert, now: time.Now}

		// Log dev-mode warning
		l.log.WarnContext(ctx, "dev-mode identity: self-signed, NOT vouched by any transparency log",
			"identity", name, "ans_name", cfg.AnsName)

		return NewIdentity(name, cfg.AnsName, cfg.AgentID, signer, artifacts)
	}

	// File-based path (existing code)
	signer, cert, err := loadSigner(cfg)
	if err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	if err := checkCertAnsName(cert, ansName); err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	artifacts, kind, err := l.artifacts(ctx, cfg, cert, ansName)
	if err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	artifacts = &certificateSource{ArtifactSource: artifacts, cert: cert, now: time.Now}
	l.log.InfoContext(ctx, "identity loaded",
		"identity", name, "ans_name", cfg.AnsName, "agent_id", cfg.AgentID, "artifacts", kind)
	return NewIdentity(name, cfg.AnsName, cfg.AgentID, signer, artifacts)
}

func loadSigner(cfg Config) (Signer, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read key_file: %w", err)
	}
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert_file: %w", err)
	}
	return NewPEMSigner(keyPEM, certPEM)
}

// checkCertAnsName requires the certificate's ans:// URI SAN to name the same
// version and host as the configured ans_name.
func checkCertAnsName(cert *x509.Certificate, want *verify.AnsName) error {
	got := verify.CertIdentityFromX509(cert).AnsName()
	if got == nil {
		return errors.New("certificate carries no ans:// URI SAN")
	}
	if canonicalAnsName(got) != canonicalAnsName(want) {
		return fmt.Errorf("certificate ans:// SAN %s does not match ans_name %s", got, want)
	}
	return nil
}

// canonicalAnsName renders an ans:// name on version and host alone, the
// comparison the SDK's verifier applies between certificate and status token.
func canonicalAnsName(a *verify.AnsName) string {
	return "ans://" + a.Version.String() + "." + a.Host
}

// artifacts returns the identity's artifact source and a label for logging.
// Whatever the source, the status token in hand is verified against the pinned
// root keys and must vouch for this certificate, agent id and ans_name: a
// misconfigured identity fails here instead of at every callee.
func (l *loader) artifacts(ctx context.Context, cfg Config, cert *x509.Certificate,
	ansName *verify.AnsName) (ArtifactSource, string, error) {
	if cfg.ReceiptFile != "" || cfg.StatusTokenFile != "" {
		return l.staticArtifacts(cfg, cert, ansName)
	}
	if err := l.connect(ctx); err != nil {
		return nil, "", err
	}
	client := &validatingClient{
		Client:    l.client,
		validator: &artifactValidator{keys: l.keys, cert: cert, cfg: cfg, name: ansName, now: time.Now},
		keys:      l.refresh,
	}
	supplier := scitt.NewHeaderSupplier(cfg.AgentID, client, l.keys, scitt.WithSupplierLogger(l.log))
	src, err := NewSupplierSource(ctx, supplier)
	if err != nil {
		return nil, "", err
	}
	l.registry.closers = append(l.registry.closers, src.Close)
	return src, "transparency_log", nil
}

func (l *loader) staticArtifacts(cfg Config, cert *x509.Certificate, ansName *verify.AnsName) (ArtifactSource, string, error) {
	if cfg.ReceiptFile == "" || cfg.StatusTokenFile == "" {
		return nil, "", errors.New("receipt_file and status_token_file must both be set")
	}
	receipt, token, err := readArtifactFiles(cfg.ReceiptFile, cfg.StatusTokenFile)
	if err != nil {
		return nil, "", err
	}
	store, err := l.rootKeyStore()
	if err != nil {
		return nil, "", err
	}
	validator := &artifactValidator{keys: store, cert: cert, cfg: cfg, name: ansName, now: time.Now}
	if err := validator.receipt(receipt); err != nil {
		return nil, "", err
	}
	vt, err := validator.status(token)
	if err != nil {
		return nil, "", err
	}
	src := NewStaticSourceUntil(Artifacts{
		ReceiptBase64:     base64.StdEncoding.EncodeToString(receipt),
		StatusTokenBase64: base64.StdEncoding.EncodeToString(token),
	}, time.Unix(vt.Payload.Exp, 0))
	return src, "static", nil
}

// verifyStatusToken checks that token is a valid status token under keys and
// that it vouches for exactly the identity being configured: the certificate's
// fingerprint is among its valid identity certificates, and its agent id and
// ans:// name match. The certificate must also be inside its validity period.
func verifyStatusToken(token []byte, keys scitt.KeyLookup, cert *x509.Certificate, cfg Config,
	ansName *verify.AnsName, now time.Time) (*scitt.VerifiedStatusToken, error) {
	vt, err := scitt.VerifyStatusTokenAt(token, keys, scitt.MaxClockSkew, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("status token: %w", err)
	}
	if !scitt.MatchesIdentityCert(&vt.Payload, sha256.Sum256(cert.Raw)) {
		return nil, errors.New("status token does not vouch for the configured certificate")
	}
	if vt.Payload.AgentID != cfg.AgentID {
		return nil, fmt.Errorf("status token names agent %q, configured agent_id is %q", vt.Payload.AgentID, cfg.AgentID)
	}
	tokenName, err := verify.ParseAnsName(vt.Payload.AnsName)
	if err != nil {
		return nil, fmt.Errorf("status token ans name: %w", err)
	}
	if canonicalAnsName(tokenName) != canonicalAnsName(ansName) {
		return nil, fmt.Errorf("status token names %s, configured ans_name is %s", vt.Payload.AnsName, cfg.AnsName)
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate is outside its validity period (%s to %s)",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return vt, nil
}

// connect builds the shared transparency-log client and root-key store on
// first use. At least one root key must be pinned in configuration: the log's
// own /root-keys endpoint serves rotation, not first trust.
func (l *loader) connect(ctx context.Context) error {
	if l.client != nil {
		return nil
	}
	if err := l.tl.Validate(); err != nil {
		return err
	}
	store, err := l.rootKeyStore()
	if err != nil {
		return err
	}
	var opts []scitt.HTTPClientOption
	if l.tl.AllowInsecureTransport {
		opts = append(opts, scitt.WithAllowInsecureTransport())
	}
	client, err := scitt.NewHTTPClient(l.tl.BaseURL, opts...)
	if err != nil {
		return fmt.Errorf("transparency_log: %w", err)
	}
	l.client = client
	l.keys = scitt.NewRefreshableKeyStore(store, client, scitt.WithRefreshLogger(l.log))
	l.refresh = &keyRefresher{refresh: l.keys.RefreshIfCooldownElapsed, now: time.Now}
	l.registry.closers = append(l.registry.closers, l.keys.StartBackgroundRefreshDefault(ctx))
	return nil
}

// rootKeyStore parses the pinned root keys once.
func (l *loader) rootKeyStore() (*scitt.KeyStore, error) {
	if l.store != nil {
		return l.store, nil
	}
	rootKeys, err := l.rootKeys()
	if err != nil {
		return nil, err
	}
	store, err := scitt.NewKeyStore(rootKeys)
	if err != nil {
		return nil, fmt.Errorf("transparency_log: root keys: %w", err)
	}
	l.store = store
	return store, nil
}

// rootKeys reads root_keys and root_keys_file; the file holds one C2SP key per
// line, with blank lines and '#' comments ignored.
func (l *loader) rootKeys() ([]string, error) {
	keys := slices.Clone(l.tl.RootKeys)
	if l.tl.RootKeysFile != "" {
		b, err := os.ReadFile(l.tl.RootKeysFile)
		if err != nil {
			return nil, fmt.Errorf("transparency_log: read root_keys_file: %w", err)
		}
		for line := range strings.SplitSeq(string(b), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				keys = append(keys, line)
			}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("transparency_log: at least one root key is required (root_keys or root_keys_file)")
	}
	return keys, nil
}
