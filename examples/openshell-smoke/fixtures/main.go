// Command fixtures mints the material the OpenShell smoke test needs and that a
// real deployment receives from an ANS registration and an OpenShell gateway:
// a fixture transparency log root key, one registered identity with its
// receipt and status token pinned to files, the gateway's Ed25519 JWT signing
// key with the JWKS the middleware trusts, and a private CA with a serving
// certificate for the middleware's gRPC listener. Everything is written under
// one directory with a manifest the launcher reads.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

const (
	identityName = "example-agent"
	ansName      = "ans://v1.0.0.example-agent.example.com"

	defaultStatusTokenTTL = time.Hour
	statusTokenBackoff    = time.Minute
	tlsValidity           = 24 * time.Hour
	tlsBackdate           = time.Hour
	kidBytes              = 6
	uuidBytes             = 16
	serialBits            = 128

	// RFC 4122 version 4 and variant bits for the random agent id, and the
	// masks that clear the bits they occupy.
	uuidVersion4    = 0x40
	uuidVersionMask = 0x0f
	uuidVariant     = 0x80
	uuidVariantMask = 0x3f

	dirPerm  = 0o700
	filePerm = 0o600

	manifestFile = "manifest.json"
)

// manifest is what the launcher reads to render the service configurations.
// The file layout under the output directory is fixed and documented in the
// README; the manifest carries only the values that differ per run.
type manifest struct {
	Identity string `json:"identity"`
	AnsName  string `json:"ansName"`
	AgentID  string `json:"agentId"`
	// StatusTokenExpires is when the pinned status token lapses and the
	// middleware stops signing; a --keep-running stack dies then.
	StatusTokenExpires time.Time `json:"statusTokenExpires"`
}

// options select what the bundle is minted for. random and now are the
// generator's two sources of nondeterminism, injected so tests can drive both.
type options struct {
	middlewareHosts []string
	statusTokenTTL  time.Duration
	now             func() time.Time
	random          io.Reader
}

// bundle holds every file before it is written, keyed by relative path.
type bundle struct {
	manifest manifest
	files    map[string][]byte
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fixtures:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("fixtures", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "directory to create (required; must not exist or must be empty)")
	hosts := fs.String("middleware-host", "", "comma-separated IP addresses or DNS names the middleware certificate is valid for (required)")
	ttl := fs.Duration("status-token-ttl", defaultStatusTokenTTL, "lifetime of the pinned status token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *hosts == "" {
		return errors.New("-out and -middleware-host are required")
	}
	parsedHosts, err := parseHosts(*hosts)
	if err != nil {
		return err
	}
	b, err := generate(options{middlewareHosts: parsedHosts, statusTokenTTL: *ttl, now: time.Now, random: rand.Reader})
	if err != nil {
		return err
	}
	if err := b.write(*out); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, filepath.Join(*out, manifestFile))
	return err
}

// parseHosts splits a comma-separated list and rejects empty entries.
func parseHosts(csv string) ([]string, error) {
	var hosts []string
	for h := range strings.SplitSeq(csv, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			return nil, errors.New("middleware-host: empty entry")
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return nil, errors.New("middleware-host: at least one host is required")
	}
	return hosts, nil
}

// generate mints the whole bundle in memory.
func generate(opts options) (*bundle, error) {
	if opts.statusTokenTTL <= 0 {
		return nil, errors.New("status token ttl must be positive")
	}
	if len(opts.middlewareHosts) == 0 {
		return nil, errors.New("at least one middleware host is required")
	}
	if opts.now == nil || opts.random == nil {
		return nil, errors.New("clock and random source are required")
	}
	now := opts.now()
	agentID, err := newUUID(opts.random)
	if err != nil {
		return nil, err
	}
	tl, err := testfixtures.NewTL()
	if err != nil {
		return nil, fmt.Errorf("fixture transparency log: %w", err)
	}
	ident, err := testfixtures.NewIdentityValid(agentID, ansName, now.Add(-tlsBackdate), now.Add(tlsValidity))
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	exp := now.Add(opts.statusTokenTTL)
	token := tl.StatusToken(agentID, ansName, scitt.StatusActive,
		now.Add(-statusTokenBackoff).Unix(), exp.Unix(), ident.Fingerprint)

	gw, err := newGatewayKey(opts.random)
	if err != nil {
		return nil, err
	}
	tls, err := newServerTLS(opts.random, opts.middlewareHosts, now)
	if err != nil {
		return nil, err
	}

	files := map[string][]byte{
		"tl-root-keys.txt":           []byte(tl.RootKeyC2SP() + "\n"),
		"identity/key.pem":           ident.KeyPEM,
		"identity/cert.pem":          ident.CertPEM,
		"identity/receipt.cose":      tl.Receipt(agentID, ansName),
		"identity/status-token.cose": token,
		"gateway/jwt/signing.pem":    gw.signingPEM,
		"gateway/jwt/public.pem":     gw.publicPEM,
		"gateway/jwt/kid":            []byte(gw.kid + "\n"),
		"gateway/jwks.json":          gw.jwks,
		"middleware-tls/ca.crt":      tls.caPEM,
		"middleware-tls/tls.crt":     tls.certPEM,
		"middleware-tls/tls.key":     tls.keyPEM,
	}
	return &bundle{
		manifest: manifest{
			Identity:           identityName,
			AnsName:            ansName,
			AgentID:            agentID,
			StatusTokenExpires: exp.UTC(),
		},
		files: files,
	}, nil
}

// write creates dir (or requires it to be empty) and writes every file with
// owner-only permissions. It never overwrites.
func (b *bundle) write(dir string) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty", dir)
	}
	for name, data := range b.files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
		if err := writeNew(path, data); err != nil {
			return err
		}
	}
	m, err := json.MarshalIndent(b.manifest, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, manifestFile), append(m, '\n'))
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}

// gatewayKey is the Ed25519 key an OpenShell gateway signs extension JWTs
// with, in the PKCS#8 and SPKI PEM forms its gateway_jwt block loads, plus the
// JWKS document the middleware verifies those tokens against.
type gatewayKey struct {
	signingPEM []byte
	publicPEM  []byte
	jwks       []byte
	kid        string
}

func newGatewayKey(random io.Reader) (*gatewayKey, error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("gateway signing key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	kid := "ans-smoke-" + hex.EncodeToString(sum[:kidBytes])
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}}})
	if err != nil {
		return nil, err
	}
	return &gatewayKey{
		signingPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		publicPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}),
		jwks:       append(jwks, '\n'),
		kid:        kid,
	}, nil
}

// serverTLS is a private CA and a serving certificate for the middleware's
// gRPC listener, valid for the requested IP addresses and DNS names. OpenShell
// is given the CA through tls_ca_cert_path.
type serverTLS struct {
	caPEM   []byte
	certPEM []byte
	keyPEM  []byte
}

func newServerTLS(random io.Reader, hosts []string, now time.Time) (*serverTLS, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, err
	}
	caTmpl, err := certTemplate(random, "ans-openshell smoke CA", now)
	if err != nil {
		return nil, err
	}
	caTmpl.IsCA = true
	caTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	caTmpl.BasicConstraintsValid = true
	caDER, err := x509.CreateCertificate(random, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("ca certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, err
	}
	leafTmpl, err := certTemplate(random, "ans-openshell-middleware", now)
	if err != nil {
		return nil, err
	}
	leafTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	leafTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTmpl.IPAddresses = append(leafTmpl.IPAddresses, ip)
		} else {
			leafTmpl.DNSNames = append(leafTmpl.DNSNames, h)
		}
	}
	leafDER, err := x509.CreateCertificate(random, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("middleware certificate: %w", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	return &serverTLS{
		caPEM:   testfixtures.CertificatePEM(caDER),
		certPEM: testfixtures.CertificatePEM(leafDER),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
	}, nil
}

func certTemplate(random io.Reader, commonName string, now time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(random, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-tlsBackdate),
		NotAfter:     now.Add(tlsValidity),
	}, nil
}

// newUUID returns a random RFC 4122 version 4 UUID for the agent id.
func newUUID(random io.Reader) (string, error) {
	var b [uuidBytes]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & uuidVersionMask) | uuidVersion4
	b[8] = (b[8] & uuidVariantMask) | uuidVariant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
