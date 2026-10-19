package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/callee"
	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/grpcserver"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	"github.com/agentnameservice/ans-openshell/internal/middleware"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

const (
	agentID     = "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
	ansName     = "ans://v1.0.0.payments.example.com"
	identityKey = "payments-agent"
	staleKey    = "stale-agent"
	staleID     = "0d2c9d1e-7f3a-4b7e-9c11-2a6e8f4b1c55"
	staleName   = "ans://v1.0.0.stale.example.com"

	gatewayIssuer = "openshell-gateway:demo"
	audience      = "urn:openshell:extension:middleware:ans"
	gatewayKid    = "demo-gateway-key"
	sandboxID     = "sb-7f2e"

	tokenTTL      = 5 * time.Minute
	headerTimeout = 5 * time.Second
	filePerm      = 0o600
)

// demo owns every process the supervisor would talk to.
type demo struct {
	out    io.Writer
	logger *slog.Logger

	tl     *testfixtures.TL
	ident  *testfixtures.Identity
	tlSrv  *httptest.Server
	gwKey  ed25519.PrivateKey
	callee *calleeServer
	mw     *grpcserver.Server
	client middlewarev1.SupervisorMiddlewareClient
	conn   *grpc.ClientConn

	fileRegistry *identity.Registry
	registry     *identity.Registry
	vet          *vetting.Service
	tmpDir       string
	failures     int
}

type calleeServer struct {
	authority string
	handler   *callee.Handler
	srv       *http.Server
}

func newDemo(ctx context.Context, out io.Writer) (*demo, error) {
	d := &demo{out: out, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	d.tl = testfixtures.MustNewTL()
	d.ident = testfixtures.MustNewIdentity(agentID, ansName)
	d.tlSrv = testfixtures.FakeTLServer(d.tl, d.ident)
	d.section("Fixtures")
	d.sayf("transparency log at %s, root key %s...", d.tlSrv.URL, d.tl.RootKeyC2SP()[:24])
	d.sayf("agent %s registered as %s", agentID, ansName)

	dir, err := os.MkdirTemp("", "ans-openshell-demo-")
	if err != nil {
		return nil, err
	}
	d.tmpDir = dir
	jwksFile, err := d.writeGatewayJWKS(dir)
	if err != nil {
		return nil, err
	}
	if err := d.startCallee(ctx); err != nil {
		return nil, err
	}
	if err := d.startMiddleware(ctx, dir, jwksFile); err != nil {
		return nil, err
	}
	return d, nil
}

// writeGatewayJWKS mints the gateway's Ed25519 signing key and writes the JWKS
// the middleware trusts, standing in for the operator-provisioned
// /.well-known/jwks.json.
func (d *demo) writeGatewayJWKS(dir string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	d.gwKey = priv
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": gatewayKid, "alg": "EdDSA",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}}}
	b, err := json.Marshal(jwks)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "gateway-jwks.json")
	return path, os.WriteFile(path, b, filePerm)
}

func (d *demo) startCallee(ctx context.Context) error {
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	authority := lis.Addr().String()
	h, err := callee.New(ctx, callee.Config{
		RootKeys:     []string{d.tl.RootKeyC2SP()},
		TrustedHosts: []string{authority},
	}, d.logger)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: headerTimeout}
	go func() { _ = srv.Serve(lis) }()
	d.callee = &calleeServer{authority: authority, handler: h, srv: srv}
	d.section("Reference callee")
	d.sayf("listening on http://%s, trusting the fixture log, verifying ANS-6 Method B with pop.Middleware", authority)
	return nil
}

func (d *demo) startMiddleware(ctx context.Context, dir, jwksFile string) error {
	keyFile, certFile := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(keyFile, d.ident.KeyPEM, filePerm); err != nil {
		return err
	}
	if err := os.WriteFile(certFile, d.ident.CertPEM, filePerm); err != nil {
		return err
	}
	fileRegistry, err := identity.NewRegistry(ctx, map[string]identity.Config{
		identityKey: {AnsName: ansName, AgentID: agentID, KeyFile: keyFile, CertFile: certFile},
	}, config.TransparencyLog{
		BaseURL:                d.tlSrv.URL,
		RootKeys:               []string{d.tl.RootKeyC2SP()},
		AllowInsecureTransport: true,
	}, d.logger)
	if err != nil {
		return fmt.Errorf("identity registry: %w", err)
	}
	d.fileRegistry = fileRegistry
	live, _ := fileRegistry.Identity(identityKey)
	stale, err := d.staleIdentity()
	if err != nil {
		return err
	}
	d.registry, err = identity.NewRegistryFromIdentities(live, stale)
	if err != nil {
		return err
	}

	d.vet, err = vetting.New(config.Vetting{TrustedTLDomains: []string{"tl.example.com"}},
		vetting.Deps{DNS: verify.NewMockDNSResolver()}, d.logger)
	if err != nil {
		return err
	}
	auth, err := extauth.NewVerifier(config.Auth{GatewayIssuer: gatewayIssuer, Audience: audience, JWKSFile: jwksFile}, d.logger)
	if err != nil {
		return err
	}
	d.mw, err = grpcserver.New(ctx, grpcserver.Options{
		Listen: "127.0.0.1:0",
		Unary:  []grpc.UnaryServerInterceptor{auth.UnaryInterceptor()},
		Stream: []grpc.StreamServerInterceptor{auth.StreamInterceptor()},
	}, d.logger)
	if err != nil {
		return err
	}
	authz, err := middleware.NewSandboxIdentities(map[string]string{sandboxID: identityKey}, d.registry)
	if err != nil {
		return err
	}
	svc := middleware.NewService(d.registry, authz, d.vet, middleware.Config{Audience: audience, ImplementationVersion: "demo"}, d.logger)
	middlewarev1.RegisterSupervisorMiddlewareServer(d.mw.Registrar(), svc)
	go func() { _ = d.mw.Serve(ctx) }()

	d.conn, err = grpc.NewClient(d.mw.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	d.client = middlewarev1.NewSupervisorMiddlewareClient(d.conn)
	d.section("Middleware")
	d.sayf("gRPC on %s; identity %q loaded from PEM files, artifacts fetched from the log; gateway JWTs verified against %s",
		d.mw.Addr(), identityKey, filepath.Base(jwksFile))
	return nil
}

// staleIdentity has a receipt but no unexpired status token, the state the
// SDK's HeaderSupplier reports once a token has lapsed and refresh has failed.
func (d *demo) staleIdentity() (*identity.Identity, error) {
	fixture := testfixtures.MustNewIdentity(staleID, staleName)
	signer, _, err := identity.NewPEMSigner(fixture.KeyPEM, fixture.CertPEM)
	if err != nil {
		return nil, err
	}
	receipt, _ := testfixtures.StaticArtifacts(d.tl, fixture)
	return identity.NewIdentity(staleKey, staleName, staleID, signer,
		identity.NewStaticSource(identity.Artifacts{ReceiptBase64: receipt}))
}

func (d *demo) close() {
	if d.conn != nil {
		_ = d.conn.Close()
	}
	if d.callee != nil {
		_ = d.callee.srv.Close()
		d.callee.handler.Close()
	}
	if d.vet != nil {
		d.vet.Close()
	}
	if d.registry != nil {
		d.registry.Close()
	}
	if d.fileRegistry != nil {
		d.fileRegistry.Close()
	}
	if d.tlSrv != nil {
		d.tlSrv.Close()
	}
	if d.tmpDir != "" {
		_ = os.RemoveAll(d.tmpDir)
	}
}

func (d *demo) section(title string) { fmt.Fprintf(d.out, "\n== %s ==\n", title) }

func (d *demo) sayf(format string, args ...any) { fmt.Fprintf(d.out, "   "+format+"\n", args...) }

// check records one expectation and prints PASS or FAIL.
func (d *demo) check(name string, ok bool, detail string) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		d.failures++
	}
	fmt.Fprintf(d.out, "%s  %s  (%s)\n", mark, name, detail)
}
