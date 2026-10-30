package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/identity"
	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// callee is an HTTP service authenticating callers with the SDK's
// pop.Middleware, the way an ANS-6 Method B callee does.
type callee struct {
	srv  *httptest.Server
	host string
	port uint32
}

func newCallee(t *testing.T, tl *testfixtures.TL) *callee {
	t.Helper()
	replay := pop.NewMemoryReplayCache(t.Context(), 0)
	t.Cleanup(replay.Close)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pop.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, id.AnsName)
	})
	srv := httptest.NewUnstartedServer(nil)
	authority := srv.Listener.Addr().String()
	srv.Config.Handler = pop.Middleware(tl.KeyStore(), replay,
		pop.WithTrustedHosts(authority), pop.WithMiddlewareLogger(slog.New(slog.DiscardHandler)))(echo)
	srv.Start()
	t.Cleanup(srv.Close)
	addr, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T is not TCP", srv.Listener.Addr())
	}
	return &callee{srv: srv, host: addr.IP.String(), port: uint32(addr.Port)}
}

// evaluationFor describes a request to the callee the way the supervisor would.
func (c *callee) evaluationFor(t *testing.T, policy map[string]any, method, path string, body []byte) *middlewarev1.HttpRequestEvaluation {
	t.Helper()
	return &middlewarev1.HttpRequestEvaluation{
		Phase:   preCredentials,
		Context: &middlewarev1.RequestContext{RequestId: "req-e2e", SandboxId: testSandbox},
		Config:  structOf(t, policy),
		Target:  &middlewarev1.HttpRequestTarget{Scheme: "http", Host: c.host, Port: c.port, Method: method, Path: path},
		Body:    body,
	}
}

// send applies the middleware's header mutations to a real request with the
// same method, path and body and returns the callee's response.
func (c *callee) send(t *testing.T, res *middlewarev1.HttpRequestResult, method, path string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, c.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Dpop", "smuggled-by-workload")
	for _, m := range res.GetHeaderMutations() {
		switch op := m.GetOperation().(type) {
		case *middlewarev1.HeaderMutation_Write:
			if op.Write.GetOnExisting() != middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE {
				t.Fatalf("mutation %v is not OVERWRITE", m)
			}
			req.Header.Set(op.Write.GetName(), op.Write.GetValue())
		case *middlewarev1.HeaderMutation_Remove:
			req.Header.Del(op.Remove.GetName())
		default:
			t.Fatalf("unexpected mutation %v", m)
		}
	}
	resp, err := c.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func newRegistry(t *testing.T, tl *testfixtures.TL, fixture *testfixtures.Identity) *identity.Registry {
	t.Helper()
	signer, _, err := identity.NewPEMSigner(fixture.KeyPEM, fixture.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	receipt, token := testfixtures.StaticArtifacts(tl, fixture)
	id, err := identity.NewIdentity(testIdentity, fixture.AnsName, fixture.AgentID, signer,
		identity.NewStaticSource(identity.Artifacts{ReceiptBase64: receipt, StatusTokenBase64: token}))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := identity.NewRegistryFromIdentities(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	return reg
}

// e2e wires a fixture transparency log and identity into a Registry, the
// Service and a verifying callee.
type e2e struct {
	callee   *callee
	registry *identity.Registry
	service  *Service
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	tl := testfixtures.MustNewTL()
	fixture := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	reg := newRegistry(t, tl, fixture)
	return &e2e{callee: newCallee(t, tl), registry: reg, service: NewService(reg, sandboxAuthorizer(testSandbox), nil, Config{}, nil)}
}

const e2ePath = "/v1/do"

func TestEndToEndSigning(t *testing.T) {
	t.Parallel()
	env := newE2E(t)
	c, s := env.callee, env.service
	const path = e2ePath
	body := []byte(`{"amount":42}`)

	t.Run("signed request authenticates", func(t *testing.T) {
		t.Parallel()
		res, err := s.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, signPolicy(), http.MethodPost, path, body))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("evaluate = %v, %v", res, err)
		}
		code, got := c.send(t, res, http.MethodPost, path, body)
		if code != http.StatusOK || got != testAnsName {
			t.Fatalf("callee = %d %q, want 200 %q", code, got, testAnsName)
		}
		if code, _ := c.send(t, res, http.MethodPost, path, body); code != http.StatusUnauthorized {
			t.Fatalf("replayed proof = %d, want 401", code)
		}
	})

	t.Run("bodyless GET authenticates", func(t *testing.T) {
		t.Parallel()
		res, err := s.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, signPolicy(), http.MethodGet, "/v1/items", nil))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("evaluate = %v, %v", res, err)
		}
		if code, got := c.send(t, res, http.MethodGet, "/v1/items", nil); code != http.StatusOK || got != testAnsName {
			t.Fatalf("callee = %d %q", code, got)
		}
	})

	t.Run("tampered body is rejected", func(t *testing.T) {
		t.Parallel()
		res, err := s.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, signPolicy(), http.MethodPost, path, body))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("evaluate = %v, %v", res, err)
		}
		if code, _ := c.send(t, res, http.MethodPost, path, []byte(`{"amount":4200}`)); code != http.StatusUnauthorized {
			t.Fatalf("tampered body = %d, want 401", code)
		}
	})

	t.Run("redirected path is rejected", func(t *testing.T) {
		t.Parallel()
		res, err := s.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, signPolicy(), http.MethodPost, path, body))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("evaluate = %v, %v", res, err)
		}
		if code, _ := c.send(t, res, http.MethodPost, "/v1/other", body); code != http.StatusUnauthorized {
			t.Fatalf("other path = %d, want 401", code)
		}
	})
}

func TestEndToEndPolicy(t *testing.T) {
	t.Parallel()
	env := newE2E(t)
	c, s, reg := env.callee, env.service, env.registry
	const path = e2ePath
	body := []byte(`{"amount":42}`)

	t.Run("strip mode leaves the request unauthenticated", func(t *testing.T) {
		t.Parallel()
		res, err := s.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, map[string]any{"mode": "strip"}, http.MethodPost, path, body))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("evaluate = %v, %v", res, err)
		}
		if code, _ := c.send(t, res, http.MethodPost, path, body); code != http.StatusUnauthorized {
			t.Fatalf("stripped request = %d, want 401", code)
		}
	})

	t.Run("unknown identity fails policy validation", func(t *testing.T) {
		t.Parallel()
		v, err := s.ValidateConfig(t.Context(), &middlewarev1.ValidateConfigRequest{Config: structOf(t, map[string]any{"identity": "ghost"})})
		if err != nil || v.GetValid() {
			t.Fatalf("ValidateConfig = %v, %v", v, err)
		}
	})

	t.Run("supervisor for another sandbox is denied", func(t *testing.T) {
		t.Parallel()
		ctx := extauth.ContextWithCaller(t.Context(), extauth.Caller{Kind: extauth.CallerSupervisor, SandboxID: "sb-other"})
		res, err := s.EvaluateHttpRequest(ctx, c.evaluationFor(t, signPolicy(), http.MethodPost, path, body))
		if err != nil || res.GetDecision() != deny || res.GetReasonCode() != ReasonCallerSandboxMismatch {
			t.Fatalf("evaluate = %v, %v", res, err)
		}
	})

	t.Run("destination vetting", func(t *testing.T) {
		t.Parallel()
		vet := &fakeVerifier{verdict: vetting.Verdict{Status: vetting.StatusUnregistered}}
		vetted := NewService(reg, sandboxAuthorizer(testSandbox), vet, Config{}, nil)
		require := map[string]any{"identity": testIdentity, "destination_policy": "require_registered"}
		res, err := vetted.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, require, http.MethodPost, path, body))
		if err != nil || res.GetDecision() != deny || res.GetReasonCode() != vetting.ReasonUnregistered {
			t.Fatalf("require_registered = %v, %v", res, err)
		}
		observe := map[string]any{"identity": testIdentity, "destination_policy": "observe"}
		res, err = vetted.EvaluateHttpRequest(t.Context(), c.evaluationFor(t, observe, http.MethodPost, path, body))
		if err != nil || res.GetDecision() != allow {
			t.Fatalf("observe = %v, %v", res, err)
		}
		types := make([]string, 0, len(res.GetFindings()))
		for _, f := range res.GetFindings() {
			types = append(types, f.GetType())
		}
		if len(types) != 2 || types[0] != FindingDestinationPrefix+"unregistered" || types[1] != FindingIdentityAttached {
			t.Fatalf("findings = %v", types)
		}
		if code, got := c.send(t, res, http.MethodPost, path, body); code != http.StatusOK || got != testAnsName {
			t.Fatalf("callee under observe = %d %q", code, got)
		}
	})
}

// TestEndToEndExpiredTokenDenies runs the identity through the SDK's
// HeaderSupplier: once the status token has expired the supplier withholds it
// and the middleware fails closed.
func TestEndToEndExpiredTokenDenies(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	fixture := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	now := time.Now().Unix()
	expired := tl.StatusToken(fixture.AgentID, fixture.AnsName, scitt.StatusActive, now-3600, now-10, fixture.Fingerprint)
	client := scitt.NewMockClient().
		WithReceipt(fixture.AgentID, tl.Receipt(fixture.AgentID, fixture.AnsName)).
		WithStatusToken(fixture.AgentID, expired)
	supplier := scitt.NewHeaderSupplier(fixture.AgentID, client, scitt.NewRefreshableKeyStore(tl.KeyStore(), nil),
		scitt.WithSupplierClockSkew(time.Minute))
	src, err := identity.NewSupplierSource(t.Context(), supplier)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	signer, _, err := identity.NewPEMSigner(fixture.KeyPEM, fixture.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewIdentity(testIdentity, fixture.AnsName, fixture.AgentID, signer, src)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := identity.NewRegistryFromIdentities(id)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	c := newCallee(t, tl)
	res, err := NewService(reg, sandboxAuthorizer(testSandbox), nil, Config{}, nil).EvaluateHttpRequest(t.Context(),
		c.evaluationFor(t, signPolicy(), http.MethodPost, "/v1/do", nil))
	if err != nil || res.GetDecision() != deny || res.GetReasonCode() != ReasonStatusTokenUnavailable {
		t.Fatalf("evaluate = %v, %v, want DENY %s", res, err, ReasonStatusTokenUnavailable)
	}
}

// TestEvaluate_DevModeIdentity_StampsAllThreeHeaders verifies that a dev-mode
// (self-signed) rogue identity is stamped at egress with DPoP, receipt, and
// status token headers. The test proves the rogue is NOT denied at the egress
// middleware — the honest 401 rejection happens downstream at ingress when the
// self-signed artifacts fail verification against the live transparency log.
func TestEvaluate_DevModeIdentity_StampsAllThreeHeaders(t *testing.T) {
	t.Parallel()

	// Build a dev-mode identity directly with self-signed components
	const rogueAnsName = "ans://v9.9.9.rogue.example"
	const rogueAgentID = "rogue-0001"
	const rogueIdentityName = "rogue"

	signer, _, cert, err := identity.NewSelfSignedSigner(rogueAnsName)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner: %v", err)
	}

	src, err := identity.NewSelfSignedArtifacts(cert, rogueAnsName, rogueAgentID)
	if err != nil {
		t.Fatalf("NewSelfSignedArtifacts: %v", err)
	}

	id, err := identity.NewIdentity(rogueIdentityName, rogueAnsName, rogueAgentID, signer, src)
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	reg, err := identity.NewRegistryFromIdentities(id)
	if err != nil {
		t.Fatalf("NewRegistryFromIdentities: %v", err)
	}
	t.Cleanup(reg.Close)

	// Build a service with an authorizer that allows the rogue identity for testSandbox
	authorizer := sandboxAuthorizer(testSandbox)
	service := NewService(reg, authorizer, nil, Config{}, nil)

	// Build a policy naming the rogue identity in sign mode
	policy := map[string]any{"identity": rogueIdentityName}

	// Evaluate a POST request
	body := []byte(`{"data":"test"}`)
	eval := &middlewarev1.HttpRequestEvaluation{
		Phase:   preCredentials,
		Context: &middlewarev1.RequestContext{RequestId: "req-rogue", SandboxId: testSandbox},
		Config:  structOf(t, policy),
		Target:  &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "target.example.com", Port: 443, Method: "POST", Path: "/v1/test"},
		Body:    body,
	}

	res, err := service.EvaluateHttpRequest(t.Context(), eval)
	if err != nil {
		t.Fatalf("EvaluateHttpRequest: %v", err)
	}

	// Assert: Decision == ALLOW (rogue is stamped, not denied at egress)
	if res.GetDecision() != allow {
		t.Fatalf("Decision = %v, want ALLOW; reason_code = %s", res.GetDecision(), res.GetReasonCode())
	}

	// Collect header mutations
	headers := make(map[string]string)
	for _, m := range res.GetHeaderMutations() {
		if op, ok := m.GetOperation().(*middlewarev1.HeaderMutation_Write); ok {
			headers[op.Write.GetName()] = op.Write.GetValue()
		}
	}

	// Assert: all three ANS headers are present
	dpopHeader, hasDPoP := headers[pop.DPoPHeader]
	receiptHeader, hasReceipt := headers[scitt.HeaderReceipt]
	statusTokenHeader, hasStatusToken := headers[scitt.HeaderStatusToken]

	if !hasDPoP {
		t.Errorf("missing DPoP header %q", pop.DPoPHeader)
	}
	if !hasReceipt {
		t.Errorf("missing receipt header %q", scitt.HeaderReceipt)
	}
	if !hasStatusToken {
		t.Errorf("missing status token header %q", scitt.HeaderStatusToken)
	}

	// Assert: status token is NON-EMPTY (the key requirement)
	if statusTokenHeader == "" {
		t.Errorf("status token header is empty")
	}

	// Also verify the receipt is non-empty (proving Task 2 minted both artifacts)
	if receiptHeader == "" {
		t.Errorf("receipt header is empty")
	}

	// DPoP should also be non-empty
	if dpopHeader == "" {
		t.Errorf("DPoP header is empty")
	}
}
