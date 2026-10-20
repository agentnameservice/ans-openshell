package testfixtures

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const (
	testAgentID = "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
	testAnsName = "ans://v1.0.0.payments.example.com"
)

func TestKeysAndPEM(t *testing.T) {
	t.Parallel()
	key, err := NewP256Key()
	if err != nil {
		t.Fatalf("NewP256Key: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", key.Curve.Params().Name)
	}
	keyPEM, err := PrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("PrivateKeyPEM: %v", err)
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != pemTypePKCS8 || len(rest) != 0 {
		t.Fatalf("PrivateKeyPEM block = %+v, rest = %d bytes", block, len(rest))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if ec, ok := parsed.(*ecdsa.PrivateKey); !ok || !ec.Equal(key) {
		t.Fatalf("parsed key %T does not equal the generated key", parsed)
	}
	certBlock, _ := pem.Decode(CertificatePEM([]byte{1, 2, 3}))
	if certBlock == nil || certBlock.Type != pemTypeCertificate || string(certBlock.Bytes) != "\x01\x02\x03" {
		t.Fatalf("CertificatePEM block = %+v", certBlock)
	}
	if _, err := PrivateKeyPEM(&ecdsa.PrivateKey{}); err == nil {
		t.Fatal("PrivateKeyPEM accepted a key without a curve")
	}
}

func TestRandomSourceFailures(t *testing.T) {
	// Go 1.26 requires this test-only switch to use injected entropy readers.
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",cryptocustomrand=1")
	broken := iotest.ErrReader(errors.New("entropy exhausted"))
	if _, err := newP256Key(broken); err == nil {
		t.Fatal("newP256Key succeeded without entropy")
	}
	if _, err := newTL(broken); err == nil {
		t.Fatal("newTL succeeded without entropy")
	}
	now := time.Now()
	if _, err := newIdentityValid(broken, testAgentID, testAnsName, now, now.Add(time.Hour)); err == nil {
		t.Fatal("newIdentityValid succeeded without entropy")
	}
}

func TestMustPanicsOnError(t *testing.T) {
	t.Parallel()
	must(nil)
	defer func() {
		if recover() == nil {
			t.Fatal("must(err) did not panic")
		}
	}()
	must(errors.New("boom"))
}

func TestNewIdentity(t *testing.T) {
	t.Parallel()
	id := MustNewIdentity(testAgentID, testAnsName)
	if id.AgentID != testAgentID || id.AnsName != testAnsName {
		t.Fatalf("identity facts = %q %q", id.AgentID, id.AnsName)
	}
	if id.Fingerprint != sha256.Sum256(id.CertDER) {
		t.Fatal("Fingerprint is not SHA-256 of CertDER")
	}
	cert, err := x509.ParseCertificate(id.CertDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != testAnsName {
		t.Fatalf("cert URIs = %v, want [%s]", cert.URIs, testAnsName)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		t.Fatalf("certificate validity %v..%v does not contain now", cert.NotBefore, cert.NotAfter)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&id.Key.PublicKey) {
		t.Fatal("certificate public key does not match Key")
	}
	certBlock, _ := pem.Decode(id.CertPEM)
	if certBlock == nil || string(certBlock.Bytes) != string(id.CertDER) {
		t.Fatal("CertPEM does not wrap CertDER")
	}
	keyBlock, _ := pem.Decode(id.KeyPEM)
	if keyBlock == nil || keyBlock.Type != pemTypePKCS8 {
		t.Fatalf("KeyPEM block = %+v", keyBlock)
	}
	if _, err := pop.NewSigner(id.Key, id.CertDER); err != nil {
		t.Fatalf("pop.NewSigner rejects the identity: %v", err)
	}
}

func TestNewIdentityValidErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		agentID string
		ansName string
	}{
		{name: "empty agent id", agentID: "", ansName: testAnsName},
		{name: "unparseable ans name", agentID: testAgentID, ansName: "ans://bad\x7fname"},
		{name: "non-ASCII opaque SAN is not an IA5String", agentID: testAgentID, ansName: "urn:ans:ex\u00e4mple"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewIdentity(tt.agentID, tt.ansName); err == nil {
				t.Fatal("NewIdentity() error = nil, want error")
			}
		})
	}
}

func TestMustPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("MustNewIdentity did not panic on an invalid identity")
		}
	}()
	MustNewIdentity("", testAnsName)
}

func TestMustCBORPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("mustCBOR did not panic on an unencodable value")
		}
	}()
	mustCBOR(make(chan int))
}

func TestTLRootKeyRoundTrip(t *testing.T) {
	t.Parallel()
	tl := MustNewTL()
	tk, err := scitt.ParseC2SPKey(tl.RootKeyC2SP())
	if err != nil {
		t.Fatalf("ParseC2SPKey(%q): %v", tl.RootKeyC2SP(), err)
	}
	if tk.Name != TLName {
		t.Fatalf("key name = %q, want %q", tk.Name, TLName)
	}
	if !tk.Key.Equal(&tl.key.PublicKey) || tk.Kid != tl.kid {
		t.Fatal("parsed root key does not match the log key")
	}
	got, err := tl.KeyStore().Get(tl.kid)
	if err != nil || got.Name != TLName {
		t.Fatalf("KeyStore().Get() = %+v, %v", got, err)
	}
	if tl.KeyStore().Len() != 1 {
		t.Fatalf("KeyStore().Len() = %d, want 1", tl.KeyStore().Len())
	}
}

func TestTLArtifactsVerify(t *testing.T) {
	t.Parallel()
	tl := MustNewTL()
	id := MustNewIdentity(testAgentID, testAnsName)
	now := time.Now().Unix()

	token := tl.StatusToken(id.AgentID, id.AnsName, scitt.StatusActive, now-60, now+3600, id.Fingerprint)
	st, err := scitt.VerifyStatusTokenAt(token, tl.KeyStore(), 0, now)
	if err != nil {
		t.Fatalf("VerifyStatusTokenAt: %v", err)
	}
	if st.Payload.AgentID != testAgentID || st.Payload.AnsName != testAnsName || st.Payload.Status != scitt.StatusActive {
		t.Fatalf("payload = %+v", st.Payload)
	}
	if st.Payload.Iat != now-60 || st.Payload.Exp != now+3600 {
		t.Fatalf("iat/exp = %d/%d", st.Payload.Iat, st.Payload.Exp)
	}
	if !scitt.MatchesIdentityCert(&st.Payload, id.Fingerprint) {
		t.Fatal("status token does not vouch the identity certificate")
	}
	if len(st.Payload.ValidIdentityCerts) != 1 || st.Payload.ValidIdentityCerts[0].CertType != scitt.CertTypeX509OVClient {
		t.Fatalf("ValidIdentityCerts = %+v", st.Payload.ValidIdentityCerts)
	}

	if _, expiredErr := scitt.VerifyStatusTokenAt(token, tl.KeyStore(), 0, now+7200); expiredErr == nil {
		t.Fatal("expired token verified")
	}
	revoked := tl.StatusToken(id.AgentID, id.AnsName, scitt.StatusRevoked, now-60, now+3600, id.Fingerprint)
	if _, revokedErr := scitt.VerifyStatusTokenAt(revoked, tl.KeyStore(), 0, now); revokedErr == nil {
		t.Fatal("revoked token verified")
	}
	other := MustNewTL()
	if _, foreignErr := scitt.VerifyStatusTokenAt(token, other.KeyStore(), 0, now); foreignErr == nil {
		t.Fatal("token verified under a different log key")
	}

	receipt := tl.Receipt(id.AgentID, id.AnsName)
	rcpt, err := scitt.VerifyReceipt(receipt, tl.KeyStore())
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if rcpt.TreeSize != 1 || rcpt.LeafIndex != 0 {
		t.Fatalf("receipt tree = %d/%d", rcpt.TreeSize, rcpt.LeafIndex)
	}
	var leaf struct {
		Payload struct {
			Producer struct {
				Event map[string]string `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(rcpt.EventBytes, &leaf); err != nil {
		t.Fatalf("leaf JSON: %v", err)
	}
	ev := leaf.Payload.Producer.Event
	if leaf.SchemaVersion != "V1" || ev["ansId"] != testAgentID || ev["ansName"] != testAnsName {
		t.Fatalf("leaf = %s", rcpt.EventBytes)
	}

	fresh := tl.FreshStatusToken(id)
	fst, err := scitt.VerifyStatusTokenAt(fresh, tl.KeyStore(), 0, now)
	if err != nil {
		t.Fatalf("FreshStatusToken does not verify: %v", err)
	}
	if ttl := time.Duration(fst.Payload.Exp-now) * time.Second; ttl < StatusTokenTTL-time.Minute || ttl > StatusTokenTTL+time.Minute {
		t.Fatalf("fresh token ttl = %v, want about %v", ttl, StatusTokenTTL)
	}
}

func TestFixturesSatisfyVerifyCaller(t *testing.T) {
	t.Parallel()
	tl := MustNewTL()
	id := MustNewIdentity(testAgentID, testAnsName)
	signer, err := pop.NewSigner(id.Key, id.CertDER)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	const method, target = http.MethodPost, "https://tools.example.com/v1/do"
	body := []byte(`{"q":1}`)
	proof, err := signer.Sign(t.Context(), method, target, pop.WithContent(body))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	replay := pop.NewMemoryReplayCache(t.Context(), 0)
	defer replay.Close()
	hdrs := &scitt.Headers{Receipt: tl.Receipt(id.AgentID, id.AnsName), StatusToken: tl.FreshStatusToken(id)}
	caller, err := pop.VerifyCaller(t.Context(), proof, hdrs, method, target, tl.KeyStore(), replay,
		pop.WithVerifyOptions(pop.WithReceivedContent(func() ([]byte, error) { return body, nil })))
	if err != nil {
		t.Fatalf("VerifyCaller: %v", err)
	}
	if caller.AnsName != testAnsName || caller.AgentID != testAgentID || caller.Fingerprint != id.Fingerprint {
		t.Fatalf("caller = %+v", caller)
	}
}

func TestFakeTLServer(t *testing.T) {
	t.Parallel()
	tl := MustNewTL()
	id := MustNewIdentity(testAgentID, testAnsName)
	srv := FakeTLServer(tl, id)
	defer srv.Close()

	get := func(path string) (int, string, []byte) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), b
	}

	if code, _, body := get("/root-keys"); code != http.StatusOK || string(body) != tl.RootKeyC2SP()+"\n" {
		t.Fatalf("/root-keys = %d %q", code, body)
	}
	code, ctype, receipt := get("/v1/agents/" + testAgentID + "/receipt")
	if code != http.StatusOK || ctype != contentTypeCOSE {
		t.Fatalf("receipt = %d %q", code, ctype)
	}
	if _, err := scitt.VerifyReceipt(receipt, tl.KeyStore()); err != nil {
		t.Fatalf("served receipt does not verify: %v", err)
	}
	code, _, token := get("/v1/agents/" + testAgentID + "/status-token")
	if code != http.StatusOK {
		t.Fatalf("status-token = %d", code)
	}
	if _, err := scitt.VerifyStatusToken(token, tl.KeyStore(), 0); err != nil {
		t.Fatalf("served status token does not verify: %v", err)
	}
	for _, path := range []string{"/v1/agents/unknown/receipt", "/v1/agents/unknown/status-token", "/checkpoint"} {
		if code, _, _ := get(path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
	}
}

func TestFakeTLServerFeedsHeaderSupplier(t *testing.T) {
	t.Parallel()
	tl := MustNewTL()
	id := MustNewIdentity(testAgentID, testAnsName)
	srv := FakeTLServer(tl, id)
	defer srv.Close()

	client, err := scitt.NewHTTPClient(srv.URL, scitt.WithAllowInsecureTransport())
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	keys := scitt.NewRefreshableKeyStore(tl.KeyStore(), client)
	if err := keys.DoRefresh(t.Context()); err != nil {
		t.Fatalf("DoRefresh against /root-keys: %v", err)
	}
	if keys.Len() != 1 {
		t.Fatalf("keys after refresh = %d, want 1", keys.Len())
	}
	supplier := scitt.NewHeaderSupplier(id.AgentID, client, keys, scitt.WithInitTimeout(5*time.Second))
	hdrs := supplier.CurrentHeaders()
	if hdrs.ReceiptBase64 == "" || hdrs.StatusTokenBase64 == "" {
		t.Fatalf("CurrentHeaders() = %v, want both headers; last error %v", hdrs, supplier.LastError())
	}
	if !supplier.Healthy() {
		t.Fatalf("supplier unhealthy: %v", supplier.LastError())
	}
	if err := supplier.RefreshNow(context.WithoutCancel(t.Context())); err != nil {
		t.Fatalf("RefreshNow: %v", err)
	}
}

func TestStaticArtifacts(t *testing.T) {
	t.Parallel()
	tl := MustNewTL()
	id := MustNewIdentity(testAgentID, testAnsName)
	receiptB64, tokenB64 := StaticArtifacts(tl, id)
	receipt, err := base64.StdEncoding.DecodeString(receiptB64)
	if err != nil {
		t.Fatalf("receipt is not standard base64: %v", err)
	}
	token, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		t.Fatalf("token is not standard base64: %v", err)
	}
	if _, err := scitt.VerifyReceipt(receipt, tl.KeyStore()); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if _, err := scitt.VerifyStatusToken(token, tl.KeyStore(), 0); err != nil {
		t.Fatalf("token: %v", err)
	}
	if strings.ContainsAny(receiptB64+tokenB64, "-_") {
		t.Fatal("artifacts must use the standard base64 alphabet")
	}
}
