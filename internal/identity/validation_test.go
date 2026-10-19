package identity

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

func testValidator(t *testing.T, keys scitt.KeyLookup, id *testfixtures.Identity, now func() time.Time) *artifactValidator {
	t.Helper()
	cert, err := x509.ParseCertificate(id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	name, err := verify.ParseAnsName(id.AnsName)
	if err != nil {
		t.Fatal(err)
	}
	return &artifactValidator{keys: keys, cert: cert, name: name, now: now, cfg: Config{AnsName: id.AnsName, AgentID: id.AgentID}}
}

func TestArtifactValidatorReceipt(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	v := testValidator(t, tl.KeyStore(), id, time.Now)
	for _, tt := range []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{name: "valid", raw: tl.Receipt(id.AgentID, id.AnsName)},
		{name: "malformed", raw: []byte("not a receipt"), wantErr: "receipt:"},
		{name: "untrusted signer", raw: testfixtures.MustNewTL().Receipt(id.AgentID, id.AnsName), wantErr: "unknown key"},
		{name: "another agent", raw: tl.Receipt("other-agent", id.AnsName), wantErr: "receipt names agent"},
		{name: "another name", raw: tl.Receipt(id.AgentID, "ans://v2.0.0.other.example"), wantErr: "configured ans_name"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := v.receipt(tt.raw)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("receipt() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestArtifactValidatorReceiptIdentity(t *testing.T) {
	t.Parallel()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	v := testValidator(t, testfixtures.MustNewTL().KeyStore(), id, time.Now)
	for _, tt := range []struct {
		name, event string
		wantErr     bool
	}{
		{name: "current schema", event: fmt.Sprintf(`{"ansId":%q,"ansName":%q}`, id.AgentID, id.AnsName)},
		{name: "legacy schema", event: fmt.Sprintf(`{"agentId":%q,"ansName":%q}`, id.AgentID, id.AnsName)},
		{name: "matching identifiers", event: fmt.Sprintf(`{"ansId":%q,"agentId":%q,"ansName":%q}`, id.AgentID, id.AgentID, id.AnsName)},
		{name: "case insensitive host", event: fmt.Sprintf(`{"ansId":%q,"ansName":"ans://v1.0.0.PAYMENTS.EXAMPLE.COM"}`, id.AgentID)},
		{name: "conflicting identifiers", event: fmt.Sprintf(`{"ansId":%q,"agentId":"other","ansName":%q}`, id.AgentID, id.AnsName), wantErr: true},
		{name: "missing identifier", event: fmt.Sprintf(`{"ansName":%q}`, id.AnsName), wantErr: true},
		{name: "missing name", event: fmt.Sprintf(`{"ansId":%q}`, id.AgentID), wantErr: true},
		{name: "invalid name", event: fmt.Sprintf(`{"ansId":%q,"ansName":"https://example.com"}`, id.AgentID), wantErr: true},
		{name: "different version", event: fmt.Sprintf(`{"ansId":%q,"ansName":"ans://v2.0.0.payments.example.com"}`, id.AgentID), wantErr: true},
		{name: "wrong field type", event: `{"ansId":12}`, wantErr: true},
		{name: "malformed JSON", event: `{`, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw := []byte(`{"payload":{"producer":{"event":` + tt.event + `}}}`)
			if err := v.receiptIdentity(raw); (err != nil) != tt.wantErr {
				t.Fatalf("receiptIdentity() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestArtifactValidatorStatus(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	now := time.Now()
	v := testValidator(t, tl.KeyStore(), id, func() time.Time { return now })
	if _, err := v.status(tl.FreshStatusToken(id)); err != nil {
		t.Fatalf("valid status: %v", err)
	}
	for _, exp := range []int64{now.Unix(), now.Add(-time.Second).Unix()} {
		if _, err := v.status(tl.StatusToken(id.AgentID, id.AnsName, scitt.StatusActive, now.Add(-time.Hour).Unix(), exp, id.Fingerprint)); err == nil {
			t.Fatal("accepted expired status within clock skew")
		}
	}
	now = v.cert.NotAfter.Add(time.Second)
	if _, err := v.status(tl.StatusToken(id.AgentID, id.AnsName, scitt.StatusActive, now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), id.Fingerprint)); err == nil {
		t.Fatal("accepted expired certificate with a fresh status token")
	}
}
