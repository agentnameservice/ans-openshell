package testfixtures

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/fxamacker/cbor/v2"
)

// TLName is the signer name the fixture log's C2SP root key carries.
const TLName = "ans-openshell-test-log"

// StatusTokenTTL is the lifetime of the status tokens FreshStatusToken mints.
const StatusTokenTTL = time.Hour

// COSE labels and values of the artifacts a transparency log signs (RFC 9052
// headers, RFC 9162 verifiable data structure, SCITT receipt proofs).
const (
	coseLabelAlg       = 1
	coseLabelKid       = 4
	coseLabelVDS       = 395
	coseLabelVDP       = 396
	coseAlgES256       = -7
	coseSign1Tag       = 18
	vdsRFC9162         = 1
	vdpTreeSize        = -1
	vdpLeafIndex       = -2
	p1363HalfLen       = 32
	p1363SigLen        = 2 * p1363HalfLen
	statusTokenBackoff = time.Minute
)

// Status token payload claims (CBOR integer keys).
const (
	claimAgentID       = 1
	claimStatus        = 2
	claimIat           = 3
	claimExp           = 4
	claimAnsName       = 5
	claimIdentityCerts = 6
)

// TL is a fixture transparency log: one ES256 signing key, published as a C2SP
// root key a verifier pins, and the minting side of the artifacts the log
// issues to its agents.
type TL struct {
	key      *ecdsa.PrivateKey
	kid      [kidLen]byte
	rootKey  string
	keyStore *scitt.KeyStore
}

// NewTL creates a transparency log with a fresh signing key.
func NewTL() (*TL, error) {
	return newTL(rand.Reader)
}

func newTL(random io.Reader) (*TL, error) {
	key, err := newP256Key(random)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(err)
	kid := kidFor(spki)
	rootKey := TLName + "+" + hex.EncodeToString(kid[:]) + "+" + base64.StdEncoding.EncodeToString(spki)
	keyStore, err := scitt.NewKeyStore([]string{rootKey})
	must(err)
	return &TL{key: key, kid: kid, rootKey: rootKey, keyStore: keyStore}, nil
}

// MustNewTL is NewTL that panics on error.
func MustNewTL() *TL {
	tl, err := NewTL()
	if err != nil {
		panic(err)
	}
	return tl
}

// RootKeyC2SP returns the log's public key in the C2SP form
// "name+hexkid+base64(SPKI)" that scitt.ParseC2SPKey and the /root-keys
// endpoint use.
func (t *TL) RootKeyC2SP() string { return t.rootKey }

// KeyStore returns a store trusting only this log's key. It implements
// scitt.KeyLookup, so it serves pop.VerifyCaller and pop.Middleware directly.
func (t *TL) KeyStore() *scitt.KeyStore { return t.keyStore }

// StatusToken mints a COSE_Sign1 status token vouching identityFP as the
// x509-ov-client identity certificate of agentID, registered under ansName,
// with the given status and validity window (Unix seconds).
func (t *TL) StatusToken(agentID, ansName string, status scitt.AgentStatus, iat, exp int64,
	identityFP [sha256.Size]byte) []byte {
	protected := mustCBOR(map[int64]any{coseLabelAlg: int64(coseAlgES256), coseLabelKid: t.kid[:]})
	certs := []any{map[string]any{
		"fingerprint": identityFP[:],
		"cert_type":   string(scitt.CertTypeX509OVClient),
	}}
	payload := mustCBOR(map[int64]any{
		claimAgentID:       agentID,
		claimStatus:        string(status),
		claimIat:           iat,
		claimExp:           exp,
		claimAnsName:       ansName,
		claimIdentityCerts: certs,
	})
	return t.sign1(protected, map[int64]any{}, payload)
}

// FreshStatusToken mints an ACTIVE status token for id issued one minute ago
// and expiring StatusTokenTTL from now.
func (t *TL) FreshStatusToken(id *Identity) []byte {
	now := time.Now()
	return t.StatusToken(id.AgentID, id.AnsName, scitt.StatusActive,
		now.Add(-statusTokenBackoff).Unix(), now.Add(StatusTokenTTL).Unix(), id.Fingerprint)
}

// Receipt mints a COSE_Sign1 SCITT receipt (RFC 9162 tree of one leaf) over the
// registration event of agentID under ansName, in the leaf envelope a live log
// signs.
func (t *TL) Receipt(agentID, ansName string) []byte {
	protected := mustCBOR(map[int64]any{
		coseLabelAlg: int64(coseAlgES256),
		coseLabelKid: t.kid[:],
		coseLabelVDS: int64(vdsRFC9162),
	})
	unprotected := map[int64]any{coseLabelVDP: map[int64]any{vdpTreeSize: uint64(1), vdpLeafIndex: uint64(0)}}
	return t.sign1(protected, unprotected, leafJSON(agentID, ansName))
}

// sign1 assembles a COSE_Sign1 (CBOR tag 18) over protected and payload with a
// P1363 ECDSA signature.
func (t *TL) sign1(protected []byte, unprotected any, payload []byte) []byte {
	digest, err := scitt.ComputeSigStructureDigest(protected, payload)
	must(err)
	r, s, err := ecdsa.Sign(rand.Reader, t.key, digest[:])
	must(err)
	sig := make([]byte, p1363SigLen)
	r.FillBytes(sig[:p1363HalfLen])
	s.FillBytes(sig[p1363HalfLen:])
	return mustCBOR(cbor.Tag{Number: coseSign1Tag, Content: []any{protected, unprotected, payload, sig}})
}

func mustCBOR(v any) []byte {
	b, err := cbor.Marshal(v)
	must(err)
	return b
}

// leafEnvelope is the transparency-log leaf a receipt signs: the event wrapped
// in payload.producer.event, naming the agent by ansId (schema V1).
type leafEnvelope struct {
	Payload       leafPayload `json:"payload"`
	SchemaVersion string      `json:"schemaVersion"`
}

type leafPayload struct {
	Producer leafProducer `json:"producer"`
}

type leafProducer struct {
	Event leafEvent `json:"event"`
}

type leafEvent struct {
	AnsID   string `json:"ansId"`
	AnsName string `json:"ansName"`
}

func leafJSON(agentID, ansName string) []byte {
	env := leafEnvelope{
		Payload:       leafPayload{Producer: leafProducer{Event: leafEvent{AnsID: agentID, AnsName: ansName}}},
		SchemaVersion: "V1",
	}
	b, err := json.Marshal(env)
	must(err)
	return b
}
