package testfixtures

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"io"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/selfsign"
)

// TLName is the signer name the fixture log's C2SP root key carries.
const TLName = "ans-openshell-test-log"

// StatusTokenTTL is the lifetime of the status tokens FreshStatusToken mints.
const StatusTokenTTL = time.Hour

const statusTokenBackoff = time.Minute

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
	token, err := selfsign.StatusToken(t.key, agentID, ansName, status, iat, exp, identityFP)
	must(err)
	return token
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
	receipt, err := selfsign.Receipt(t.key, agentID, ansName)
	must(err)
	return receipt
}

