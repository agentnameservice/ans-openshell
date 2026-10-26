// Package selfsign provides COSE_Sign1 minting for self-signed artifacts used
// in dev-mode identities. It is NOT a test-only package, so production code can
// use it.
package selfsign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/fxamacker/cbor/v2"
)

// COSE labels and values of the artifacts a transparency log signs (RFC 9052
// headers, RFC 9162 verifiable data structure, SCITT receipt proofs).
const (
	coseLabelAlg = 1
	coseLabelKid = 4
	coseLabelVDS = 395
	coseLabelVDP = 396
	coseAlgES256 = -7
	coseSign1Tag = 18
	vdsRFC9162   = 1
	vdpTreeSize  = -1
	vdpLeafIndex = -2
	p1363HalfLen = 32
	p1363SigLen  = 2 * p1363HalfLen
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

const kidLen = 4

// StatusToken mints a COSE_Sign1 status token vouching identityFP as the
// x509-ov-client identity certificate of agentID, registered under ansName,
// with the given status and validity window (Unix seconds).
func StatusToken(key *ecdsa.PrivateKey, agentID, ansName string, status scitt.AgentStatus, iat, exp int64,
	identityFP [sha256.Size]byte) ([]byte, error) {
	kid := kidFor(key)
	protected := mustCBOR(map[int64]any{coseLabelAlg: int64(coseAlgES256), coseLabelKid: kid[:]})
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
	return sign1(key, protected, map[int64]any{}, payload)
}

// Receipt mints a COSE_Sign1 SCITT receipt (RFC 9162 tree of one leaf) over the
// registration event of agentID under ansName, in the leaf envelope a live log
// signs.
func Receipt(key *ecdsa.PrivateKey, agentID, ansName string) ([]byte, error) {
	kid := kidFor(key)
	protected := mustCBOR(map[int64]any{
		coseLabelAlg: int64(coseAlgES256),
		coseLabelKid: kid[:],
		coseLabelVDS: int64(vdsRFC9162),
	})
	unprotected := map[int64]any{coseLabelVDP: map[int64]any{vdpTreeSize: uint64(1), vdpLeafIndex: uint64(0)}}
	return sign1(key, protected, unprotected, leafJSON(agentID, ansName))
}

// sign1 assembles a COSE_Sign1 (CBOR tag 18) over protected and payload with a
// P1363 ECDSA signature.
func sign1(key *ecdsa.PrivateKey, protected []byte, unprotected any, payload []byte) ([]byte, error) {
	digest, err := scitt.ComputeSigStructureDigest(protected, payload)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, p1363SigLen)
	r.FillBytes(sig[:p1363HalfLen])
	s.FillBytes(sig[p1363HalfLen:])
	return mustCBOR(cbor.Tag{Number: coseSign1Tag, Content: []any{protected, unprotected, payload, sig}}), nil
}

func mustCBOR(v any) []byte {
	b, err := cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// kidFor computes the 4-byte key ID from an ECDSA public key.
func kidFor(key *ecdsa.PrivateKey) [kidLen]byte {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(spki)
	var kid [kidLen]byte
	copy(kid[:], h[:kidLen])
	return kid
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
	if err != nil {
		panic(err)
	}
	return b
}
