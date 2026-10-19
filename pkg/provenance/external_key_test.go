package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

// recordingSigner stands in for a key held outside the process: it signs with
// a P-256 key it never exposes and counts the calls.
type recordingSigner struct {
	key   *ecdsa.PrivateKey
	calls int
	der   []byte
	err   error
}

func (r *recordingSigner) Public() crypto.PublicKey { return &r.key.PublicKey }

func (r *recordingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	if r.der != nil {
		return r.der, nil
	}
	return r.key.Sign(random, digest, opts)
}

func certFor(t *testing.T, pub any, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "external"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestNewSignerExternalKey(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ext := &recordingSigner{key: key}
	cert := certFor(t, &key.PublicKey, key)
	s, err := NewSigner(ext, cert)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	body := []byte(`{"observations":[]}`)
	jws, err := s.Sign(body, time.Unix(1_700_000_000, 0), 0, "ans://v1.0.0.ops.example.com")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if ext.calls != 1 {
		t.Fatalf("external signer called %d times, want 1", ext.calls)
	}
	claims, got, err := Verify(jws, body)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !got.Equal(cert) || claims.AIMID != "ans://v1.0.0.ops.example.com" || claims.IssuedAt != 1_700_000_000 {
		t.Fatalf("claims = %+v, cert match %v", claims, got.Equal(cert))
	}
}

func TestNewSignerRejections(t *testing.T) {
	t.Parallel()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	cert := certFor(t, &p256.PublicKey, p256)
	tests := []struct {
		name    string
		key     crypto.Signer
		cert    *x509.Certificate
		wantErr string
	}{
		{name: "nil key", cert: cert, wantErr: "required"},
		{name: "nil cert", key: p256, wantErr: "required"},
		{name: "ed25519 key", key: edKey, cert: cert, wantErr: "not an ECDSA P-256 key"},
		{name: "p384 key", key: p384, cert: certFor(t, &p384.PublicKey, p384), wantErr: "not an ECDSA P-256 key"},
		{name: "certificate for another key", key: other, cert: cert, wantErr: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSigner(tt.key, tt.cert)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewSigner() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSignExternalFailures(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := certFor(t, &key.PublicKey, key)
	tests := []struct {
		name    string
		signer  *recordingSigner
		wantErr string
	}{
		{name: "signer error", signer: &recordingSigner{key: key, err: errors.New("hsm offline")}, wantErr: "hsm offline"},
		{name: "malformed asn1", signer: &recordingSigner{key: key, der: []byte{0x30, 0x01}}, wantErr: "malformed ASN.1"},
		{name: "trailing bytes", signer: &recordingSigner{key: key, der: append(mustDER(t, key), 0x00)}, wantErr: "malformed ASN.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := NewSigner(tt.signer, cert)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Sign([]byte("x"), time.Now(), 1, "a"); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Sign() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func mustDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := ecdsa.SignASN1(rand.Reader, key, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return der
}
