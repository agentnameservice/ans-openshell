package pemkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: TypePKCS8, Bytes: der})
}

func TestParseP256PrivateKey(t *testing.T) {
	t.Parallel()
	p256 := mustKey(t, elliptic.P256())
	sec1, err := x509.MarshalECPrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		name    string
		in      []byte
		wantErr string
	}{
		{name: "pkcs8", in: pkcs8(t, p256)},
		{name: "sec1", in: pem.EncodeToMemory(&pem.Block{Type: TypeSEC1, Bytes: sec1})},
		{name: "not pem", in: []byte("nope"), wantErr: "no PEM block"},
		{name: "unsupported block", in: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}), wantErr: "unsupported PEM block"},
		{name: "pkcs8 garbage", in: pem.EncodeToMemory(&pem.Block{Type: TypePKCS8, Bytes: []byte{1, 2}}), wantErr: "parse PRIVATE KEY"},
		{name: "sec1 garbage", in: pem.EncodeToMemory(&pem.Block{Type: TypeSEC1, Bytes: []byte{1, 2}}), wantErr: "parse EC PRIVATE KEY"},
		{name: "not ecdsa", in: pkcs8(t, edKey), wantErr: "want an ECDSA P-256 key"},
		{name: "wrong curve", in: pkcs8(t, mustKey(t, elliptic.P384())), wantErr: "want P-256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := ParseP256PrivateKey(tt.in)
			if tt.wantErr == "" {
				if err != nil || key == nil {
					t.Fatalf("ParseP256PrivateKey() = %v, %v", key, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseP256PrivateKey() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	t.Parallel()
	key := mustKey(t, elliptic.P256())
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		in      []byte
		wantErr string
	}{
		{name: "ok", in: pem.EncodeToMemory(&pem.Block{Type: TypeCertificate, Bytes: der})},
		{name: "not pem", in: []byte("x"), wantErr: "no PEM block"},
		{name: "wrong block", in: pem.EncodeToMemory(&pem.Block{Type: TypePKCS8, Bytes: der}), wantErr: "unsupported PEM block"},
		{name: "garbage", in: pem.EncodeToMemory(&pem.Block{Type: TypeCertificate, Bytes: []byte{1}}), wantErr: "parse certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert, err := ParseCertificate(tt.in)
			if tt.wantErr == "" {
				if err != nil || cert == nil {
					t.Fatalf("ParseCertificate() = %v, %v", cert, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseCertificate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
