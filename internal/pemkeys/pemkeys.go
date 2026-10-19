// Package pemkeys parses the PEM-encoded key material the extension loads from
// files or mounted secrets: P-256 ECDSA private keys and X.509 certificates.
package pemkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// PEM block types accepted by this package.
const (
	TypePKCS8       = "PRIVATE KEY"
	TypeSEC1        = "EC PRIVATE KEY"
	TypeCertificate = "CERTIFICATE"
)

// ParseP256PrivateKey decodes a PKCS#8 or SEC1 PEM block holding an ECDSA key
// on P-256, the only curve ANS identity certificates use.
func ParseP256PrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var key any
	var err error
	switch block.Type {
	case TypePKCS8:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case TypeSEC1:
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q (want %q or %q)", block.Type, TypePKCS8, TypeSEC1)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", block.Type, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want an ECDSA P-256 key", key)
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key curve is %s, want P-256", ec.Curve.Params().Name)
	}
	return ec, nil
}

// ParseCertificate decodes a CERTIFICATE PEM block.
func ParseCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != TypeCertificate {
		return nil, fmt.Errorf("unsupported PEM block %q (want %q)", block.Type, TypeCertificate)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}
