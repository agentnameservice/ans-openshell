package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/callee"
	"github.com/agentnameservice/ans-openshell/internal/config"
	"github.com/agentnameservice/ans-openshell/internal/extauth"
	"github.com/agentnameservice/ans-openshell/internal/identity"
)

func TestRunWritesABundleTheServicesLoad(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "fixtures")
	var stdout bytes.Buffer
	err := run([]string{"-out", dir, "-middleware-host", "192.0.2.10, middleware.test"}, &stdout)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got, want := strings.TrimSpace(stdout.String()), filepath.Join(dir, manifestFile); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}

	m := readManifest(t, dir)
	if m.Identity != identityName || m.AnsName != ansName || m.AgentID == "" {
		t.Fatalf("manifest = %+v", m)
	}
	if time.Until(m.StatusTokenExpires) < defaultStatusTokenTTL-time.Minute {
		t.Fatalf("status token expires too soon: %s", m.StatusTokenExpires)
	}
	// The layout is a contract with smoke.sh, which hardcodes these paths.
	for _, rel := range []string{
		"tl-root-keys.txt", "identity/key.pem", "identity/cert.pem", "identity/receipt.cose",
		"identity/status-token.cose", "gateway/jwt/signing.pem", "gateway/jwt/public.pem",
		"gateway/jwt/kid", "gateway/jwks.json", "middleware-tls/ca.crt", "middleware-tls/tls.crt",
		"middleware-tls/tls.key",
	} {
		info, statErr := os.Stat(filepath.Join(dir, rel))
		if statErr != nil {
			t.Fatalf("%s: %v", rel, statErr)
		}
		if perm := info.Mode().Perm(); perm != filePerm {
			t.Fatalf("%s: mode %o, want %o", rel, perm, filePerm)
		}
	}

	// The middleware loads the identity from the pinned files and verifies the
	// artifacts against the root key, exactly as the launcher configures it:
	// no transparency log is contacted, so none is configured.
	logger := slog.New(slog.DiscardHandler)
	reg, err := identity.NewRegistry(t.Context(), map[string]identity.Config{
		m.Identity: {
			AnsName:         m.AnsName,
			AgentID:         m.AgentID,
			KeyFile:         filepath.Join(dir, "identity/key.pem"),
			CertFile:        filepath.Join(dir, "identity/cert.pem"),
			ReceiptFile:     filepath.Join(dir, "identity/receipt.cose"),
			StatusTokenFile: filepath.Join(dir, "identity/status-token.cose"),
		},
	}, config.TransparencyLog{RootKeysFile: filepath.Join(dir, "tl-root-keys.txt")}, logger)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()
	if !reg.Healthy() {
		t.Fatal("registry not healthy")
	}

	// The callee trusts the same root key.
	keys, err := callee.ReadRootKeys(filepath.Join(dir, "tl-root-keys.txt"))
	if err != nil {
		t.Fatalf("ReadRootKeys: %v", err)
	}
	store, err := scitt.NewKeyStore(keys)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	token, err := os.ReadFile(filepath.Join(dir, "identity/status-token.cose"))
	if err != nil {
		t.Fatal(err)
	}
	vt, err := scitt.VerifyStatusTokenAt(token, store, 0, time.Now().Unix())
	if err != nil {
		t.Fatalf("status token does not verify under the written root key: %v", err)
	}
	if vt.Payload.AgentID != m.AgentID {
		t.Fatalf("status token agent %q, manifest %q", vt.Payload.AgentID, m.AgentID)
	}

	// The middleware verifies gateway JWTs against the written JWKS.
	v, err := extauth.NewVerifier(config.Auth{
		GatewayIssuer: "openshell-gateway:smoke",
		Audience:      "urn:openshell:extension:middleware:ans",
		JWKSFile:      filepath.Join(dir, "gateway/jwks.json"),
	}, logger)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if !v.Ready() {
		t.Fatal("verifier did not load a key from jwks.json")
	}
	kid, err := os.ReadFile(filepath.Join(dir, "gateway/jwt/kid"))
	if err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	jwksData, err := os.ReadFile(filepath.Join(dir, "gateway/jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jwksData, &jwks); err != nil || len(jwks.Keys) != 1 || jwks.Keys[0].Kid != strings.TrimSpace(string(kid)) {
		t.Fatalf("jwks.json kid does not match the kid file: %s vs %q (%v)", jwksData, kid, err)
	}
	assertPEMType(t, filepath.Join(dir, "gateway/jwt/signing.pem"), "PRIVATE KEY")
	assertPEMType(t, filepath.Join(dir, "gateway/jwt/public.pem"), "PUBLIC KEY")

	// The serving certificate chains to the CA and names every host.
	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, "middleware-tls/ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.crt is not a certificate")
	}
	leaf := parseCert(t, filepath.Join(dir, "middleware-tls/tls.crt"))
	for _, host := range []string{"192.0.2.10", "middleware.test"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: caPool, DNSName: host}); err != nil {
			t.Fatalf("tls.crt does not verify for %s: %v", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: caPool, DNSName: "other.test"}); err == nil {
		t.Fatal("tls.crt verified for a host it was not minted for")
	}
	assertPEMType(t, filepath.Join(dir, "middleware-tls/tls.key"), "EC PRIVATE KEY")
}

func TestRunRejectsBadArguments(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing flags", args: []string{"-out", filepath.Join(base, "a")}, want: "are required"},
		{name: "empty host entry", args: []string{"-out", filepath.Join(base, "b"), "-middleware-host", "a,,b"}, want: "empty entry"},
		{name: "zero ttl", args: []string{"-out", filepath.Join(base, "c"), "-middleware-host", "h", "-status-token-ttl", "0s"}, want: "must be positive"},
		{name: "unknown flag", args: []string{"-bogus"}, want: "flag provided but not defined"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := run(tt.args, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run(%v) = %v, want %q", tt.args, err, tt.want)
			}
		})
	}
}

func TestWriteRefusesANonEmptyDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("x"), filePerm); err != nil {
		t.Fatal(err)
	}
	b, err := generate(options{middlewareHosts: []string{"h"}, statusTokenTTL: time.Hour, now: time.Now, random: rand.Reader})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := b.write(dir); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("write into a non-empty dir = %v, want refusal", err)
	}
}

func TestWriteReportsFilesystemErrors(t *testing.T) {
	t.Parallel()
	b, err := generate(options{middlewareHosts: []string{"h"}, statusTokenTTL: time.Hour, now: time.Now, random: rand.Reader})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// A regular file where the output directory should be.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), filePerm); err != nil {
		t.Fatal(err)
	}
	if err := b.write(file); err == nil {
		t.Fatal("write onto a file succeeded")
	}
	if err := b.write(filepath.Join(file, "child")); err == nil {
		t.Fatal("write under a file succeeded")
	}
	// writeNew never overwrites.
	existing := filepath.Join(t.TempDir(), "kid")
	if err := writeNew(existing, []byte("a")); err != nil {
		t.Fatalf("writeNew: %v", err)
	}
	if err := writeNew(existing, []byte("b")); err == nil || !strings.Contains(err.Error(), "exist") {
		t.Fatalf("writeNew overwrite = %v", err)
	}
}

func TestGenerateHonoursTheClockAndTTL(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	b, err := generate(options{middlewareHosts: []string{"10.0.0.1"}, statusTokenTTL: 15 * time.Minute, now: func() time.Time { return fixed }, random: rand.Reader})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !b.manifest.StatusTokenExpires.Equal(fixed.Add(15 * time.Minute)) {
		t.Fatalf("expires = %s", b.manifest.StatusTokenExpires)
	}
	// Every certificate follows the injected clock, not the wall clock.
	for _, name := range []string{"identity/cert.pem", "middleware-tls/ca.crt", "middleware-tls/tls.crt"} {
		block, _ := pem.Decode(b.files[name])
		if block == nil {
			t.Fatalf("%s: not PEM", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !cert.NotBefore.Equal(fixed.Add(-tlsBackdate)) || !cert.NotAfter.Equal(fixed.Add(tlsValidity)) {
			t.Fatalf("%s: validity %s to %s, want from the injected clock", name, cert.NotBefore, cert.NotAfter)
		}
	}
	for _, tt := range []struct {
		name string
		opts options
		want string
	}{
		{name: "no hosts", opts: options{statusTokenTTL: time.Hour, now: time.Now, random: rand.Reader}, want: "middleware host"},
		{name: "negative ttl", opts: options{middlewareHosts: []string{"h"}, statusTokenTTL: -1, now: time.Now, random: rand.Reader}, want: "positive"},
		{name: "no random source", opts: options{middlewareHosts: []string{"h"}, statusTokenTTL: time.Hour, now: time.Now}, want: "random source"},
		{name: "failing random source", opts: options{middlewareHosts: []string{"h"}, statusTokenTTL: time.Hour, now: time.Now, random: failingReader{}}, want: "unlucky"},
	} {
		if _, err := generate(tt.opts); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: generate = %v, want %q", tt.name, err, tt.want)
		}
	}
}

// failingReader fails every read, standing in for an exhausted entropy source.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("unlucky") }

// TestGeneratorsSurfaceRandomFailures drives each minting helper with a random
// source that fails, so the error returns behind it are exercised. Since Go
// 1.26 ecdsa.GenerateKey ignores the caller's reader, so the P-256 key paths
// cannot be made to fail this way; the Ed25519 key, the certificate serials
// and signatures, and the agent id still read from it.
func TestGeneratorsSurfaceRandomFailures(t *testing.T) {
	t.Parallel()
	now := time.Now()
	if _, err := newGatewayKey(failingReader{}); err == nil {
		t.Error("newGatewayKey accepted a failing random source")
	}
	if _, err := newServerTLS(failingReader{}, []string{"h"}, now); err == nil {
		t.Error("newServerTLS accepted a failing random source")
	}
	if _, err := certTemplate(failingReader{}, "cn", now); err == nil {
		t.Error("certTemplate accepted a failing random source")
	}
	if _, err := newUUID(failingReader{}); err == nil {
		t.Error("newUUID accepted a failing random source")
	}
}

func TestParseHosts(t *testing.T) {
	t.Parallel()
	got, err := parseHosts(" a , b ")
	if err != nil || len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("parseHosts = %v, %v", got, err)
	}
	if _, err := parseHosts(""); err == nil {
		t.Fatal("parseHosts(\"\") accepted")
	}
}

func readManifest(t *testing.T, dir string) manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return m
}

func assertPEMType(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != want {
		t.Fatalf("%s: PEM type %v, want %s", path, block, want)
	}
}

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return cert
}
