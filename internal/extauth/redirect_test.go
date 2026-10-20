package extauth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type jwksTransportFunc func(*http.Request) (*http.Response, error)

func (f jwksTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestJWKSRedirectsCannotReplaceTrustedKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		redirect string
	}{
		{name: "direct trusted response"},
		{name: "another authority", redirect: "https://attacker.example.com/keys"},
		{name: "plaintext downgrade", redirect: "http://gateway.example.com/keys"},
		{name: "same origin redirect", redirect: "/moved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
			trusted, replacement := newSigner(t, "trusted"), newSigner(t, "replacement")
			trustedDocument := jwksJSON(t, trusted.jwk())
			replacementDocument := jwksJSON(t, replacement.jwk())
			var calls atomic.Int32
			var suppliedRedirectCalls atomic.Int32
			client := &http.Client{
				Timeout: time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					suppliedRedirectCalls.Add(1)
					return nil
				},
				Transport: jwksTransportFunc(func(req *http.Request) (*http.Response, error) {
					header := make(http.Header)
					status := http.StatusOK
					body := replacementDocument
					switch calls.Add(1) {
					case 1:
						body = trustedDocument
					case 2:
						if tc.redirect != "" {
							status = http.StatusFound
							header.Set("Location", tc.redirect)
						}
					}
					return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
				}),
			}
			verifier, err := NewVerifier(remoteAuth(t, "https://gateway.example.com/.well-known/jwks.json"),
				discardLogger(), WithClock(clock.Now), WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			mustVerify(t, verifier, gatewayToken(t, trusted, clock.now))
			clock.advance(defaultUnknownKeyCooldown + time.Second)
			replacementToken := gatewayToken(t, replacement, clock.now)
			if tc.redirect == "" {
				mustVerify(t, verifier, replacementToken)
			} else {
				mustReject(t, verifier, replacementToken, ErrUnknownKey)
				mustVerify(t, verifier, gatewayToken(t, trusted, clock.now))
				if _, imported := verifier.keys.get(replacement.kid); imported {
					t.Fatal("redirected key entered the verification cache")
				}
			}
			if tc.redirect == "" {
				mustVerify(t, verifier, replacementToken)
			} else {
				mustReject(t, verifier, replacementToken, ErrUnknownKey)
			}
			if calls.Load() != 2 || suppliedRedirectCalls.Load() != 0 {
				t.Fatalf("HTTP requests %d, supplied redirect callbacks %d; want 2 and 0", calls.Load(), suppliedRedirectCalls.Load())
			}
			if client == verifier.keys.client || verifier.keys.client.Timeout != client.Timeout {
				t.Fatal("the supplied HTTP client must be copied with its timeout preserved")
			}
			if err := client.CheckRedirect(nil, nil); err != nil || suppliedRedirectCalls.Load() != 1 {
				t.Fatalf("supplied redirect policy changed: %v", err)
			}
		})
	}
}

func TestDefaultJWKSClientRejectsRedirects(t *testing.T) {
	t.Parallel()
	clock := time.Unix(1_800_000_000, 0)
	forged := newSigner(t, "forged")
	document := jwksJSON(t, forged.jwk())
	verifier, err := NewVerifier(remoteAuth(t, "https://gateway.example.com/.well-known/jwks.json"),
		discardLogger(), WithClock(fixedClock(clock)))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	verifier.keys.client.Transport = jwksTransportFunc(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		status := http.StatusOK
		if calls.Add(1) == 1 {
			status = http.StatusFound
			header.Set("Location", "http://attacker.example.com/keys")
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(document)), Request: req}, nil
	})
	for range 2 {
		if _, err := verifier.Verify(t.Context(), gatewayToken(t, forged, clock)); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("Verify() error = %v, want ErrUnknownKey", err)
		}
	}
	if calls.Load() != 1 || verifier.keys.count() != 0 {
		t.Fatalf("HTTP requests %d, cached keys %d; want 1 and 0", calls.Load(), verifier.keys.count())
	}
}
