package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseToolsListRequired(t *testing.T) {
	toolsListBytes, err := os.ReadFile(filepath.Join("testdata", "seller-tools-list.json"))
	if err != nil {
		t.Fatalf("failed to read seller-tools-list.json: %v", err)
	}

	tests := []struct {
		name    string
		body    []byte
		tool    string
		want    []Capability
		wantErr bool
	}{
		{
			name:    "book_flight from seller tools",
			body:    toolsListBytes,
			tool:    "book_flight",
			want:    []Capability{"quote_id", "mandate", "dpop_proof"},
			wantErr: false,
		},
		{
			name:    "tool not found",
			body:    toolsListBytes,
			tool:    "nonexistent_tool",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			body:    []byte(`{invalid`),
			tool:    "book_flight",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "no required field",
			body:    []byte(`{"tools":[{"name":"test_tool","inputSchema":{"type":"object","properties":{}}}]}`),
			tool:    "test_tool",
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseToolsListRequired(tt.body, tt.tool)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseToolsListRequired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseToolsListRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCardDPoP(t *testing.T) {
	cardBytes, err := os.ReadFile(filepath.Join("testdata", "seller-agent-card.json"))
	if err != nil {
		t.Fatalf("failed to read seller-agent-card.json: %v", err)
	}

	tests := []struct {
		name    string
		card    []byte
		want    *DPoPParams
		wantErr bool
	}{
		{
			name: "seller card DPoP params",
			card: cardBytes,
			want: &DPoPParams{
				Alg:    "ES256",
				Ath:    "base64url(SHA-256(quote_id))",
				Htm:    "POST",
				Htu:    "https://seller.skybound-travel.com/mcp/",
				Typ:    "dpop+jwt",
				Claims: []string{"jti", "htm", "htu", "iat", "ath"},
			},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			card:    []byte(`{invalid`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "no DPoP extension",
			card:    []byte(`{"capabilities":{"extensions":[{"uri":"https://other.uri"}]}}`),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCardDPoP(tt.card)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCardDPoP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCardDPoP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyCardJWS(t *testing.T) {
	// Generate a throwaway Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// Create JWK representation of the public key
	jwk := map[string]interface{}{
		"kid": "test-key-001",
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey),
	}
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	// Serve the JWK from httptest
	jkuServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jkuServer.Close()

	// Build an agent card WITHOUT signatures
	cardWithoutSig := map[string]interface{}{
		"version": "1.0",
		"name":    "test-agent",
		"capabilities": map[string]interface{}{
			"extensions": []interface{}{
				map[string]interface{}{
					"uri": "https://modelcontextprotocol.io/ext/server/v1",
					"params": map[string]interface{}{
						"endpoint": "https://example.com/mcp/",
					},
				},
			},
		},
	}

	// Serialize to canonical JSON
	cardBodyBytes, err := json.Marshal(cardWithoutSig)
	if err != nil {
		t.Fatalf("failed to marshal card body: %v", err)
	}

	// Build JWS protected header
	protectedHeader := map[string]interface{}{
		"alg": "EdDSA",
		"jku": jkuServer.URL,
		"kid": "test-key-001",
		"typ": "application/agent-card+json",
	}
	protectedBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(cardBodyBytes)

	// Sign: Ed25519.Sign(protected.payload)
	signingInput := protectedB64 + "." + payloadB64
	signature := ed25519.Sign(privKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build the signed card
	cardWithoutSig["signatures"] = []interface{}{
		map[string]interface{}{
			"protected": protectedB64,
			"signature": signatureB64,
		},
	}
	signedCardBytes, err := json.Marshal(cardWithoutSig)
	if err != nil {
		t.Fatalf("failed to marshal signed card: %v", err)
	}

	tests := []struct {
		name string
		card []byte
		want bool
	}{
		{
			name: "valid hermetic card",
			card: signedCardBytes,
			want: true,
		},
		{
			name: "no signatures block",
			card: []byte(`{"name":"test","capabilities":{}}`),
			want: false,
		},
		{
			name: "invalid JSON",
			card: []byte(`{invalid`),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyCardJWS(tt.card)
			if got != tt.want {
				t.Errorf("verifyCardJWS() = %v, want %v", got, tt.want)
			}
		})
	}

	// Test tamper detection
	t.Run("tampered card body fails Ed25519 verification", func(t *testing.T) {
		var tamperedCard map[string]interface{}
		if err := json.Unmarshal(signedCardBytes, &tamperedCard); err != nil {
			t.Fatalf("failed to unmarshal signed card: %v", err)
		}
		// Tamper: change the version field
		tamperedCard["version"] = "2.0"
		tamperedBytes, err := json.Marshal(tamperedCard)
		if err != nil {
			t.Fatalf("failed to marshal tampered card: %v", err)
		}

		// Tampered card should fail signature verification
		if got := verifyCardJWS(tamperedBytes); got {
			t.Error("verifyCardJWS() = true for tampered card, want false")
		}
	})
}

func TestParsePrerequisites(t *testing.T) {
	tests := []struct {
		name string
		desc string
		want []Capability
	}{
		{
			name: "valid prerequisites",
			desc: "A2A + MCP. Ticket { ticket_id }. Prerequisites: quote_id, mandate, dpop_proof.",
			want: []Capability{"quote_id", "mandate", "dpop_proof"},
		},
		{
			name: "no prerequisites",
			desc: "Some description without the keyword",
			want: nil,
		},
		{
			name: "empty description",
			desc: "",
			want: nil,
		},
		{
			name: "prerequisites with spaces",
			desc: "Prerequisites: foo,  bar  , baz",
			want: []Capability{"foo", "bar", "baz"},
		},
		{
			name: "prerequisites at end",
			desc: "Description. Prerequisites: a, b",
			want: []Capability{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePrerequisites(tt.desc)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePrerequisites() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTPDiscoverer_Discover(t *testing.T) {
	toolsListBytes, err := os.ReadFile(filepath.Join("testdata", "seller-tools-list.json"))
	if err != nil {
		t.Fatalf("failed to read seller-tools-list.json: %v", err)
	}

	// Create JSON-RPC tools/list response
	toolsListResponse := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  json.RawMessage(toolsListBytes),
	}
	toolsListResponseBytes, _ := json.Marshal(toolsListResponse)

	t.Run("successful discovery", func(t *testing.T) {
		// Generate a throwaway Ed25519 keypair
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		// Create JWK representation of the public key
		jwk := map[string]interface{}{
			"kid": "test-key-001",
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pubKey),
		}
		jwks := map[string]interface{}{
			"keys": []interface{}{jwk},
		}

		// Serve the JWK from httptest
		jkuServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer jkuServer.Close()

		// Create a placeholder for the server (will be filled in the handler)
		var server *httptest.Server
		var signedCardBytes []byte

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/agent-card.json" {
				// Build card on first request with correct server URL
				if signedCardBytes == nil {
					cardWithoutSig := map[string]interface{}{
						"version": "1.0",
						"name":    "test-seller",
						"capabilities": map[string]interface{}{
							"extensions": []interface{}{
								map[string]interface{}{
									"uri": "https://modelcontextprotocol.io/ext/server/v1",
									"params": map[string]interface{}{
										"endpoint": server.URL + "/mcp/",
									},
								},
								map[string]interface{}{
									"uri": "https://ans.dev/ext/dpop/v1",
									"params": map[string]interface{}{
										"alg":    "ES256",
										"ath":    "base64url(SHA-256(quote_id))",
										"htm":    "POST",
										"htu":    server.URL + "/mcp/",
										"typ":    "dpop+jwt",
										"claims": []string{"jti", "htm", "htu", "iat", "ath"},
									},
								},
							},
						},
					}
					cardBodyBytes, _ := json.Marshal(cardWithoutSig)
					protectedHeader := map[string]interface{}{
						"alg": "EdDSA",
						"jku": jkuServer.URL,
						"kid": "test-key-001",
						"typ": "application/agent-card+json",
					}
					protectedBytes, _ := json.Marshal(protectedHeader)
					protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
					payloadB64 := base64.RawURLEncoding.EncodeToString(cardBodyBytes)
					signingInput := protectedB64 + "." + payloadB64
					signature := ed25519.Sign(privKey, []byte(signingInput))
					signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
					cardWithoutSig["signatures"] = []interface{}{
						map[string]interface{}{
							"protected": protectedB64,
							"signature": signatureB64,
						},
					}
					signedCardBytes, _ = json.Marshal(cardWithoutSig)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(signedCardBytes)
				return
			}
			if r.URL.Path == "/mcp/" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(toolsListResponseBytes)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		discoverer := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)
		target := Target{
			Host: server.URL, // Full URL with http://
			Tool: "book_flight",
		}

		req := discoverer.Discover(context.Background(), target)

		if req.Empty() {
			t.Fatal("expected non-empty requirement")
		}
		if req.Tool != "book_flight" {
			t.Errorf("Tool = %v, want book_flight", req.Tool)
		}
		wantCaps := []Capability{"quote_id", "mandate", "dpop_proof"}
		if !reflect.DeepEqual(req.Capabilities, wantCaps) {
			t.Errorf("Capabilities = %v, want %v", req.Capabilities, wantCaps)
		}
		if req.DPoP == nil {
			t.Fatal("expected DPoP params")
		}
		// Check that htu matches server URL
		expectedHtu := server.URL + "/mcp/"
		if req.DPoP.Htu != expectedHtu {
			t.Errorf("DPoP.Htu = %v, want %v", req.DPoP.Htu, expectedHtu)
		}
		if req.DPoP.Alg != "ES256" {
			t.Errorf("DPoP.Alg = %v, want ES256", req.DPoP.Alg)
		}
		if req.DPoP.Ath != "base64url(SHA-256(quote_id))" {
			t.Errorf("DPoP.Ath = %v, want base64url(SHA-256(quote_id))", req.DPoP.Ath)
		}
	})

	t.Run("empty tool name short-circuits without network", func(t *testing.T) {
		hitCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hitCount++
			http.NotFound(w, r)
		}))
		defer server.Close()

		discoverer := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)
		target := Target{
			Host: server.URL,
			Tool: "", // Empty tool name
		}

		req := discoverer.Discover(context.Background(), target)

		if !req.Empty() {
			t.Errorf("expected empty requirement for empty tool, got %+v", req)
		}
		if hitCount != 0 {
			t.Errorf("expected zero network calls for empty tool, got %d", hitCount)
		}
	})

	t.Run("404 card fetch returns empty", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer server.Close()

		discoverer := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)
		target := Target{
			Host: server.URL,
			Tool: "book_flight",
		}

		req := discoverer.Discover(context.Background(), target)

		if !req.Empty() {
			t.Errorf("expected empty requirement, got %+v", req)
		}
	})

	t.Run("unverified card returns requirement without htu", func(t *testing.T) {
		// Card without signatures (unverified) should not trust the discovered htu
		var server *httptest.Server
		var cardBytes []byte

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/agent-card.json" {
				if cardBytes == nil {
					cardWithoutSig := map[string]interface{}{
						"version": "1.0",
						"name":    "test-seller",
						"capabilities": map[string]interface{}{
							"extensions": []interface{}{
								map[string]interface{}{
									"uri": "https://modelcontextprotocol.io/ext/server/v1",
									"params": map[string]interface{}{
										"endpoint": server.URL + "/mcp/",
									},
								},
								map[string]interface{}{
									"uri": "https://ans.dev/ext/dpop/v1",
									"params": map[string]interface{}{
										"alg":    "ES256",
										"ath":    "base64url(SHA-256(quote_id))",
										"htm":    "POST",
										"htu":    server.URL + "/mcp/",
										"typ":    "dpop+jwt",
										"claims": []string{"jti", "htm", "htu", "iat", "ath"},
									},
								},
							},
						},
					}
					cardBytes, _ = json.Marshal(cardWithoutSig)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(cardBytes)
				return
			}
			if r.URL.Path == "/mcp/" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(toolsListResponseBytes)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		discoverer := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)
		target := Target{
			Host: server.URL,
			Tool: "book_flight",
		}

		req := discoverer.Discover(context.Background(), target)

		// Should have capabilities (from tools/list) but NO DPoP (htu not trusted)
		if req.Tool != "book_flight" {
			t.Errorf("Tool = %v, want book_flight", req.Tool)
		}
		wantCaps := []Capability{"quote_id", "mandate", "dpop_proof"}
		if !reflect.DeepEqual(req.Capabilities, wantCaps) {
			t.Errorf("Capabilities = %v, want %v", req.Capabilities, wantCaps)
		}
		if req.DPoP != nil {
			t.Errorf("expected nil DPoP for unverified card, got %+v", req.DPoP)
		}
	})

	t.Run("caching works", func(t *testing.T) {
		// Generate a throwaway Ed25519 keypair
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		// Create JWK representation
		jwk := map[string]interface{}{
			"kid": "test-key-001",
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pubKey),
		}
		jwks := map[string]interface{}{
			"keys": []interface{}{jwk},
		}

		// Serve JWK
		jkuServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer jkuServer.Close()

		callCount := 0
		var server *httptest.Server
		var signedCardBytes []byte

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if r.URL.Path == "/.well-known/agent-card.json" {
				if signedCardBytes == nil {
					cardWithoutSig := map[string]interface{}{
						"version": "1.0",
						"name":    "test-seller",
						"capabilities": map[string]interface{}{
							"extensions": []interface{}{
								map[string]interface{}{
									"uri": "https://modelcontextprotocol.io/ext/server/v1",
									"params": map[string]interface{}{
										"endpoint": server.URL + "/mcp/",
									},
								},
								map[string]interface{}{
									"uri": "https://ans.dev/ext/dpop/v1",
									"params": map[string]interface{}{
										"alg": "ES256",
										"htu": server.URL + "/mcp/",
									},
								},
							},
						},
					}
					cardBodyBytes, _ := json.Marshal(cardWithoutSig)
					protectedHeader := map[string]interface{}{
						"alg": "EdDSA",
						"jku": jkuServer.URL,
						"kid": "test-key-001",
					}
					protectedBytes, _ := json.Marshal(protectedHeader)
					protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
					payloadB64 := base64.RawURLEncoding.EncodeToString(cardBodyBytes)
					signingInput := protectedB64 + "." + payloadB64
					signature := ed25519.Sign(privKey, []byte(signingInput))
					signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
					cardWithoutSig["signatures"] = []interface{}{
						map[string]interface{}{
							"protected": protectedB64,
							"signature": signatureB64,
						},
					}
					signedCardBytes, _ = json.Marshal(cardWithoutSig)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(signedCardBytes)
				return
			}
			if r.URL.Path == "/mcp/" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(toolsListResponseBytes)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		discoverer := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)
		target := Target{
			Host: server.URL,
			Tool: "book_flight",
		}

		// First call
		req1 := discoverer.Discover(context.Background(), target)
		firstCallCount := callCount

		// Second call (should hit cache)
		req2 := discoverer.Discover(context.Background(), target)
		secondCallCount := callCount

		if req1.Empty() || req2.Empty() {
			t.Fatal("expected non-empty requirements")
		}
		if !reflect.DeepEqual(req1, req2) {
			t.Errorf("cached result differs from original")
		}
		if secondCallCount != firstCallCount {
			t.Errorf("expected cache hit (no new calls), but got %d calls on second request", secondCallCount-firstCallCount)
		}
	})
}

// TestCapsEqual tests the capsEqual helper function.
func TestCapsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []Capability
		b    []Capability
		want bool
	}{
		{name: "equal slices", a: []Capability{"mandate", "dpop_proof"}, b: []Capability{"mandate", "dpop_proof"}, want: true},
		{name: "equal different order", a: []Capability{"mandate", "dpop_proof"}, b: []Capability{"dpop_proof", "mandate"}, want: true},
		{name: "different lengths", a: []Capability{"mandate"}, b: []Capability{"mandate", "dpop_proof"}, want: false},
		{name: "different elements", a: []Capability{"mandate", "other"}, b: []Capability{"mandate", "dpop_proof"}, want: false},
		{name: "both empty", a: []Capability{}, b: []Capability{}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := capsEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("capsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestExtractMCPURL_ErrorPaths tests error handling in MCP URL extraction.
func TestExtractMCPURL_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		card    string
		wantErr bool
	}{
		{name: "MCP extension", card: `{"capabilities":{"extensions":[{"uri":"https://modelcontextprotocol.io/ext/server/v1","params":{"endpoint":"https://example.com/mcp/"}}]}}`, wantErr: false},
		{name: "supportedInterfaces", card: `{"supportedInterfaces":[{"protocolBinding":"https://modelcontextprotocol.io/spec/v1","url":"https://example.com/mcp/"}]}`, wantErr: false},
		{name: "missing MCP URL", card: `{"capabilities":{}}`, wantErr: true},
		{name: "invalid JSON", card: `{invalid`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractMCPURL([]byte(tt.card))
			if (err != nil) != tt.wantErr {
				t.Errorf("extractMCPURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerifyCardJWS_NoSignatures tests the no-signatures path.
func TestVerifyCardJWS_NoSignatures(t *testing.T) {
	card := `{"version":"1.0"}`
	// No signatures block returns false (not verified)
	if got := verifyCardJWS([]byte(card)); got {
		t.Errorf("verifyCardJWS() = %v, want false for no-signatures card", got)
	}
}

// TestVerifyCardJWS_InvalidJSON tests invalid JSON handling.
func TestVerifyCardJWS_InvalidJSON(t *testing.T) {
	card := `{invalid`
	if got := verifyCardJWS([]byte(card)); got {
		t.Error("verifyCardJWS() = true for invalid JSON, want false")
	}
}

// TestVerifyCardJWS_HermeticEd25519 tests Ed25519 signature verification with a hermetic httptest JWK server.
// This test actually exercises the signature verification path (not just JSON parsing).
func TestVerifyCardJWS_HermeticEd25519(t *testing.T) {
	// Generate a throwaway Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// Create JWK representation of the public key
	jwk := map[string]interface{}{
		"kid": "test-key-001",
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey),
	}
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	// Serve the JWK from httptest
	jkuServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jkuServer.Close()

	// Build an agent card WITHOUT signatures
	cardWithoutSig := map[string]interface{}{
		"version": "1.0",
		"name":    "test-agent",
		"capabilities": map[string]interface{}{
			"extensions": []interface{}{
				map[string]interface{}{
					"uri": "https://modelcontextprotocol.io/ext/server/v1",
					"params": map[string]interface{}{
						"endpoint": "https://example.com/mcp/",
					},
				},
			},
		},
	}

	// Serialize to canonical JSON
	cardBodyBytes, err := json.Marshal(cardWithoutSig)
	if err != nil {
		t.Fatalf("failed to marshal card body: %v", err)
	}

	// Build JWS protected header
	protectedHeader := map[string]interface{}{
		"alg": "EdDSA",
		"jku": jkuServer.URL,
		"kid": "test-key-001",
		"typ": "application/agent-card+json",
	}
	protectedBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(cardBodyBytes)

	// Sign: Ed25519.Sign(protected.payload)
	signingInput := protectedB64 + "." + payloadB64
	signature := ed25519.Sign(privKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build the signed card
	cardWithoutSig["signatures"] = []interface{}{
		map[string]interface{}{
			"protected": protectedB64,
			"signature": signatureB64,
		},
	}
	signedCardBytes, err := json.Marshal(cardWithoutSig)
	if err != nil {
		t.Fatalf("failed to marshal signed card: %v", err)
	}

	// Test 1: UNMODIFIED signed card → verifies successfully
	t.Run("valid Ed25519 signature verifies", func(t *testing.T) {
		if got := verifyCardJWS(signedCardBytes); !got {
			t.Errorf("verifyCardJWS() = %v, want true for valid signature", got)
		}
	})

	// Test 2: Tamper the card body (keeping JSON valid) → signature verification fails
	t.Run("tampered card body fails Ed25519 verification", func(t *testing.T) {
		var tamperedCard map[string]interface{}
		if err := json.Unmarshal(signedCardBytes, &tamperedCard); err != nil {
			t.Fatalf("failed to unmarshal signed card: %v", err)
		}
		// Tamper: change the version field
		tamperedCard["version"] = "2.0"
		tamperedBytes, err := json.Marshal(tamperedCard)
		if err != nil {
			t.Fatalf("failed to marshal tampered card: %v", err)
		}

		// Tampered card should fail signature verification
		if got := verifyCardJWS(tamperedBytes); got {
			t.Error("verifyCardJWS() = true for tampered card, want false")
		}
	})
}

// Additional coverage tests for fix-round 1

// TestVerifyCardJWS_JkuUnreachable tests jku unreachable path.
func TestVerifyCardJWS_JkuUnreachable(t *testing.T) {
	// Generate a key and create a signed card
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kid": "test-key",
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pubKey),
			},
		},
	}

	jkuServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	jkuURL := jkuServer.URL

	cardBody := map[string]interface{}{"version": "1.0", "name": "test"}
	cardBodyBytes, _ := json.Marshal(cardBody)
	protectedHeader := map[string]interface{}{"alg": "EdDSA", "jku": jkuURL, "kid": "test-key"}
	protectedBytes, _ := json.Marshal(protectedHeader)
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(cardBodyBytes)
	signingInput := protectedB64 + "." + payloadB64
	signature := ed25519.Sign(privKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	cardBody["signatures"] = []interface{}{
		map[string]interface{}{"protected": protectedB64, "signature": signatureB64},
	}
	signedCard, _ := json.Marshal(cardBody)

	// Close server before verification
	jkuServer.Close()

	if got := verifyCardJWS(signedCard); got {
		t.Error("verifyCardJWS() = true for unreachable jku, want false")
	}
}

// TestVerifyCardJWS_MoreErrorPaths tests additional error paths.
func TestVerifyCardJWS_MoreErrorPaths(t *testing.T) {
	t.Run("invalid protected header base64", func(t *testing.T) {
		card := `{"signatures":[{"protected":"!!!invalid!!!","signature":"dGVzdA"}]}`
		if got := verifyCardJWS([]byte(card)); got {
			t.Error("want false for invalid protected base64")
		}
	})

	t.Run("invalid protected JSON", func(t *testing.T) {
		invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{bad"))
		card := fmt.Sprintf(`{"signatures":[{"protected":"%s","signature":"dGVzdA"}]}`, invalidJSON)
		if got := verifyCardJWS([]byte(card)); got {
			t.Error("want false for invalid protected JSON")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		hdr := map[string]interface{}{"alg": "RS256"}
		hdrBytes, _ := json.Marshal(hdr)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrBytes)
		card := fmt.Sprintf(`{"signatures":[{"protected":"%s","signature":"dGVzdA"}]}`, hdrB64)
		if got := verifyCardJWS([]byte(card)); got {
			t.Error("want false for unsupported alg")
		}
	})

	t.Run("invalid signature base64", func(t *testing.T) {
		hdr := map[string]interface{}{"alg": "EdDSA", "jku": "http://x", "kid": "k"}
		hdrBytes, _ := json.Marshal(hdr)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrBytes)
		card := fmt.Sprintf(`{"signatures":[{"protected":"%s","signature":"!!!bad!!!"}]}`, hdrB64)
		if got := verifyCardJWS([]byte(card)); got {
			t.Error("want false for invalid signature base64")
		}
	})
}

// TestFetchEdDSAPublicKey_AllPaths tests all fetchEdDSAPublicKey branches.
func TestFetchEdDSAPublicKey_AllPaths(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("success", func(t *testing.T) {
		jwks := map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kid": "k", "kty": "OKP", "crv": "Ed25519",
					"x": base64.RawURLEncoding.EncodeToString(pubKey),
				},
			},
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer srv.Close()
		key, err := fetchEdDSAPublicKey(srv.URL, "k")
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Errorf("want success, got err=%v", err)
		}
	})

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		_, err := fetchEdDSAPublicKey(srv.URL, "k")
		if err == nil {
			t.Error("want error for 404")
		}
	})

	t.Run("bad JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{bad`))
		}))
		defer srv.Close()
		_, err := fetchEdDSAPublicKey(srv.URL, "k")
		if err == nil {
			t.Error("want error for bad JSON")
		}
	})

	t.Run("key not found", func(t *testing.T) {
		jwks := map[string]interface{}{"keys": []interface{}{}}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer srv.Close()
		_, err := fetchEdDSAPublicKey(srv.URL, "missing")
		if err == nil {
			t.Error("want error for missing key")
		}
	})

	t.Run("wrong key type", func(t *testing.T) {
		jwks := map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kid": "k", "kty": "RSA", "crv": "Ed25519",
					"x": base64.RawURLEncoding.EncodeToString(pubKey),
				},
			},
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer srv.Close()
		_, err := fetchEdDSAPublicKey(srv.URL, "k")
		if err == nil {
			t.Error("want error for wrong kty")
		}
	})

	t.Run("bad x base64", func(t *testing.T) {
		jwks := map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kid": "k", "kty": "OKP", "crv": "Ed25519", "x": "!!!bad!!!",
				},
			},
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer srv.Close()
		_, err := fetchEdDSAPublicKey(srv.URL, "k")
		if err == nil {
			t.Error("want error for bad x base64")
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		jwks := map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kid": "k", "kty": "OKP", "crv": "Ed25519",
					"x": base64.RawURLEncoding.EncodeToString([]byte("short")),
				},
			},
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(jwks)
		}))
		defer srv.Close()
		_, err := fetchEdDSAPublicKey(srv.URL, "k")
		if err == nil {
			t.Error("want error for wrong key size")
		}
	})

	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		url := srv.URL
		srv.Close()
		_, err := fetchEdDSAPublicKey(url, "k")
		if err == nil {
			t.Error("want error for network failure")
		}
	})
}

// TestFetchURL_Errors tests fetchURL error branches.
func TestFetchURL_Errors(t *testing.T) {
	d := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, err := d.fetchURL(context.Background(), srv.URL)
		if err == nil {
			t.Error("want error for 500")
		}
	})

	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		url := srv.URL
		srv.Close()
		_, err := d.fetchURL(context.Background(), url)
		if err == nil {
			t.Error("want error for closed server")
		}
	})
}

// TestFetchToolsList_Errors tests fetchToolsList error branches.
func TestFetchToolsList_Errors(t *testing.T) {
	d := NewHTTPDiscoverer(&http.Client{Timeout: 5 * time.Second}, 10*time.Minute)

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()
		_, err := d.fetchToolsList(context.Background(), srv.URL)
		if err == nil {
			t.Error("want error for 400")
		}
	})

	t.Run("bad JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{bad`))
		}))
		defer srv.Close()
		_, err := d.fetchToolsList(context.Background(), srv.URL)
		if err == nil {
			t.Error("want error for bad JSON")
		}
	})

	t.Run("JSON-RPC error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "error": map[string]string{"message": "err"}}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()
		_, err := d.fetchToolsList(context.Background(), srv.URL)
		if err == nil {
			t.Error("want error for JSON-RPC error")
		}
	})

	t.Run("network error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		url := srv.URL
		srv.Close()
		_, err := d.fetchToolsList(context.Background(), url)
		if err == nil {
			t.Error("want error for closed server")
		}
	})
}

// TestParsePrerequisitesFromCard_AllPaths tests all parsePrerequisitesFromCard branches.
func TestParsePrerequisitesFromCard_AllPaths(t *testing.T) {
	d := NewHTTPDiscoverer(&http.Client{}, 0)

	t.Run("valid prereqs", func(t *testing.T) {
		card := []byte(`{"skills":[{"id":"t","description":"X. Prerequisites: a, b."}]}`)
		caps := d.parsePrerequisitesFromCard(card, "t")
		if len(caps) != 2 {
			t.Errorf("want 2 caps, got %d", len(caps))
		}
	})

	t.Run("no match", func(t *testing.T) {
		card := []byte(`{"skills":[{"id":"other","description":"X"}]}`)
		caps := d.parsePrerequisitesFromCard(card, "t")
		if caps != nil {
			t.Errorf("want nil, got %v", caps)
		}
	})

	t.Run("bad JSON", func(t *testing.T) {
		card := []byte(`{bad`)
		caps := d.parsePrerequisitesFromCard(card, "t")
		if caps != nil {
			t.Errorf("want nil, got %v", caps)
		}
	})

	t.Run("no prereqs", func(t *testing.T) {
		card := []byte(`{"skills":[{"id":"t","description":"No prereqs"}]}`)
		caps := d.parsePrerequisitesFromCard(card, "t")
		if caps != nil {
			t.Errorf("want nil, got %v", caps)
		}
	})
}

// TestNewHTTPDiscoverer_DefaultTTL tests the TTL default path.
func TestNewHTTPDiscoverer_DefaultTTL(t *testing.T) {
	d := NewHTTPDiscoverer(&http.Client{}, 0)
	if d.ttl != defaultDiscoveryTTL {
		t.Errorf("ttl = %v, want %v", d.ttl, defaultDiscoveryTTL)
	}
}
