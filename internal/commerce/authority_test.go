package commerce

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-openshell/internal/commercekey"
)

func TestParseMandateResponse_Success(t *testing.T) {
	// Valid response with mandate in content[0].text
	responseBody := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"content": [
				{
					"type": "text",
					"text": "{\"mandate_id\":\"mandate-123\",\"quote_id\":\"quote-456\",\"subject_ans\":\"ans://traveler.example.com\",\"audience_ans\":\"ans://seller.example.com\",\"scope\":\"commerce:travel:book\",\"max_amount\":500.0,\"currency\":\"USD\",\"not_before\":\"2026-10-20T10:00:00Z\",\"not_after\":\"2026-10-20T11:00:00Z\",\"jkt\":\"test-jkt-123\",\"authority_ans\":\"ans://authority.example.com\",\"signature\":\"sig-abc\"}"
				}
			]
		}
	}`

	mandate, err := parseMandateResponse([]byte(responseBody))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if mandate.MandateID != "mandate-123" {
		t.Errorf("expected mandate_id mandate-123, got %s", mandate.MandateID)
	}
	if mandate.QuoteID != "quote-456" {
		t.Errorf("expected quote_id quote-456, got %s", mandate.QuoteID)
	}
	if mandate.JKT != "test-jkt-123" {
		t.Errorf("expected jkt test-jkt-123, got %s", mandate.JKT)
	}
}

func TestParseMandateResponse_Error(t *testing.T) {
	// Response with error object
	responseBody := `{
		"jsonrpc": "2.0",
		"id": 1,
		"error": {
			"code": -32001,
			"message": "POLICY_VIOLATION: insufficient credit limit"
		}
	}`

	mandate, err := parseMandateResponse([]byte(responseBody))
	if err == nil {
		t.Fatalf("expected error, got mandate: %+v", mandate)
	}

	if !strings.Contains(err.Error(), "POLICY_VIOLATION") {
		t.Errorf("expected error to contain POLICY_VIOLATION, got: %v", err)
	}
	if !strings.Contains(err.Error(), "insufficient credit limit") {
		t.Errorf("expected error to contain full message, got: %v", err)
	}
}

func TestParseMandateResponse_NoContent(t *testing.T) {
	// Response with empty content array
	responseBody := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"content": []
		}
	}`

	mandate, err := parseMandateResponse([]byte(responseBody))
	if err == nil {
		t.Fatalf("expected error for empty content, got mandate: %+v", mandate)
	}

	if !strings.Contains(err.Error(), "no content") {
		t.Errorf("expected error about no content, got: %v", err)
	}
}

func TestParseMandateResponse_Malformed(t *testing.T) {
	// Malformed JSON
	responseBody := `{"invalid": "not a valid response"}`

	mandate, err := parseMandateResponse([]byte(responseBody))
	if err == nil {
		t.Fatalf("expected error for malformed response, got mandate: %+v", mandate)
	}
}

func TestHTTPAuthority_RequestMandate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Assert method and content-type
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("expected Content-Type: application/json, got %s", ct)
			}

			// Read and parse request body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			// Unmarshal to verify structure
			var envelope struct {
				Jsonrpc string `json:"jsonrpc"`
				ID      int    `json:"id"`
				Method  string `json:"method"`
				Params  struct {
					Name      string       `json:"name"`
					Arguments MandateInput `json:"arguments"`
				} `json:"params"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("failed to unmarshal request: %v", err)
			}

			// Assert envelope structure
			if envelope.Jsonrpc != "2.0" {
				t.Errorf("expected jsonrpc 2.0, got %s", envelope.Jsonrpc)
			}
			if envelope.ID != 1 {
				t.Errorf("expected id 1, got %d", envelope.ID)
			}
			if envelope.Method != "tools/call" {
				t.Errorf("expected method tools/call, got %s", envelope.Method)
			}
			if envelope.Params.Name != "request_mandate" {
				t.Errorf("expected params.name request_mandate, got %s", envelope.Params.Name)
			}
			if envelope.Params.Arguments.QuoteID != "quote-789" {
				t.Errorf("expected quote_id quote-789, got %s", envelope.Params.Arguments.QuoteID)
			}

			// Return success response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"jsonrpc": "2.0",
				"id": 1,
				"result": {
					"content": [
						{
							"type": "text",
							"text": "{\"mandate_id\":\"mandate-999\",\"quote_id\":\"quote-789\",\"subject_ans\":\"ans://traveler.example.com\",\"audience_ans\":\"ans://seller.example.com\",\"scope\":\"commerce:travel:book\",\"max_amount\":1000.0,\"currency\":\"USD\",\"not_before\":\"2026-10-20T10:00:00Z\",\"not_after\":\"2026-10-20T11:00:00Z\",\"jkt\":\"test-jkt-456\",\"authority_ans\":\"ans://authority.example.com\",\"signature\":\"sig-xyz\"}"
						}
					]
				}
			}`))
		}))
		defer server.Close()

		// Create client
		client := NewHTTPAuthority(server.URL)

		// Make request
		input := MandateInput{
			QuoteID:     "quote-789",
			Total:       1000.0,
			Currency:    "USD",
			MerchantANS: "ans://seller.example.com",
			ScopeHint:   "commerce:travel:book",
			SubjectANS:  "ans://traveler.example.com",
			TravelerDPoPJWK: commercekey.JwkPublic{
				Kty: "EC",
				Crv: "P-256",
				X:   "test-x",
				Y:   "test-y",
			},
		}

		mandate, err := client.RequestMandate(context.Background(), input)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if mandate.MandateID != "mandate-999" {
			t.Errorf("expected mandate_id mandate-999, got %s", mandate.MandateID)
		}
		if mandate.QuoteID != "quote-789" {
			t.Errorf("expected quote_id quote-789, got %s", mandate.QuoteID)
		}
	})

	t.Run("non-2xx error", func(t *testing.T) {
		// Create test server that returns 500
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error: database connection failed"))
		}))
		defer server.Close()

		// Create client
		client := NewHTTPAuthority(server.URL)

		// Make request
		input := MandateInput{
			QuoteID:  "quote-error",
			Total:    100.0,
			Currency: "USD",
		}

		mandate, err := client.RequestMandate(context.Background(), input)
		if err == nil {
			t.Fatalf("expected error for non-2xx, got mandate: %+v", mandate)
		}

		// Should contain truncated body
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("expected error to contain 500, got: %v", err)
		}
	})
}
