package commerce

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	authorityTimeout = 30 * time.Second
	maxErrBodyLen    = 200
)

// HTTPAuthority is an HTTP client for requesting mandates from an authority
// service via JSON-RPC tools/call.
type HTTPAuthority struct {
	baseURL string
	client  *http.Client
}

// NewHTTPAuthority creates a new HTTP authority client with a sane timeout.
func NewHTTPAuthority(baseURL string) *HTTPAuthority {
	return &HTTPAuthority{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: authorityTimeout,
		},
	}
}

// jsonRPCRequest is the JSON-RPC request envelope for tools/call.
// Field order matters for byte-exact JSON matching in tests.
type jsonRPCRequest struct {
	Jsonrpc string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  toolCallParams `json:"params"`
}

// toolCallParams contains the params for the tools/call method.
type toolCallParams struct {
	Name      string       `json:"name"`
	Arguments MandateInput `json:"arguments"`
}

// jsonRPCResponse is the JSON-RPC response envelope.
type jsonRPCResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  *toolCallResult `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// toolCallResult contains the content array from a successful response.
type toolCallResult struct {
	Content []contentItem `json:"content"`
}

// contentItem represents a content item with type and text.
type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// jsonRPCError represents a JSON-RPC error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RequestMandate requests a mandate from the authority service via JSON-RPC.
// It implements the AuthorityClient interface.
func (h *HTTPAuthority) RequestMandate(ctx context.Context, in MandateInput) (*Mandate, error) {
	// Build JSON-RPC request envelope
	envelope := jsonRPCRequest{
		Jsonrpc: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: toolCallParams{
			Name:      "request_mandate",
			Arguments: in,
		},
	}

	// Marshal request to JSON
	requestBody, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for non-2xx status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Truncate body to 200 characters for error message
		truncated := string(body)
		if len(truncated) > maxErrBodyLen {
			truncated = truncated[:maxErrBodyLen]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncated)
	}

	// Parse mandate from response
	return parseMandateResponse(body)
}

// parseMandateResponse parses a mandate from a JSON-RPC response body.
// Returns an error if the response contains an error object, has no content,
// or cannot be parsed.
func parseMandateResponse(body []byte) (*Mandate, error) {
	var response jsonRPCResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("JSON parse failed: %w", err)
	}

	// Check for error object
	if response.Error != nil {
		return nil, fmt.Errorf("authority error: %s", response.Error.Message)
	}

	// Check for result
	if response.Result == nil {
		return nil, errors.New("no result in response")
	}

	// Check for content
	if len(response.Result.Content) == 0 {
		return nil, errors.New("no content in authority response")
	}

	// Parse mandate from first content item text
	mandateText := response.Result.Content[0].Text
	var mandate Mandate
	if err := json.Unmarshal([]byte(mandateText), &mandate); err != nil {
		return nil, fmt.Errorf("failed to parse mandate from content: %w", err)
	}

	return &mandate, nil
}
