package hydrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ImportPath is the Trust Index observation import endpoint.
const ImportPath = "/v1/internal/observations/import"

// BatchSignatureHeader carries the compact JWS over the request body. HTTP
// header names are case-insensitive; this is the canonical form net/http
// emits for X-ANS-Batch-Signature.
const BatchSignatureHeader = "X-Ans-Batch-Signature"

// DefaultHTTPTimeout bounds one import request when no client is supplied.
const DefaultHTTPTimeout = 10 * time.Second

const (
	maxResponseBytes  = 64 << 10
	maxErrorBodyBytes = 256
)

// Batch is one import request: the observations, the exact body bytes that
// are posted and the signature over them when the batch is signed.
type Batch struct {
	Observations []Observation
	Body         []byte
	Signature    string
}

// Sink delivers a batch.
type Sink interface {
	Post(ctx context.Context, batch Batch) error
}

// ImportError is a non-2xx answer from the import API. Title, Detail and Code
// come from the RFC 7807 problem body when there is one; otherwise Title is
// the status text and Detail a bounded, quoted excerpt of the body.
type ImportError struct {
	Status int
	Title  string
	Detail string
	Code   string
}

func newImportError(status int, body []byte) *ImportError {
	ie := &ImportError{Status: status}
	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Code   string `json:"code"`
	}
	if err := json.Unmarshal(body, &problem); err == nil && (problem.Title != "" || problem.Detail != "" || problem.Code != "") {
		ie.Title, ie.Detail, ie.Code = problem.Title, problem.Detail, problem.Code
		return ie
	}
	ie.Title = http.StatusText(status)
	if excerpt := bytes.TrimSpace(body); len(excerpt) > 0 {
		ie.Detail = strconv.Quote(string(excerpt[:min(len(excerpt), maxErrorBodyBytes)]))
	}
	return ie
}

// Error implements error.
func (e *ImportError) Error() string {
	var b strings.Builder
	b.WriteString("hydrator: import returned HTTP ")
	b.WriteString(strconv.Itoa(e.Status))
	if e.Title != "" {
		b.WriteString(" " + e.Title)
	}
	if e.Code != "" {
		b.WriteString(" (" + e.Code + ")")
	}
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	return b.String()
}

// HTTPSink posts batches to the Trust Index import API.
type HTTPSink struct {
	endpoint string
	adminKey string
	client   *http.Client
	// UserAgent identifies the producer to the Trust Index when set, for
	// example "ans-ocsf-hydrator/0.1.0".
	UserAgent string
}

// NewHTTPSink targets the Trust Index at baseURL. adminKey is sent as
// "Authorization: Bearer <adminKey>" when non-empty, which is how the import
// API's admin middleware expects it; leave it empty for a deployment whose
// import routes run unauthenticated. A nil client uses one with
// DefaultHTTPTimeout.
func NewHTTPSink(baseURL, adminKey string, client *http.Client) (*HTTPSink, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("hydrator: base url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("hydrator: base url %q must be http(s) with a host", baseURL)
	}
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &HTTPSink{endpoint: u.JoinPath(ImportPath).String(), adminKey: adminKey, client: client}, nil
}

// Post sends the batch and returns an *ImportError for a non-2xx answer.
func (s *HTTPSink) Post(ctx context.Context, batch Batch) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(batch.Body))
	if err != nil {
		return fmt.Errorf("hydrator: build import request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	if s.adminKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.adminKey)
	}
	if batch.Signature != "" {
		req.Header.Set(BatchSignatureHeader, batch.Signature)
	}
	resp, err := s.client.Do(req) //nolint:gosec // G704: the endpoint is operator configuration validated in NewHTTPSink, never request input
	if err != nil {
		return fmt.Errorf("hydrator: post import: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("hydrator: read import response: %w", err)
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	return newImportError(resp.StatusCode, body)
}

// WriterSink writes the request body to w for dry runs: the body on one line,
// followed by the compact JWS on its own line when the batch is signed.
type WriterSink struct {
	w io.Writer
}

// NewWriterSink returns a WriterSink over w.
func NewWriterSink(w io.Writer) *WriterSink {
	return &WriterSink{w: w}
}

// Post writes the batch.
func (s *WriterSink) Post(_ context.Context, batch Batch) error {
	var buf bytes.Buffer
	buf.Write(batch.Body)
	buf.WriteByte('\n')
	if batch.Signature != "" {
		buf.WriteString(batch.Signature)
		buf.WriteByte('\n')
	}
	if _, err := s.w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("hydrator: write batch: %w", err)
	}
	return nil
}
