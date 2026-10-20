package hydrator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type capturedRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

func captureServer(t *testing.T, status int, response string) (*httptest.Server, <-chan capturedRequest) {
	t.Helper()
	captured := make(chan capturedRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- capturedRequest{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body}
		if strings.HasPrefix(response, "{") {
			w.Header().Set("Content-Type", "application/problem+json")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

func TestNewHTTPSink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		baseURL      string
		wantEndpoint string
		wantErr      bool
	}{
		{name: "host only", baseURL: "https://ti.example", wantEndpoint: "https://ti.example/v1/internal/observations/import"},
		{name: "trailing slash", baseURL: "http://localhost:8080/", wantEndpoint: "http://localhost:8080/v1/internal/observations/import"},
		{name: "path prefix", baseURL: "https://ti.example/trust/", wantEndpoint: "https://ti.example/trust/v1/internal/observations/import"},
		{name: "unparseable", baseURL: "::bad", wantErr: true},
		{name: "wrong scheme", baseURL: "ftp://ti.example", wantErr: true},
		{name: "no host", baseURL: "https://", wantErr: true},
		{name: "relative", baseURL: "/v1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := NewHTTPSink(tt.baseURL, "", nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewHTTPSink() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if s.endpoint != tt.wantEndpoint {
				t.Fatalf("endpoint = %q, want %q", s.endpoint, tt.wantEndpoint)
			}
			if s.client == nil || s.client.Timeout != DefaultHTTPTimeout {
				t.Fatalf("client = %+v, want default with %v timeout", s.client, DefaultHTTPTimeout)
			}
		})
	}
}

func TestHTTPSinkPostRequest(t *testing.T) {
	t.Parallel()
	body := []byte(`{"observations":[]}`)

	t.Run("authenticated and signed", func(t *testing.T) {
		t.Parallel()
		srv, captured := captureServer(t, http.StatusOK, `{"imported":2}`)
		sink, err := NewHTTPSink(srv.URL, "admin-key", srv.Client())
		if err != nil {
			t.Fatalf("NewHTTPSink() error = %v", err)
		}
		if err := sink.Post(t.Context(), Batch{Body: body, Signature: "h.p.s"}); err != nil {
			t.Fatalf("Post() error = %v", err)
		}
		got := <-captured
		if got.method != http.MethodPost || got.path != ImportPath {
			t.Fatalf("request = %s %s", got.method, got.path)
		}
		if ct := got.header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q", ct)
		}
		if auth := got.header.Get("Authorization"); auth != "Bearer admin-key" {
			t.Fatalf("Authorization = %q", auth)
		}
		if sig := got.header.Get(BatchSignatureHeader); sig != "h.p.s" {
			t.Fatalf("%s = %q", BatchSignatureHeader, sig)
		}
		if !bytes.Equal(got.body, body) {
			t.Fatalf("body = %s", got.body)
		}
	})
	t.Run("unauthenticated and unsigned", func(t *testing.T) {
		t.Parallel()
		srv, captured := captureServer(t, http.StatusCreated, "")
		sink, err := NewHTTPSink(srv.URL, "", nil)
		if err != nil {
			t.Fatalf("NewHTTPSink() error = %v", err)
		}
		if err := sink.Post(t.Context(), Batch{Body: body}); err != nil {
			t.Fatalf("Post() error = %v", err)
		}
		got := <-captured
		if _, present := got.header["Authorization"]; present {
			t.Fatalf("Authorization sent without an admin key: %v", got.header)
		}
		if _, present := got.header[BatchSignatureHeader]; present {
			t.Fatalf("signature header sent for an unsigned batch: %v", got.header)
		}
	})
}

func TestHTTPSinkPostErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		status     int
		response   string
		wantErr    *ImportError
		wantString string
	}{
		{
			name:     "422 problem",
			status:   http.StatusUnprocessableEntity,
			response: `{"type":"about:blank","title":"Unprocessable Entity","status":422,"detail":"signal \"x\" is not registered in this binary","code":"UNKNOWN_SIGNAL"}`,
			wantErr: &ImportError{
				Status: http.StatusUnprocessableEntity, Title: "Unprocessable Entity",
				Detail: `signal "x" is not registered in this binary`, Code: "UNKNOWN_SIGNAL",
			},
			wantString: `hydrator: import returned HTTP 422 Unprocessable Entity (UNKNOWN_SIGNAL): signal "x" is not registered in this binary`,
		},
		{
			name:       "400 problem without code",
			status:     http.StatusBadRequest,
			response:   `{"title":"Bad Request","status":400,"detail":"observations: at least one observation is required"}`,
			wantErr:    &ImportError{Status: http.StatusBadRequest, Title: "Bad Request", Detail: "observations: at least one observation is required"},
			wantString: "hydrator: import returned HTTP 400 Bad Request: observations: at least one observation is required",
		},
		{
			name:       "401 problem",
			status:     http.StatusUnauthorized,
			response:   `{"title":"Unauthorized","status":401,"detail":"missing or invalid admin bearer key","code":"UNAUTHORIZED"}`,
			wantErr:    &ImportError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "missing or invalid admin bearer key", Code: "UNAUTHORIZED"},
			wantString: "hydrator: import returned HTTP 401 Unauthorized (UNAUTHORIZED): missing or invalid admin bearer key",
		},
		{
			name:       "500 plain text",
			status:     http.StatusInternalServerError,
			response:   "upstream exploded\n",
			wantErr:    &ImportError{Status: http.StatusInternalServerError, Title: "Internal Server Error", Detail: `"upstream exploded"`},
			wantString: `hydrator: import returned HTTP 500 Internal Server Error: "upstream exploded"`,
		},
		{
			name:       "503 empty body",
			status:     http.StatusServiceUnavailable,
			wantErr:    &ImportError{Status: http.StatusServiceUnavailable, Title: "Service Unavailable"},
			wantString: "hydrator: import returned HTTP 503 Service Unavailable",
		},
		{
			name:       "json without problem fields",
			status:     http.StatusBadGateway,
			response:   `{"error":"nope"}`,
			wantErr:    &ImportError{Status: http.StatusBadGateway, Title: "Bad Gateway", Detail: `"{\"error\":\"nope\"}"`},
			wantString: `hydrator: import returned HTTP 502 Bad Gateway: "{\"error\":\"nope\"}"`,
		},
		{
			name:     "long body is truncated",
			status:   http.StatusInternalServerError,
			response: strings.Repeat("e", 2*maxErrorBodyBytes),
			wantErr:  &ImportError{Status: http.StatusInternalServerError, Title: "Internal Server Error", Detail: `"` + strings.Repeat("e", maxErrorBodyBytes) + `"`},
		},
		{
			name:     "control characters are quoted",
			status:   http.StatusInternalServerError,
			response: "line1\x1b[31mred",
			wantErr:  &ImportError{Status: http.StatusInternalServerError, Title: "Internal Server Error", Detail: `"line1\x1b[31mred"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := captureServer(t, tt.status, tt.response)
			sink, err := NewHTTPSink(srv.URL, "k", nil)
			if err != nil {
				t.Fatalf("NewHTTPSink() error = %v", err)
			}
			err = sink.Post(t.Context(), Batch{Body: []byte("{}")})
			var ie *ImportError
			if !errors.As(err, &ie) {
				t.Fatalf("Post() error = %v, want *ImportError", err)
			}
			if *ie != *tt.wantErr {
				t.Fatalf("ImportError = %+v, want %+v", *ie, *tt.wantErr)
			}
			if tt.wantString != "" && err.Error() != tt.wantString {
				t.Fatalf("Error() = %q, want %q", err.Error(), tt.wantString)
			}
		})
	}
}

func TestHTTPSinkPostTransportFailures(t *testing.T) {
	t.Parallel()

	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		sink, err := NewHTTPSink(srv.URL, "", nil)
		if err != nil {
			t.Fatalf("NewHTTPSink() error = %v", err)
		}
		err = sink.Post(t.Context(), Batch{Body: []byte("{}")})
		var ie *ImportError
		if err == nil || errors.As(err, &ie) || !strings.Contains(err.Error(), "post import") {
			t.Fatalf("Post() error = %v, want a transport error", err)
		}
	})
	t.Run("context cancelled", func(t *testing.T) {
		t.Parallel()
		srv, _ := captureServer(t, http.StatusOK, "")
		sink, err := NewHTTPSink(srv.URL, "", nil)
		if err != nil {
			t.Fatalf("NewHTTPSink() error = %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := sink.Post(ctx, Batch{Body: []byte("{}")}); !errors.Is(err, context.Canceled) {
			t.Fatalf("Post() error = %v, want context.Canceled", err)
		}
	})
	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		srv, _ := captureServer(t, http.StatusOK, "")
		sink, err := NewHTTPSink(srv.URL, "", nil)
		if err != nil {
			t.Fatalf("NewHTTPSink() error = %v", err)
		}
		var ctx context.Context
		if err := sink.Post(ctx, Batch{Body: []byte("{}")}); err == nil || !strings.Contains(err.Error(), "build import request") {
			t.Fatalf("Post() error = %v, want request build failure", err)
		}
	})
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriterSink(t *testing.T) {
	t.Parallel()
	body := []byte(`{"observations":[]}`)

	t.Run("unsigned", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		if err := NewWriterSink(&out).Post(t.Context(), Batch{Body: body}); err != nil {
			t.Fatalf("Post() error = %v", err)
		}
		if out.String() != string(body)+"\n" {
			t.Fatalf("output = %q", out.String())
		}
	})
	t.Run("signed", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		if err := NewWriterSink(&out).Post(t.Context(), Batch{Body: body, Signature: "h.p.s"}); err != nil {
			t.Fatalf("Post() error = %v", err)
		}
		if out.String() != string(body)+"\nh.p.s\n" {
			t.Fatalf("output = %q", out.String())
		}
	})
	t.Run("write failure", func(t *testing.T) {
		t.Parallel()
		err := NewWriterSink(failingWriter{}).Post(t.Context(), Batch{Body: body})
		if err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Fatalf("Post() error = %v, want write failure", err)
		}
	})
}
