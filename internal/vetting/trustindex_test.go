package vetting

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPTrustIndexClientLowestDimension(t *testing.T) {
	t.Parallel()
	vector := `{"agentId":"a1","trustEvaluation":{"agentId":"a1","trustVector":{"integrity":90,"identity":70,"solvency":55,"behavior":80,"safety":100},"recommendedProfile":"TRANSACTIONAL"}}`
	tests := []struct {
		name       string
		status     int
		body       string
		want       float64
		wantErr    error
		wantErrSub string
	}{
		{name: "lowest dimension", status: http.StatusOK, body: vector, want: 55},
		{name: "not found", status: http.StatusNotFound, body: `{"type":"about:blank","code":"AGENT_NOT_FOUND"}`, wantErr: ErrNoTrustRecord},
		{name: "server error", status: http.StatusInternalServerError, wantErrSub: "unexpected status 500"},
		{name: "malformed json", status: http.StatusOK, body: "{", wantErrSub: "decode response"},
		{name: "missing evaluation", status: http.StatusOK, body: `{"agentId":"a1"}`, wantErrSub: "no trust vector"},
		{name: "missing vector", status: http.StatusOK, body: `{"trustEvaluation":{"agentId":"a1"}}`, wantErrSub: "no trust vector"},
		{name: "oversized body", status: http.StatusOK, body: `{"pad":"` + strings.Repeat("x", maxTrustIndexResponseBytes) + `",` + vector[1:], wantErrSub: "decode response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotPath, gotAccept string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotAccept = r.URL.EscapedPath(), r.Header.Get("Accept")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)
			client, err := NewHTTPTrustIndexClient(server.URL+"/", server.Client())
			if err != nil {
				t.Fatalf("NewHTTPTrustIndexClient() error = %v", err)
			}
			got, err := client.LowestDimension(t.Context(), "agent/1")
			if gotPath != "/v1/ans/registered-agents/agent%2F1" || gotAccept != "application/json" {
				t.Fatalf("request path %q accept %q", gotPath, gotAccept)
			}
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("LowestDimension() error = %v, want %v", err, tt.wantErr)
				}
			case tt.wantErrSub != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("LowestDimension() error = %v, want containing %q", err, tt.wantErrSub)
				}
			default:
				if err != nil || got != tt.want {
					t.Fatalf("LowestDimension() = %v, %v; want %v", got, err, tt.want)
				}
			}
		})
	}
}

func TestHTTPTrustIndexClientRequestFailures(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("no request expected")
	}))
	client, err := NewHTTPTrustIndexClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("NewHTTPTrustIndexClient() error = %v", err)
	}
	if _, err := client.LowestDimension(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "empty agent id") {
		t.Fatalf("LowestDimension(\"\") error = %v", err)
	}
	server.Close()
	if _, err := client.LowestDimension(t.Context(), "a1"); err == nil {
		t.Fatal("LowestDimension() against a closed server should fail")
	}
}

func TestNewHTTPTrustIndexClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		baseURL  string
		wantBase string
		wantErr  bool
	}{
		{baseURL: "https://ti.example.com/", wantBase: "https://ti.example.com"},
		{baseURL: " http://localhost:8080 ", wantBase: "http://localhost:8080"},
		{baseURL: "", wantErr: true},
		{baseURL: "ftp://ti.example.com", wantErr: true},
		{baseURL: "https://", wantErr: true},
		{baseURL: "ti.example.com", wantErr: true},
		{baseURL: "http://[::1", wantErr: true},
	}
	for _, tt := range tests {
		client, err := NewHTTPTrustIndexClient(tt.baseURL, nil)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewHTTPTrustIndexClient(%q) error = %v, wantErr %v", tt.baseURL, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if client.base != tt.wantBase {
			t.Errorf("NewHTTPTrustIndexClient(%q) base = %q, want %q", tt.baseURL, client.base, tt.wantBase)
		}
		if client.client.Timeout != 5*time.Second {
			t.Errorf("default client timeout = %v, want 5s", client.client.Timeout)
		}
	}
}
