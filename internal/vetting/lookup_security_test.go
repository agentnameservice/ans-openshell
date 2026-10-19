package vetting

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
)

type badgeClientFunc func(context.Context, string) (*models.Badge, error)

func (f badgeClientFunc) FetchBadge(ctx context.Context, target string) (*models.Badge, error) {
	return f(ctx, target)
}

func TestBadgeScanStopsOnCancellation(t *testing.T) {
	t.Parallel()
	for _, afterFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "before first fetch", true: "after terminal badge"}[afterFirst], func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			h.deps.TL = badgeClientFunc(func(context.Context, string) (*models.Badge, error) {
				calls++
				cancel()
				return badgeFor(testHost, models.BadgeStatusRevoked), nil
			})
			if !afterFirst {
				cancel()
			}
			svc := h.service(t)
			got := svc.fetchBadges(ctx, testHost, []verify.AnsBadgeRecord{
				record("v2.0.0", badgeURL("v2")), record("v1.0.0", badgeURL("v1")),
			})
			wantCalls := 0
			if afterFirst {
				wantCalls = 1
			}
			if got.Status != StatusError || calls != wantCalls {
				t.Fatalf("fetchBadges() = %+v, calls %d; want error and %d calls", got, calls, wantCalls)
			}
		})
	}
}

func TestBadgeScanRespectsLookupDeadline(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.dns.WithRecords(testHost, []verify.AnsBadgeRecord{
		record("v2.0.0", badgeURL("v2")), record("v1.0.0", badgeURL("v1")),
	})
	h.deps.LookupTimeout = 10 * time.Millisecond
	var calls atomic.Int32
	h.deps.TL = badgeClientFunc(func(ctx context.Context, _ string) (*models.Badge, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	svc := h.service(t)
	got := svc.Lookup(t.Context(), testHost, time.Second)
	if got.Status != StatusError || calls.Load() != 1 {
		t.Fatalf("Lookup() = %+v, calls %d; want error and one fetch", got, calls.Load())
	}
}

type vettingTransportFunc func(*http.Request) (*http.Response, error)

func (f vettingTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHTTPVettingClientsRejectRedirects(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"badge", "trust index"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			for _, target := range []string{"", "https://other.example.com/forged", "http://tl.example.com/forged", "/moved", "https://tl.example.com:8443/forged"} {
				t.Run(target, func(t *testing.T) {
					t.Parallel()
					badge, err := json.Marshal(badgeFor(testHost, models.BadgeStatusActive))
					if err != nil {
						t.Fatal(err)
					}
					body := string(badge)
					if kind == "trust index" {
						body = `{"trustEvaluation":{"trustVector":{"integrity":90,"identity":90,"solvency":90,"behavior":90,"safety":90}}}`
					}
					var calls atomic.Int32
					transport := vettingTransportFunc(func(req *http.Request) (*http.Response, error) {
						status := http.StatusOK
						header := make(http.Header)
						if calls.Add(1) == 1 && target != "" {
							status = http.StatusFound
							header.Set("Location", target)
						}
						return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
					})
					if kind == "badge" {
						assertBadgeRedirectResult(t, transport, target != "")
					} else {
						assertTrustIndexRedirectResult(t, transport, target != "")
					}
					if calls.Load() != 1 {
						t.Fatalf("HTTP requests = %d, want one", calls.Load())
					}
				})
			}
		})
	}
}

func assertBadgeRedirectResult(t *testing.T, transport http.RoundTripper, redirected bool) {
	t.Helper()
	h := newHarness()
	h.registered(testHost)
	h.deps.TL = newHTTPBadgeClient(&http.Client{Transport: transport})
	svc := h.service(t)
	v := svc.Lookup(t.Context(), testHost, time.Second)
	want := StatusRegistered
	if redirected {
		want = StatusError
	}
	if v.Status != want {
		t.Fatalf("Lookup() = %+v, want %s", v, want)
	}
}

func assertTrustIndexRedirectResult(t *testing.T, transport http.RoundTripper, redirected bool) {
	t.Helper()
	client, err := NewHTTPTrustIndexClient("https://tl.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	client.client.Transport = transport
	score, err := client.LowestDimension(t.Context(), "agent-id")
	if !redirected && (err != nil || score != 90) {
		t.Fatalf("LowestDimension() = %v, %v; want 90", score, err)
	}
	if redirected && (err == nil || !strings.Contains(err.Error(), "unexpected status 302")) {
		t.Fatalf("LowestDimension() error = %v; want rejected redirect", err)
	}
}

func TestWithoutRedirectsPreservesSuppliedClient(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("supplied redirect policy")
	original := &http.Client{
		Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return wantErr
		},
	}
	configured := withoutRedirects(original)
	if configured == original || configured.Timeout != original.Timeout {
		t.Fatal("client must be copied with its timeout preserved")
	}
	if err := original.CheckRedirect(nil, nil); !errors.Is(err, wantErr) {
		t.Fatalf("original redirect policy changed: %v", err)
	}
	if err := configured.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("configured redirect policy = %v, want ErrUseLastResponse", err)
	}
}
