package vetting

import (
	"slices"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/verify"
)

func TestNormalizeHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"Agent.Example.COM.", testHost},
		{"  agent.example.com  ", testHost},
		{"agent.example.com:8443", testHost},
		{"192.0.2.1:443", "192.0.2.1"},
		{"[::1]:443", "::1"},
		{"[::1]", "::1"},
		{"::1", "::1"},
		{"", ""},
		{":443", ":443"},
	}
	for _, tt := range tests {
		if got := normalizeHost(tt.in); got != tt.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExemptSet(t *testing.T) {
	t.Parallel()
	set, err := parseExemptHosts([]string{"API.openai.com.", "*.Amazonaws.com"})
	if err != nil {
		t.Fatalf("parseExemptHosts() error = %v", err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"api.openai.com", true},
		{"openai.com", false},
		{"s3.amazonaws.com", true},
		{"a.b.amazonaws.com", true},
		{"amazonaws.com", false},
		{"notamazonaws.com", false},
		{"*.amazonaws.com", true},
	}
	for _, tt := range tests {
		if got := set.contains(tt.host); got != tt.want {
			t.Errorf("contains(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestParseExemptHostsErrors(t *testing.T) {
	t.Parallel()
	for _, patterns := range [][]string{{""}, {" . "}, {"*."}, {"api.*.example.com"}, {"*.*.example.com"}, {"*"}} {
		if _, err := parseExemptHosts(patterns); err == nil {
			t.Errorf("parseExemptHosts(%q) expected an error", patterns)
		}
	}
}

func TestParseTrustedDomains(t *testing.T) {
	t.Parallel()
	list, err := parseTrustedDomains([]string{" TL.Example.com. ", "logs.example.net"})
	if err != nil {
		t.Fatalf("parseTrustedDomains() error = %v", err)
	}
	if want := (tlAllowlist{trustedTL, "logs.example.net"}); !slices.Equal(list, want) {
		t.Fatalf("parseTrustedDomains() = %v, want %v", list, want)
	}
	for _, domains := range [][]string{nil, {}, {""}, {"https://tl.example.com"}, {"tl.example.com:443"}, {"*.example.com"}, {"tl.example.com/v1"}, {"tl example.com"}} {
		if _, err := parseTrustedDomains(domains); err == nil {
			t.Errorf("parseTrustedDomains(%q) expected an error", domains)
		}
	}
}

func TestTLAllowlistReject(t *testing.T) {
	t.Parallel()
	list := tlAllowlist{trustedTL}
	tests := []struct {
		rawURL string
		want   string
	}{
		{"https://tl.example.com/v1/agents/x", ""},
		{"https://TL.Example.COM./v1/agents/x", ""},
		{"https://eu.tl.example.com/v1/agents/x", ""},
		{"https://tl.example.com:443/v1/agents/x", ""},
		{"https://nottl.example.com/v1/agents/x", "untrusted transparency log nottl.example.com"},
		{"https://evil.example.net/v1/agents/x", "untrusted transparency log evil.example.net"},
		{"http://tl.example.com/v1/agents/x", "badge url is not https"},
		{"https://user@tl.example.com/v1/agents/x", "badge url carries userinfo"},
		{"https:///v1/agents/x", "badge url has no host"},
		{"https://tl.example.com:8443/v1/agents/x", "badge url uses a non-standard port"},
		{"https://tl.example.com:bad/v1/agents/x", "badge url is malformed"},
	}
	for _, tt := range tests {
		if got := list.reject(tt.rawURL); got != tt.want {
			t.Errorf("reject(%q) = %q, want %q", tt.rawURL, got, tt.want)
		}
	}
}

func TestTLAllowlistFilterOrdersByVersion(t *testing.T) {
	t.Parallel()
	list := tlAllowlist{trustedTL}
	records := []verify.AnsBadgeRecord{
		record("", badgeURL("none")),
		record("v1.2.0", badgeURL("v1.2")),
		record("v2.0.0", "https://evil.example.net/v1/agents/x"),
		record("", badgeURL("none2")),
		record("v1.10.0", badgeURL("v1.10")),
	}
	kept, reason := list.filter(records)
	urls := make([]string, 0, len(kept))
	for _, rec := range kept {
		urls = append(urls, strings.TrimPrefix(rec.URL, badgeURL("")))
	}
	if want := []string{"v1.10", "v1.2", "none", "none2"}; !slices.Equal(urls, want) {
		t.Fatalf("filter() order = %v, want %v", urls, want)
	}
	if reason != "untrusted transparency log evil.example.net" {
		t.Fatalf("filter() reason = %q", reason)
	}
	if _, reason := list.filter(records[:2]); reason != "" {
		t.Fatalf("filter() reason = %q, want none", reason)
	}
}

func TestByVersionDesc(t *testing.T) {
	t.Parallel()
	v1 := record("v1.0.0", "")
	v2 := record("v2.0.0", "")
	none := record("", "")
	tests := []struct {
		name string
		a, b verify.AnsBadgeRecord
		want int
	}{
		{name: "both versionless", a: none, b: none, want: 0},
		{name: "versionless sorts after", a: none, b: v1, want: 1},
		{name: "versioned sorts before versionless", a: v1, b: none, want: -1},
		{name: "higher sorts first", a: v2, b: v1, want: -1},
		{name: "lower sorts last", a: v1, b: v2, want: 1},
		{name: "equal", a: v1, b: v1, want: 0},
	}
	for _, tt := range tests {
		if got := byVersionDesc(tt.a, tt.b); got != tt.want {
			t.Errorf("%s: byVersionDesc() = %d, want %d", tt.name, got, tt.want)
		}
	}
}
