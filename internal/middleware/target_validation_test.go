package middleware

import (
	"testing"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
)

func TestTargetURL_RejectsAuthorityRebinding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host string
		ok   bool
		want string
	}{
		{host: "tools.example.com", ok: true, want: "https://tools.example.com/v1"},
		{host: "2001:db8::1", ok: true, want: "https://[2001:db8::1]/v1"},
		{host: "[2001:db8::1]", ok: true, want: "https://[2001:db8::1]/v1"},
		{host: "evil.example/", ok: false},
		{host: "evil.example/../other", ok: false},
		{host: "user@evil.example", ok: false},
		{host: "evil.example?x=1", ok: false},
		{host: "evil.example#frag", ok: false},
		{host: "evil example", ok: false},
		{host: "evil.example:443:8443", ok: false},
		{host: "[not-an-ip]", ok: false},
		{host: "evil]example", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			t.Parallel()
			got, err := TargetURL(&middlewarev1.HttpRequestTarget{Scheme: "https", Host: tt.host, Port: 443, Method: "GET", Path: "/v1"})
			if (err == nil) != tt.ok {
				t.Fatalf("TargetURL(%q) error = %v, want ok=%v", tt.host, err, tt.ok)
			}
			if tt.ok && got != tt.want {
				t.Fatalf("TargetURL(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
