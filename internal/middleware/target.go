package middleware

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
)

const (
	schemeHTTP       = "http"
	schemeHTTPS      = "https"
	schemeWS         = "ws"
	schemeWSS        = "wss"
	defaultPortHTTP  = 80
	defaultPortHTTPS = 443
)

// TargetURL renders the admitted target as the absolute URL the DPoP proof
// binds (ANS-6 section 7.3): scheme://host[:port]/path, with ws and wss mapped
// to http and https, the scheme's default port omitted, an empty path
// normalized to "/" and the query never included.
func TargetURL(t *middlewarev1.HttpRequestTarget) (string, error) {
	scheme, defaultPort, err := httpScheme(t.GetScheme())
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSpace(t.GetHost()))
	if host == "" {
		return "", errors.New("target host is required")
	}
	if !validAuthorityHost(host) {
		return "", errors.New("target host is not a valid authority")
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if port := t.GetPort(); port != 0 && port != defaultPort {
		host += ":" + strconv.FormatUint(uint64(port), 10)
	}
	path := t.GetPath()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path, nil
}

// httpScheme maps a target scheme to the HTTP scheme the proof binds and that
// scheme's default port.
func httpScheme(scheme string) (string, uint32, error) {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case schemeHTTP, schemeWS:
		return schemeHTTP, defaultPortHTTP, nil
	case schemeHTTPS, schemeWSS:
		return schemeHTTPS, defaultPortHTTPS, nil
	}
	return "", 0, fmt.Errorf("unsupported target scheme %q", scheme)
}

// validAuthorityHost rejects a host that could rebind the signed URL: anything
// that would terminate the authority or start a path, query, fragment or
// userinfo, and colons outside an IPv6 literal.
func validAuthorityHost(host string) bool {
	if strings.ContainsAny(host, "/@?#\\ \t\r\n") {
		return false
	}
	switch {
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		_, err := netip.ParseAddr(host[1 : len(host)-1])
		return err == nil
	case strings.ContainsAny(host, "[]"):
		return false
	case strings.Contains(host, ":"):
		_, err := netip.ParseAddr(host)
		return err == nil
	}
	return true
}
