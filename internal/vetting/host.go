package vetting

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/verify"
)

const httpsScheme = "https"

// normalizeName lowercases a DNS name and drops surrounding whitespace and the
// trailing root dot.
func normalizeName(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
}

// normalizeHost turns the host a caller dialed into the cache key: a
// normalized name with any port and IPv6 brackets removed.
func normalizeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if hostOnly, _, err := net.SplitHostPort(h); err == nil && hostOnly != "" {
		h = hostOnly
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return normalizeName(h)
}

func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// isIPRange recognises the CIDR form OpenShell accepts in allowed_ips.
func isIPRange(host string) bool {
	_, err := netip.ParsePrefix(host)
	return err == nil
}

// exemptSet holds vetting.exempt_hosts: exact names and "*.suffix" patterns.
// A suffix pattern matches subdomains only; list the apex separately to
// exempt it.
type exemptSet struct {
	exact    map[string]struct{}
	suffixes []string
}

func parseExemptHosts(patterns []string) (exemptSet, error) {
	set := exemptSet{exact: make(map[string]struct{}, len(patterns))}
	for _, raw := range patterns {
		p := normalizeName(raw)
		if p == "" {
			return exemptSet{}, errors.New("vetting: exempt_hosts contains an empty entry")
		}
		suffix, wildcard := strings.CutPrefix(p, "*.")
		if strings.Contains(suffix, "*") || (wildcard && suffix == "") {
			return exemptSet{}, fmt.Errorf("vetting: unsupported exempt_hosts pattern %q (use a hostname or *.suffix)", raw)
		}
		if wildcard {
			set.suffixes = append(set.suffixes, "."+suffix)
			continue
		}
		set.exact[p] = struct{}{}
	}
	return set, nil
}

func (e exemptSet) contains(host string) bool {
	if _, ok := e.exact[host]; ok {
		return true
	}
	for _, suffix := range e.suffixes {
		if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// tlAllowlist is vetting.trusted_tl_domains. A badge URL host is trusted when
// it equals a listed domain or is a subdomain of one.
type tlAllowlist []string

func parseTrustedDomains(domains []string) (tlAllowlist, error) {
	list := make(tlAllowlist, 0, len(domains))
	for _, raw := range domains {
		d := normalizeName(raw)
		if d == "" || strings.ContainsAny(d, "*/:@ \t") {
			return nil, fmt.Errorf("vetting: trusted_tl_domains entry %q is not a hostname", raw)
		}
		list = append(list, d)
	}
	if len(list) == 0 {
		return nil, errors.New("vetting: trusted_tl_domains must name at least one transparency log")
	}
	return list, nil
}

func (a tlAllowlist) trusts(hostname string) bool {
	for _, d := range a {
		if hostname == d || strings.HasSuffix(hostname, "."+d) {
			return true
		}
	}
	return false
}

// filter keeps the records whose badge URL may be fetched, highest version
// first, and reports why the first rejected record was refused.
func (a tlAllowlist) filter(records []verify.AnsBadgeRecord) ([]verify.AnsBadgeRecord, string) {
	kept := make([]verify.AnsBadgeRecord, 0, len(records))
	reason := ""
	for _, rec := range records {
		if why := a.reject(rec.URL); why != "" {
			if reason == "" {
				reason = why
			}
			continue
		}
		kept = append(kept, rec)
	}
	slices.SortStableFunc(kept, byVersionDesc)
	return kept, reason
}

// reject explains why rawURL must not be fetched, or returns "" when it names
// a trusted transparency log over HTTPS on the default port.
func (a tlAllowlist) reject(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "badge url is malformed"
	}
	hostname := normalizeName(u.Hostname())
	switch {
	case u.Scheme != httpsScheme:
		return "badge url is not https"
	case u.User != nil:
		return "badge url carries userinfo"
	case hostname == "":
		return "badge url has no host"
	case u.Port() != "" && u.Port() != "443":
		return "badge url uses a non-standard port"
	case !a.trusts(hostname):
		return "untrusted transparency log " + hostname
	}
	return ""
}

func byVersionDesc(a, b verify.AnsBadgeRecord) int {
	switch {
	case a.Version == nil && b.Version == nil:
		return 0
	case a.Version == nil:
		return 1
	case b.Version == nil:
		return -1
	}
	return b.Version.Compare(*a.Version)
}
