package vetting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
)

// resolve runs one uncached lookup: DNS record, trusted-TL allowlist, badge
// status and, when configured, the Trust Index threshold.
func (s *Service) resolve(ctx context.Context, fqdn models.Fqdn) Verdict {
	host := fqdn.String()
	res, err := s.dns.LookupAnsBadge(ctx, fqdn)
	if err != nil {
		s.warn(ctx, host, "dns lookup failed", err)
		return Verdict{Host: host, Status: StatusError, Detail: "dns lookup failed"}
	}
	if !res.Found || len(res.Records) == 0 {
		return Verdict{Host: host, Status: StatusUnregistered, Detail: "no _ans-badge record"}
	}
	records, reason := s.trusted.filter(res.Records)
	if len(records) == 0 {
		return Verdict{Host: host, Status: StatusUntrustedTL, Detail: reason}
	}
	v := s.fetchBadges(ctx, host, records)
	if v.Status != StatusRegistered || s.trustIndex == nil {
		return v
	}
	return s.applyThreshold(ctx, v)
}

// badgeScan accumulates what the fetched badges said when none was ACTIVE.
type badgeScan struct {
	deprecated *models.Badge
	terminal   *models.Badge
	fetchErr   bool
	unknown    bool
}

// fetchBadges fetches badges highest version first and stops at the first
// ACTIVE or WARNING one. A badge sealed for a different host does not count
// for this one: a record may only vouch for the name it is published under.
func (s *Service) fetchBadges(ctx context.Context, host string, records []verify.AnsBadgeRecord) Verdict {
	var scan badgeScan
	for _, rec := range records {
		if ctx.Err() != nil {
			scan.fetchErr = true
			break
		}
		badge, err := s.tl.FetchBadge(ctx, rec.URL)
		if err != nil {
			s.warn(ctx, host, "badge fetch failed", err)
			scan.fetchErr = true
			continue
		}
		if normalizeName(badge.AgentHost()) != host {
			continue
		}
		switch {
		case badge.Status.IsActive():
			return badgeVerdict(host, StatusRegistered, badge)
		case badge.Status.IsValidForConnection():
			if scan.deprecated == nil {
				scan.deprecated = badge
			}
		case badge.Status.ShouldReject():
			if scan.terminal == nil {
				scan.terminal = badge
			}
		default:
			scan.unknown = true
		}
	}
	return scan.verdict(host)
}

func (b badgeScan) verdict(host string) Verdict {
	switch {
	case b.deprecated != nil:
		return badgeVerdict(host, StatusRegistered, b.deprecated)
	case b.fetchErr:
		return Verdict{Host: host, Status: StatusError, Detail: "badge fetch failed"}
	case b.unknown:
		return Verdict{Host: host, Status: StatusError, Detail: "badge status unknown"}
	case b.terminal != nil:
		return badgeVerdict(host, StatusRevoked, b.terminal)
	}
	return Verdict{Host: host, Status: StatusUnregistered, Detail: "badge names a different host"}
}

func badgeVerdict(host string, status Status, badge *models.Badge) Verdict {
	return Verdict{
		Host:        host,
		Status:      status,
		AnsName:     badge.AgentName(),
		AgentID:     badge.AgentID(),
		BadgeStatus: string(badge.Status),
		Detail:      "badge status " + string(badge.Status),
	}
}

// applyThreshold downgrades a registered verdict whose Trust Index score is
// missing or below the minimum.
func (s *Service) applyThreshold(ctx context.Context, v Verdict) Verdict {
	score, err := s.trustIndex.LowestDimension(ctx, v.AgentID)
	switch {
	case errors.Is(err, ErrNoTrustRecord):
		v.Status = StatusBelowThreshold
		v.Detail = "no trust index record"
	case err != nil:
		s.warn(ctx, v.Host, "trust index lookup failed", err)
		v.Status = StatusError
		v.Detail = "trust index unavailable"
	case score < s.minTrustScore:
		v.Status = StatusBelowThreshold
		v.Detail = fmt.Sprintf("trust index score %.0f below minimum %.0f", score, s.minTrustScore)
	}
	return v
}

func (s *Service) warn(ctx context.Context, host, msg string, err error) {
	s.logger.LogAttrs(ctx, slog.LevelWarn, msg, slog.String("host", host), slog.Any("error", err))
}

var _ Verifier = (*Service)(nil)
