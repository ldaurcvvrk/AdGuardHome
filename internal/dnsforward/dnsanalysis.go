// DNS analysis integration for the dnsforward package.
//
// This file adds enhanced DNS request analysis capabilities by collecting
// detailed per-request data and forwarding it to the dnsanalysis module.

package dnsforward

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsanalysis"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

// processAnalysis collects DNS analysis data for the given request.  It is
// called from processQueryLogsAndStats.  l and dctx must not be nil.
func (s *Server) processAnalysis(
	ctx context.Context,
	l *slog.Logger,
	dctx *dnsContext,
	analysis *dnsanalysis.Analysis,
) {
	if analysis == nil {
		return
	}

	pctx := dctx.proxyCtx
	q := pctx.Req.Question[0]
	host := aghnet.NormalizeDomain(q.Name)
	processingTime := time.Since(dctx.startTime)

	ip := pctx.Addr.Addr().AsSlice()
	s.anonymizer.Load()(ip)
	ipStr := net.IP(ip).String()

	// Build the analysis record.
	ra := &dnsanalysis.RequestAnalysis{
		ID:        fmt.Sprintf("%d", dns.Id()),
		Timestamp: dctx.startTime,
		Question: dnsanalysis.QuestionInfo{
			Name:  host,
			Type:  dns.TypeToString[q.Qtype],
			Class: dns.ClassToString[q.Qclass],
		},
		ClientIP: ipStr,
		ClientID: dctx.clientID,
		Protocol: protoToString(pctx.Proto),
		Timeline: dnsanalysis.TimelineInfo{
			TotalDuration: processingTime.Nanoseconds(),
		},
		ResponseCode:     pctx.Res.Rcode,
		ResponseCodeName: dns.RcodeToString[pctx.Res.Rcode],
	}

	// Filtering info.
	if dctx.result != nil {
		fi := dnsanalysis.FilteringInfo{
			Matched: dctx.result.Reason.Matched(),
			Reason:  reasonToString(dctx.result.Reason),
		}

		if dctx.result.ServiceName != "" {
			fi.ServiceName = dctx.result.ServiceName
		}

		if dctx.result.CanonName != "" {
			fi.CanonName = dctx.result.CanonName
		}

		if len(dctx.result.Rules) > 0 {
			fi.MatchedRules = make([]string, 0, len(dctx.result.Rules))
			for _, r := range dctx.result.Rules {
				fi.MatchedRules = append(fi.MatchedRules, r.Text)
			}
		}

		switch dctx.result.Reason {
		case filtering.FilteredSafeBrowsing:
			fi.SafeBrowsingHit = true
		case filtering.FilteredParental:
			fi.ParentalHit = true
		case filtering.FilteredSafeSearch:
			fi.SafeSearchApplied = true
		case filtering.Rewritten, filtering.RewrittenRule:
			fi.RewritesApplied = true
		}

		ra.Filtering = fi
	}

	// Upstream and cache info.
	if pctx.Upstream != nil {
		ra.Upstream.Address = pctx.Upstream.Address()
	}

	if qs := pctx.QueryStatistics(); qs != nil {
		ms := qs.Main()
		if len(ms) == 1 {
			ra.Upstream.Duration = ms[0].QueryDuration.Nanoseconds()
			if ms[0].IsCached {
				ra.Upstream.IsCached = true
				ra.Cache.Hit = true
				ra.Upstream.Address = ms[0].Address
			}
		}
	}

	// Error info.
	if dctx.err != nil {
		ra.Error = dctx.err.Error()
	}

	analysis.Record(ra)
}

// protoToString converts a proxy protocol to a human-readable string.
func protoToString(p proxy.Proto) (s string) {
	switch p {
	case proxy.ProtoUDP:
		return "udp"
	case proxy.ProtoTCP:
		return "tcp"
	case proxy.ProtoHTTPS:
		return "doh"
	case proxy.ProtoQUIC:
		return "doq"
	case proxy.ProtoTLS:
		return "dot"
	case proxy.ProtoDNSCrypt:
		return "dnscrypt"
	default:
		return "unknown"
	}
}

// reasonToString converts a filtering reason to a human-readable string.
func reasonToString(reason filtering.Reason) (s string) {
	switch reason {
	case filtering.NotFilteredNotFound:
		return "NotFilteredNotFound"
	case filtering.NotFilteredAllowList:
		return "NotFilteredAllowList"
	case filtering.NotFilteredError:
		return "NotFilteredError"
	case filtering.FilteredBlockList:
		return "FilteredBlockList"
	case filtering.FilteredSafeBrowsing:
		return "FilteredSafeBrowsing"
	case filtering.FilteredParental:
		return "FilteredParental"
	case filtering.FilteredInvalid:
		return "FilteredInvalid"
	case filtering.FilteredSafeSearch:
		return "FilteredSafeSearch"
	case filtering.FilteredBlockedService:
		return "FilteredBlockedService"
	case filtering.Rewritten:
		return "Rewritten"
	case filtering.RewrittenAutoHosts:
		return "RewrittenAutoHosts"
	case filtering.RewrittenRule:
		return "RewrittenRule"
	default:
		return "Unknown"
	}
}