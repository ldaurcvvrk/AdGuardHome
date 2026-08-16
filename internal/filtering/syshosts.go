package filtering

import (
	"net/netip"

	"github.com/miekg/dns"
)

// matchSysHosts looks up the host in the system hosts file storage and returns
// a rewrite result with the found addresses, if any.
func (d *DNSFilter) matchSysHosts(
	host string,
	qtype uint16,
	setts *Settings,
) (res Result, err error) {
	if !setts.ProtectionEnabled {
		return Result{}, nil
	}

	if d.conf.EtcHosts == nil {
		return Result{}, nil
	}

	var ips []netip.Addr
	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		ips = d.conf.EtcHosts.ByName(host)
	default:
		return Result{}, nil
	}

	if len(ips) == 0 {
		return Result{}, nil
	}

	res = Result{
		Reason: RewrittenAutoHosts,
	}
	for _, ip := range ips {
		if (qtype == dns.TypeA && ip.Is4()) || (qtype == dns.TypeAAAA && ip.Is6()) {
			res.IPList = append(res.IPList, ip)
		}
	}

	return res, nil
}
