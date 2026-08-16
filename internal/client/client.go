// Package client contains types and logic dealing with AdGuard Home's DNS
// clients.
//
// TODO(a.garipov): Expand.
package client

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// ClientID is a unique identifier for a persistent client used in
// DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC queries.
//
// TODO(s.chzhen):  Use everywhere.
type ClientID string

// ValidateClientID returns an error if id is not a valid ClientID.
//
// TODO(s.chzhen):  Consider implementing [validate.Interface] for ClientID.
func ValidateClientID(id string) (err error) {
	err = netutil.ValidateHostnameLabel(id)
	if err != nil {
		// Replace the domain name label wrapper with our own.
		return fmt.Errorf("invalid clientid %q: %w", id, errors.Unwrap(err))
	}

	return nil
}

// isValidClientID returns false if id is not a valid ClientID.
func isValidClientID(id string) (ok bool) {
	return netutil.IsValidHostnameLabel(id)
}

// CommonUpstreamConfig is the common upstream configuration for clients.
type CommonUpstreamConfig struct {
	Bootstrap               upstream.Resolver
	UpstreamTimeout         time.Duration
	BootstrapPreferIPv6     bool
	EDNSClientSubnetEnabled bool
	UseHTTP3Upstreams       bool
}