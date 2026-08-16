package aghslog

import (
	"log/slog"
)

// UpstreamType represents the type of upstream.
type UpstreamType string

const (
	UpstreamTypeMain      UpstreamType = "main"
	UpstreamTypeLocal     UpstreamType = "local"
	UpstreamTypeBootstrap UpstreamType = "bootstrap"
	UpstreamTypeFallback  UpstreamType = "fallback"
	UpstreamTypeService   UpstreamType = "service"
	UpstreamTypeTest      UpstreamType = "test"
)

const PrefixDNSProxy = "dnsproxy"

// NewForUpstream creates a new logger for the given upstream type.
func NewForUpstream(base *slog.Logger, t UpstreamType) *slog.Logger {
	return base.With(slog.String("upstream", string(t)))
}
