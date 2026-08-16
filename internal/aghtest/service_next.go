//go:build next

package aghtest

import (
	"context"

	"github.com/AdguardTeam/AdGuardHome/internal/next/agh"
)

// ServiceWithConfig is a fake [agh.ServiceWithConfig] implementation for tests.
type ServiceWithConfig[ConfigType any] struct {
	OnStart    func() (err error)
	OnShutdown func(ctx context.Context) (err error)
	OnConfig   func() (c ConfigType)
}

// type check
var _ agh.ServiceWithConfig[struct{}] = (*ServiceWithConfig[struct{}])(nil)

// Start implements the [agh.ServiceWithConfig] interface for
// *ServiceWithConfig.
func (s *ServiceWithConfig[_]) Start() (err error) {
	return s.OnStart()
}

// Shutdown implements the [agh.ServiceWithConfig] interface for
// *ServiceWithConfig.
func (s *ServiceWithConfig[_]) Shutdown(ctx context.Context) (err error) {
	return s.OnShutdown(ctx)
}

// Config implements the [agh.ServiceWithConfig] interface for
// *ServiceWithConfig.
func (s *ServiceWithConfig[ConfigType]) Config() (c ConfigType) {
	return s.OnConfig()
}