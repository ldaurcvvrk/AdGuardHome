package home

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/arpdb"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/safesearch"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/AdGuardHome/internal/stats"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// clientsContainer is the storage of all runtime and persistent clients.
type clientsContainer struct {
	// baseLogger is used to create loggers with custom prefixes for sources of
	// information about clients.  It must not be nil.
	baseLogger *slog.Logger

	// logger is used for logging the operation of the clients container.  It
	// must not be nil.
	logger *slog.Logger

	// storage stores information about persistent clients.
	storage *client.Index

	// clientChecker checks if a client is blocked by the current access
	// settings.
	clientChecker BlockedClientChecker

	// confModifier is used to update the global configuration.  It must not
	// be nil.
	confModifier agh.ConfigModifier

	// httpReg registers HTTP handlers.  It must not be nil.
	httpReg aghhttp.Registrar

	// lock protects all fields.
	lock sync.Mutex

	// safeSearchCacheSize is the size of the safe search cache to use for
	// persistent clients.
	safeSearchCacheSize uint

	// safeSearchCacheTTL is the TTL of the safe search cache to use for
	// persistent clients.
	safeSearchCacheTTL time.Duration
}

// BlockedClientChecker checks if a client is blocked by the current access
// settings.
type BlockedClientChecker interface {
	// IsBlockedClient returns true if the client is blocked by the current
	// access settings.
	IsBlockedClient(ip netip.Addr, clientID string) (blocked bool, rule string)
}

// Init initializes the clients container.  All arguments must not be nil
// except for objects.
func (clients *clientsContainer) Init(
	ctx context.Context,
	baseLogger *slog.Logger,
	objects []*client.Persistent,
	dhcpServer client.DHCP,
	etcHosts *aghnet.HostsContainer,
	arpDB arpdb.Interface,
	filteringConf *filtering.Config,
	confModifier agh.ConfigModifier,
	httpReg aghhttp.Registrar,
) (err error) {
	if clients.storage != nil {
		return errors.Error("clients container already initialized")
	}

	clients.baseLogger = baseLogger.With(slogutil.KeyPrefix, "clients")
	clients.logger = clients.baseLogger.With(slogutil.KeyPrefix, "container")
	clients.confModifier = confModifier
	clients.httpReg = httpReg

	clients.storage = client.NewIndex()

	for _, obj := range objects {
		clients.storage.Add(obj)
	}

	// TODO(s.chzhen):  Use empty interface.
	clients.clientChecker = &blockedClientChecker{
		clients: clients,
	}

	// Initialize the address processor.
	addrProcConf := &client.DefaultAddrProcConfig{
		BaseLogger:      baseLogger.With(slogutil.KeyPrefix, "addrproc"),
		DialContext:     aghnet.DialContextFunc(netutil.DialContext),
		PrivateSubnets:  netutil.SubnetSet{},
		AddressUpdater:  clients,
		UsePrivateRDNS:  false,
		UseRDNS:         false,
		UseWHOIS:        false,
	}

	// TODO(s.chzhen):  Use the actual configuration.
	// clients.addrProc = client.NewDefaultAddrProc(addrProcConf)

	return nil
}

// UpdateAddress updates information about an IP address, setting host (if
// not empty) and WHOIS info (if not nil).
func (clients *clientsContainer) UpdateAddress(ctx context.Context, ip netip.Addr, host string, info *whois.Info) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	// Find or create the client.
	// ...
}

// IsBlockedClient returns true if the client is blocked by the current
// access settings.
func (clients *clientsContainer) IsBlockedClient(ip netip.Addr, clientID string) (blocked bool, rule string) {
	return clients.clientChecker.IsBlockedClient(ip, clientID)
}

// blockedClientChecker implements BlockedClientChecker.
type blockedClientChecker struct {
	clients *clientsContainer
}

func (b *blockedClientChecker) IsBlockedClient(ip netip.Addr, clientID string) (blocked bool, rule string) {
	// Delegate to the dnsforward server's access manager.
	// This is a placeholder implementation.
	return false, ""
}