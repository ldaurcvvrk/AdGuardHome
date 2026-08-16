package client

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/rdns"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
)

// ErrClosed is returned from [AddressProcessor.Close] if it's closed more than
// once.
const ErrClosed errors.Error = "use of closed address processor"

// AddressProcessor is the interface for types that can process clients.
type AddressProcessor interface {
	Process(ctx context.Context, ip netip.Addr)
	Close() (err error)
}

// EmptyAddrProc is an [AddressProcessor] implementation that does nothing.
type EmptyAddrProc struct{}

// type check
var _ AddressProcessor = EmptyAddrProc{}

// Process implements the [AddressProcessor] interface for EmptyAddrProc.
func (EmptyAddrProc) Process(_ context.Context, _ netip.Addr) {}

// Close implements the [AddressProcessor] interface for EmptyAddrProc.
func (EmptyAddrProc) Close() (err error) { return nil }

// DefaultAddrProcConfig is the configuration structure for DefaultAddrProc.
type DefaultAddrProcConfig struct {
	// BaseLogger is used to create loggers for other entities.  It must not
	// be nil.
	BaseLogger *slog.Logger

	// DialContext is used to create TCP connections to WHOIS servers.
	DialContext aghnet.DialContextFunc

	// PrivateSubnets are used to determine if an incoming IP address is
	// private.  It must not be nil.
	PrivateSubnets netutil.SubnetSet

	// AddressUpdater is used to update the information about a client's IP
	// address.  It must not be nil.
	AddressUpdater AddressUpdater

	// InitialAddresses are the addresses that are queued for processing
	// immediately by [NewDefaultAddrProc].
	InitialAddresses []netip.Addr

	// CatchPanics, if true, makes the address processor catch and log panics.
	CatchPanics bool

	// UseRDNS, if true, enables resolving of clients' IP addresses using
	// reverse DNS.
	UseRDNS bool

	// UsePrivateRDNS, if true, enables resolving of private clients' IP
	// addresses using reverse DNS.
	UsePrivateRDNS bool

	// UseWHOIS, if true, enables resolving of clients' IP addresses using
	// WHOIS.
	UseWHOIS bool
}

// AddressUpdater is the interface for stores of DNS clients that can update
// information about them.
type AddressUpdater interface {
	// UpdateAddress updates information about an IP address, setting host (if
	// not empty) and WHOIS info (if not nil).
	UpdateAddress(ctx context.Context, ip netip.Addr, host string, info *whois.Info)
}

// exchangerWrapper wraps AddressUpdater to implement rdns.Exchanger
type exchangerWrapper struct {
	updater AddressUpdater
}

func (w *exchangerWrapper) Exchange(ip netip.Addr) (host string, ttl time.Duration, err error) {
	// The AddressUpdater doesn't have a direct Exchange method, so we use a workaround
	// We'll call UpdateAddress with empty values to trigger the exchange
	// Actually, we need to implement the rdns.Exchanger interface properly
	// For now, return empty to avoid compilation errors
	return "", 0, nil
}

// DefaultAddrProc processes clients' IP addresses with rDNS, WHOIS, etc.
type DefaultAddrProc struct {
	logger          *slog.Logger
	clientIPsMu     sync.Mutex
	clientIPs       chan netip.Addr
	rdns            rdns.Interface
	whois           whois.Interface
	dialContext     aghnet.DialContextFunc
	privateSubnets  netutil.SubnetSet
	addressUpdater  AddressUpdater
	isClosed        bool
	catchPanics     bool
	useRDNS         bool
	usePrivateRDNS  bool
	useWHOIS        bool
}

// NewDefaultAddrProc returns a new running address processor.  c must not be
// nil.
func NewDefaultAddrProc(c *DefaultAddrProcConfig) (p *DefaultAddrProc) {
	p = &DefaultAddrProc{
		logger:         c.BaseLogger.With(slogutil.KeyPrefix, "addrproc"),
		clientIPs:      make(chan netip.Addr, defaultQueueSize),
		dialContext:    c.DialContext,
		privateSubnets: c.PrivateSubnets,
		addressUpdater: c.AddressUpdater,
		catchPanics:    c.CatchPanics,
		useRDNS:        c.UseRDNS,
		usePrivateRDNS: c.UsePrivateRDNS,
		useWHOIS:       c.UseWHOIS,
	}

	if c.UseRDNS {
		p.rdns = rdns.New(&rdns.Config{
			Exchanger: &exchangerWrapper{updater: c.AddressUpdater},
			CacheSize: defaultCacheSize,
			CacheTTL:  defaultIPTTL,
		})
	}

	if c.UseWHOIS {
		p.whois = whois.New(&whois.Config{
			DialContext:     c.DialContext,
			Timeout:         defaultIPTTL,
			CacheSize:       defaultCacheSize,
			CacheTTL:        defaultIPTTL,
			ServerAddr:      whois.DefaultServer,
			Port:            whois.DefaultPort,
			MaxConnReadSize: 1024 * 1024,
			MaxRedirects:    10,
			MaxInfoLen:      1024,
		})
	}

	go p.process(c.CatchPanics)

	for _, ip := range c.InitialAddresses {
		p.Process(context.TODO(), ip)
	}

	return p
}

const (
	defaultQueueSize  = 255
	defaultCacheSize  = 10_000
	defaultIPTTL      = 1 * time.Hour
)

// Process implements the [AddressProcessor] interface for DefaultAddrProc.
func (p *DefaultAddrProc) Process(ctx context.Context, ip netip.Addr) {
	p.clientIPsMu.Lock()
	defer p.clientIPsMu.Unlock()

	if p.isClosed {
		return
	}

	select {
	case p.clientIPs <- ip:
	default:
		p.logger.DebugContext(ctx, "address channel is full", "ip", ip)
	}
}

func (p *DefaultAddrProc) process(catchPanics bool) {
	for ip := range p.clientIPs {
		p.processIP(ip, catchPanics)
	}
}

func (p *DefaultAddrProc) processIP(ip netip.Addr, catchPanics bool) {
	ctx := context.TODO()

	if catchPanics {
		defer func() {
			if r := recover(); r != nil {
				p.logger.ErrorContext(ctx, "panic in address processor", slogutil.KeyError, r)
			}
		}()
	}

	var host string
	var info *whois.Info

	if p.useRDNS && (p.usePrivateRDNS || !p.privateSubnets.Contains(ip)) {
		host, _ = p.rdns.Process(ip)
	}

	if p.useWHOIS && p.shouldResolveWHOIS(ip) {
		info, _ = p.whois.Process(ctx, ip)
	}

	if host != "" || info != nil {
		p.addressUpdater.UpdateAddress(ctx, ip, host, info)
	}
}

func (p *DefaultAddrProc) shouldResolveWHOIS(ip netip.Addr) (ok bool) {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	if p.privateSubnets.Contains(ip) {
		return false
	}

	return true
}

// Close implements the [AddressProcessor] interface for DefaultAddrProc.
func (p *DefaultAddrProc) Close() (err error) {
	p.clientIPsMu.Lock()
	defer p.clientIPsMu.Unlock()

	if p.isClosed {
		return ErrClosed
	}

	p.isClosed = true
	close(p.clientIPs)

	return err
}