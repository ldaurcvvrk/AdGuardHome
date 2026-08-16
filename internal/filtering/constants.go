package filtering

import (
	"context"
	"net"

	"github.com/AdguardTeam/urlfilter/rules"
)

// List identifiers for some special-purpose filter lists.  These values must
// not overlap with real filter list IDs.
const (
	// CustomListID is the ID of the custom filtering-rule list.
	CustomListID rules.ListID = 2

	// BlockHostListID is the ID of the block host list.
	BlockHostListID rules.ListID = 0

	// SafeBrowsingListID is the ID of the safebrowsing list.
	SafeBrowsingListID rules.ListID = 1

	// BlockedSvcsListID is the ID of the blocked services list.
	// Use a high value that won't overlap with real filter list IDs (which start from 1).
	BlockedSvcsListID rules.ListID = ^rules.ListID(0)
)

// Constants for filter configuration file.
const (
	// FilterFile is the name of the filtering filter configuration file.
	FilterFile = "filters.json"

	// WhitelistFile is the name of the filtering whitelist configuration file.
	WhitelistFile = "whitelist.json"

	// SafeListFile is the name of the filtering safe list configuration file.
	SafeListFile = "safe.json"

	// ParentalFile is the name of the filtering parental control configuration file.
	ParentalFile = "parental.json"
)

// Resolver is the interface for net.Resolver to simplify testing.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) (ips []net.IP, err error)
}
