package filtering

import (
	"log/slog"

	"github.com/AdguardTeam/urlfilter/rules"
)

// idGenerator generates unique IDs for filtering-rule lists.
type idGenerator struct {
	// nextID is the next ID to be used.
	nextID uint64
}

// newIDGenerator creates a new idGenerator with the given seed value and
// logger.  l is currently unused but is kept for interface compatibility.
func newIDGenerator(seed uint64, l *slog.Logger) (g *idGenerator) {
	return &idGenerator{
		nextID: seed,
	}
}

// next returns the next unique ID for a new filter list.
func (g *idGenerator) next() (id rules.ListID) {
	next := g.nextID
	g.nextID++

	return rules.ListID(next)
}

// fix ensures that the generator's next ID is greater than all IDs in the
// given filters, so that newly generated IDs don't collide with existing ones.
func (g *idGenerator) fix(filters []FilterYAML) {
	for _, f := range filters {
		id := uint64(f.ID)
		if id >= g.nextID {
			g.nextID = id + 1
		}
	}
}
