package hashprefix

import (
	"github.com/AdguardTeam/golibs/errors"
)

// HashPrefix represents a hash prefix for filtering.
type HashPrefix struct {
	Prefix []byte
}

// New creates a new HashPrefix.
func New(prefix []byte) *HashPrefix {
	return &HashPrefix{Prefix: prefix}
}

// Match checks if the hash matches the prefix.
func (hp *HashPrefix) Match(hash []byte) bool {
	return len(hash) >= len(hp.Prefix) && string(hash[:len(hp.Prefix)]) == string(hp.Prefix)
}

// ErrNotFound is returned when a hash prefix is not found.
var ErrNotFound = errors.New("hash prefix not found")
