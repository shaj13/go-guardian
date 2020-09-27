package cache

import (
	"strconv"
	"sync"
)

// Container identifies a cache container that implemented in another package.
type Container uint

const (
	// IDLE cache container.
	IDLE Container = iota + 1
	// LRU cache container.
	LRU
	// FIFO cache container.
	FIFO
	max
)

var containers = make([]func(opts ...Option) Cache, max)

// Register registers a function that returns a new instance,
// of the given cache container function.
// This is intended to be called from the init function in packages that implement container functions.
func (c Container) Register(function func(opts ...Option) Cache) {
	if c <= 0 && c >= max { //nolint:staticcheck
		panic("cache: Register of unknown cache container function")
	}

	containers[c] = function
}

// Available reports whether the given cache container is linked into the binary.
func (c Container) Available() bool {
	return c > 0 && c < max && containers[c] != nil
}

// New returns a new thread safe cache.
// New panics if the cache container function is not linked into the binary.
func (c Container) New(opts ...Option) Cache {
	cache := new(cache)
	cache.mu = sync.RWMutex{}
	cache.container = c.NewUnsafe(opts...)
	return cache
}

// NewUnsafe returns a new thread unsafe cache.
// NewUnsafe panics if the cache container function is not linked into the binary.
func (c Container) NewUnsafe(opts ...Option) Cache {
	if !c.Available() {
		panic("cache: Requested cache container function #" + strconv.Itoa(int(c)) + " is unavailable")
	}

	return containers[c](opts...)
}
