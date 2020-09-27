// Package cache provides in-memory caches based on different caches replacement algorithms.
package cache

import (
	"sync"
)

// Cache stores data so that future requests for that data can be served faster.
type Cache interface {
	// Load returns key's value.
	Load(key interface{}) (interface{}, bool)
	// Peek returns key's value without updating the underlying "rank".
	Peek(key interface{}) (interface{}, bool)
	// Update the key value without updating the underlying "rank".
	Update(key interface{}, value interface{})
	// Store sets the value for a key.
	Store(key interface{}, value interface{})
	// Delete deletes the key value.
	Delete(key interface{})
	// Keys return cache records keys.
	Keys() []interface{}
	// Contains Checks if a key exists in cache.
	Contains(key interface{}) bool
	// Purge Clears all cache entries.
	Purge()
	// Resize cache, returning number evicted
	Resize(int) int
	// Len Returns the number of items in the cache.
	Len() int
	// Cap Returns the cache capacity.
	Cap() int
}

// OnEvicted define a function signature to be
// executed in its own goroutine when an entry is purged from the cache.
type OnEvicted func(key interface{}, value interface{})

// OnExpired define a function signature to be
// executed in its own goroutine when an entry TTL elapsed.
// invocation of OnExpired, does not mean the entry is purged from the cache,
// if need be, it must coordinate with the cache explicitly.
//
// 	var cache cache.Cache
// 	onExpired := func(key interface{}) {
//	 	_, _, _ = cache.Peek(key)
// 	}
//
// This should not be done unless the cache thread-safe.
type OnExpired func(key interface{})

type cache struct {
	mu        sync.RWMutex
	container Cache
}

func (c *cache) Load(key interface{}) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.container.Load(key)
}

func (c *cache) Peek(key interface{}) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.container.Peek(key)
}

func (c *cache) Update(key interface{}, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.container.Update(key, value)
}

func (c *cache) Store(key interface{}, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.container.Store(key, value)
}

func (c *cache) Delete(key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.container.Delete(key)
}

func (c *cache) Keys() []interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.container.Keys()
}

func (c *cache) Contains(key interface{}) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.container.Contains(key)
}

func (c *cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.container.Purge()
}

func (c *cache) Resize(s int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.container.Resize(s)
}

func (c *cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.container.Len()
}

func (c *cache) Cap() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.container.Cap()
}
