package lru

import (
	"time"

	"github.com/shaj13/go-guardian/v2/cache"
)

// TTL set cache container entries TTL.
func TTL(ttl time.Duration) cache.Option {
	return cache.OptionFunc(func(c cache.Cache) {
		if l, ok := c.(*lru); ok {
			l.c.TTL = ttl
		}
	})
}

// Capacity set cache container capacity.
func Capacity(capacity int) cache.Option {
	return cache.OptionFunc(func(c cache.Cache) {
		if l, ok := c.(*lru); ok {
			l.c.Capacity = capacity
		}
	})
}

// RegisterOnEvicted register OnEvicted callback.
func RegisterOnEvicted(cb cache.OnEvicted) cache.Option {
	return cache.OptionFunc(func(c cache.Cache) {
		if l, ok := c.(*lru); ok {
			l.c.OnEvicted = cb
		}
	})
}

// RegisterOnExpired register OnExpired callback.
func RegisterOnExpired(cb cache.OnExpired) cache.Option {
	return cache.OptionFunc(func(c cache.Cache) {
		if l, ok := c.(*lru); ok {
			l.c.OnExpired = cb
		}
	})
}
