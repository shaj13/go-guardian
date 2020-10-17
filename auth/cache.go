package auth

import "time"

// Cache type describes the requirements for authentication strategies,
// that cache the authentication decisions.
type Cache interface {
	// Load returns key value.
	Load(key interface{}) (interface{}, bool)
	// Store sets the key value.
	Store(key interface{}, value interface{})
	// StoreWithTTL sets the key value with TTL overrides the default.
	StoreWithTTL(key interface{}, value interface{}, ttl time.Duration)
	// Delete deletes the key value.
	Delete(key interface{})
}
