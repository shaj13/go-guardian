// Package store provides different cache mechanisms and algorithms,
// To caches the authentication decisions.
package store

import (
	"errors"
	"net/http"
	"time"
)

// ErrCachedExp returned by cache when cached record have expired,
// and no longer living in cache (deleted)
var ErrCachedExp = errors.New("cache: Cached record have expired")

// Cache stores data so that future requests for that data can be served faster.
type Cache interface {
	// Load returns the value stored in the cache for a key, or nil if no value is present.
	// The ok result indicates whether value was found in the Cache.
	// The error reserved for moderate cache and returned if an error occurs, Otherwise nil.
	Load(key string, r *http.Request) (interface{}, bool, error)
	// Store sets the value for a key.
	// The error reserved for moderate cache and returned if an error occurs, Otherwise nil.
	Store(key string, value interface{}, r *http.Request) error
	// Delete deletes the value for a key.
	// The error reserved for moderate cache and returned if an error occurs, Otherwise nil.
	Delete(key string, r *http.Request) error

	// Keys return cache records keys.
	Keys() []string
}

// OnEvicted define a function signature to be
// executed when an entry is purged from the cache.
type OnEvicted func(key string, value interface{})

// NoCache is an implementation of Cache interface that never finds/stores a record.
type NoCache struct{}

func (NoCache) Store(_ string, _ interface{}, _ *http.Request) (err error)         { return } // nolint:golint
func (NoCache) Load(_ string, _ *http.Request) (v interface{}, ok bool, err error) { return } // nolint:golint
func (NoCache) Delete(_ string, _ *http.Request) (err error)                       { return } // nolint:golint
func (NoCache) Keys() (keys []string)                                              { return } // nolint:golint

type record struct {
	Exp   time.Time
	Key   string
	Value interface{}
}
