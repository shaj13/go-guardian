package store

import (
	"net/http"
	"sync"

	"github.com/golang/groupcache/lru"
)

// LRU implements a fixed-size thread safe LRU cache.
// It is based on the LRU cache in Groupcache.
type LRU struct {
	Cache *lru.Cache
	MU    *sync.Mutex
}

// Load returns the value stored in the Cache for a key, or nil if no value is present.
// The ok result indicates whether value was found in the Cache.
func (l *LRU) Load(key string, _ *http.Request) (interface{}, bool, error) {
	l.MU.Lock()
	defer l.MU.Unlock()
	v, ok := l.Cache.Get(key)
	return v, ok, nil
}

// Store sets the value for a key.
func (l *LRU) Store(key string, value interface{}, _ *http.Request) error {
	l.MU.Lock()
	defer l.MU.Unlock()
	l.Cache.Add(key, value)
	return nil
}

// Delete the value for a key.
func (l *LRU) Delete(key string, r *http.Request) error {
	l.MU.Lock()
	defer l.MU.Unlock()
	l.Cache.Remove(key)
	return nil
}
