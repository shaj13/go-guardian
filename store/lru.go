package store

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// LRU implements a fixed-size thread safe LRU cache.
// It is based on the LRU cache in Groupcache.
type LRU struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	// OnEvicted optionally specifies a callback function to be
	// executed when an entry is purged from the cache.
	OnEvicted OnEvicted

	// TTL To expire a value in cache.
	// 0 TTL means no expiry policy specified.
	TTL time.Duration

	MU *sync.Mutex

	ll    *list.List
	cache map[string]*list.Element
}

// New creates a new LRU Cache.
// If maxEntries is zero, the cache has no limit and it's assumed
// that eviction is done by the caller.
func New(maxEntries int) *LRU {
	return &LRU{
		MaxEntries: maxEntries,
		ll:         list.New(),
		cache:      make(map[string]*list.Element),
		MU:         new(sync.Mutex),
	}
}

// Store sets the value for a key.
func (l *LRU) Store(key string, value interface{}, _ *http.Request) error {
	l.MU.Lock()
	defer l.MU.Unlock()

	if l.cache == nil {
		l.cache = make(map[string]*list.Element)
		l.ll = list.New()
	}

	if ee, ok := l.cache[key]; ok {
		l.ll.MoveToFront(ee)
		r := ee.Value.(*record)
		r.Value = value
		l.withTTL(r)
		return nil
	}

	r := &record{
		Key:   key,
		Value: value,
	}

	l.withTTL(r)

	ele := l.ll.PushFront(r)
	l.cache[key] = ele

	if l.MaxEntries != 0 && l.ll.Len() > l.MaxEntries {
		l.removeOldest()
	}

	return nil
}

// Update the value for a key without updating the "recently used".
func (l *LRU) Update(key string, value interface{}, _ *http.Request) error {
	l.MU.Lock()
	defer l.MU.Unlock()

	if e, ok := l.cache[key]; ok {
		r := e.Value.(*record)
		r.Value = value
	}

	return nil
}

func (l *LRU) withTTL(r *record) {
	if l.TTL > 0 {
		r.Exp = time.Now().UTC().Add(l.TTL)
	}
}

// Load returns the value stored in the Cache for a key, or nil if no value is present.
// The ok result indicates whether value was found in the Cache.
func (l *LRU) Load(key string, _ *http.Request) (interface{}, bool, error) {
	l.MU.Lock()
	defer l.MU.Unlock()

	if l.cache == nil {
		return nil, false, nil
	}

	if ele, ok := l.cache[key]; ok {
		r := ele.Value.(*record)

		if l.TTL > 0 {
			if time.Now().UTC().After(r.Exp) {
				l.removeElement(ele)
				return nil, ok, ErrCachedExp
			}
		}

		l.ll.MoveToFront(ele)
		return r.Value, ok, nil
	}

	return nil, false, nil
}

// Peek returns the value stored in the Cache for a key
// without updating the "recently used", or nil if no value is present.
// The ok result indicates whether value was found in the Cache.
func (l *LRU) Peek(key string, _ *http.Request) (interface{}, bool, error) {
	if ele, ok := l.cache[key]; ok {
		r := ele.Value.(*record)

		if l.TTL > 0 {
			if time.Now().UTC().After(r.Exp) {
				l.removeElement(ele)
				return nil, ok, ErrCachedExp
			}
		}

		return r.Value, ok, nil
	}

	return nil, false, nil
}

// Delete the value for a key.
func (l *LRU) Delete(key string, _ *http.Request) error {
	l.MU.Lock()
	defer l.MU.Unlock()

	if l.cache == nil {
		return nil
	}

	if ele, hit := l.cache[key]; hit {
		l.removeElement(ele)
	}

	return nil
}

// RemoveOldest removes the oldest item from the cache.
func (l *LRU) RemoveOldest() {
	l.MU.Lock()
	defer l.MU.Unlock()
	l.removeOldest()
}

func (l *LRU) removeOldest() {
	if l.cache == nil {
		return
	}

	if ele := l.ll.Back(); ele != nil {
		l.removeElement(ele)
	}
}

func (l *LRU) removeElement(e *list.Element) {
	l.ll.Remove(e)
	kv := e.Value.(*record)
	delete(l.cache, kv.Key)
	if l.OnEvicted != nil {
		l.OnEvicted(kv.Key, kv.Value)
	}
}

// Len returns the number of items in the cache.
func (l *LRU) Len() int {
	l.MU.Lock()
	defer l.MU.Unlock()

	if l.cache == nil {
		return 0
	}

	return l.ll.Len()
}

// Clear purges all stored items from the cache.
func (l *LRU) Clear() {
	l.MU.Lock()
	defer l.MU.Unlock()

	if l.OnEvicted != nil {
		for _, e := range l.cache {
			kv := e.Value.(*record)
			l.OnEvicted(kv.Key, kv.Value)
		}
	}

	l.ll = nil
	l.cache = nil
}

// Keys return cache records keys.
func (l *LRU) Keys() []string {
	l.MU.Lock()
	defer l.MU.Unlock()
	keys := make([]string, 0)

	for k := range l.cache {
		keys = append(keys, k)
	}

	return keys
}
