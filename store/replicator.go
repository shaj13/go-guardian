package store

import (
	"net/http"
	"sort"
)

// Replicator holding two caches instances to replicate data between them on load and store data,
// Replicator is typically used to replicate data between in-memory and a persistent caches,
// to obtain data consistency and persistency between runs of a program or scaling purposes.
//
// NOTICE: Replicator cache ignore errors from in-memory cache since all data first stored in Persistent.
type Replicator struct {
	InMemory   Cache
	Persistent Cache
}

// Load returns the value stored in the Cache for a key, or nil if no value is present.
// The ok result indicates whether value was found in the Cache.
// When any error occurs fallback to persistent cache.
func (r *Replicator) Load(key string, req *http.Request) (interface{}, bool, error) {
	v, ok, err := r.InMemory.Load(key, req)

	if err != nil {
		ok = false
	}

	if !ok {

		v, ok, err = r.Persistent.Load(key, req)

		if ok {
			_ = r.InMemory.Store(key, v, req)
		}
	}

	return v, ok, err
}

// Store sets the value for a key.
func (r *Replicator) Store(key string, value interface{}, req *http.Request) error {
	err := r.Persistent.Store(key, value, req)

	if err != nil {
		return err
	}

	_ = r.InMemory.Store(key, value, req)
	return nil
}

// Delete the value for a key.
func (r *Replicator) Delete(key string, req *http.Request) error {
	if err := r.Persistent.Delete(key, req); err != nil {
		return err
	}

	_ = r.InMemory.Delete(key, req)
	return nil
}

// Keys return cache records keys.
func (r *Replicator) Keys() []string {
	return r.Persistent.Keys()
}

// IsSynced return true/false if two cached keys are equal.
func (r *Replicator) IsSynced() bool {
	mk := r.InMemory.Keys()
	pk := r.Persistent.Keys()

	if len(mk) != len(pk) {
		return false
	}

	sort.Strings(mk)
	sort.Strings(pk)

	for i, v := range mk {
		if v != pk[i] {
			return false
		}
	}

	return true
}

// Sync two caches by reload all persistent cache records into in-memory cache.
func (r *Replicator) Sync() error {

	if r.IsSynced() {
		return nil
	}

	for _, k := range r.Persistent.Keys() {
		_, _, err := r.Load(k, nil)
		if err != nil {
			return err
		}
	}

	return nil
}
