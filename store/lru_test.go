package store

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/stretchr/testify/assert"
)

func TestLRU(t *testing.T) {
	table := []struct {
		name        string
		key         string
		value       interface{}
		op          string
		expectedErr bool
		found       bool
	}{
		{
			name:  "it return false when key does not exist",
			op:    "load",
			key:   "key",
			found: false,
		},
		{
			name:  "it return true and value when exist",
			op:    "load",
			key:   "test",
			value: "test",
			found: true,
		},
		{
			name:  "it overwrite exist key and value when store",
			op:    "store",
			key:   "test",
			value: "test2",
			found: true,
		},
		{
			name:  "it create new record when store",
			op:    "store",
			key:   "key",
			value: "value",
			found: true,
		},
		{
			name:  "it's not crash when trying to delete a non exist record",
			key:   "key",
			found: false,
		},
		{
			name:  "it delete a exist record",
			op:    "delete",
			key:   "test",
			found: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			cache := &LRU{
				Cache: lru.New(2),
				MU:    &sync.Mutex{},
			}

			cache.Cache.Add("test", "test")

			r, _ := http.NewRequest("GET", "/", nil)
			var err error

			switch tt.op {
			case "load":
				v, ok, err := cache.Load(tt.key, r)
				assert.Equal(t, tt.value, v)
				assert.Equal(t, tt.found, ok)
				assert.NoError(t, err)
				return
			case "store":
				err = cache.Store(tt.key, tt.value, r)
			case "delete":
				err = cache.Delete(tt.key, r)
			}

			v, ok := cache.Cache.Get(tt.key)
			assert.NoError(t, err)
			assert.Equal(t, tt.found, ok)
			assert.Equal(t, tt.value, v)

		})
	}

}

func TestTTLLRU(t *testing.T) {
	cache := &LRU{
		Cache: lru.New(2),
		MU:    &sync.Mutex{},
		TTL:   time.Nanosecond * 100,
	}

	_ = cache.Store("key", "value", nil)

	time.Sleep(time.Nanosecond * 110)

	v, ok, err := cache.Load("key", nil)

	assert.Equal(t, ErrCachedExp, err)
	assert.False(t, ok)
	assert.Nil(t, v)
}
