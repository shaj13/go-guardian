package store

import (
	"fmt"
	"net/http"
	"testing"
	"time"

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
			cache := New(2)

			cache.Store("test", "test", nil)

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

			v, ok, _ := cache.Load(tt.key, nil)
			assert.NoError(t, err)
			assert.Equal(t, tt.found, ok)
			assert.Equal(t, tt.value, v)

		})
	}

}

func TestTTLLRU(t *testing.T) {
	cache := New(2)
	cache.TTL = time.Nanosecond * 100

	_ = cache.Store("key", "value", nil)

	time.Sleep(time.Nanosecond * 110)

	v, ok, err := cache.Load("key", nil)

	assert.Equal(t, ErrCachedExp, err)
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestLRUEvict(t *testing.T) {
	evictedKeys := make([]string, 0)
	onEvictedFun := func(key string, value interface{}) {
		evictedKeys = append(evictedKeys, key)
	}

	lru := New(20)
	lru.OnEvicted = onEvictedFun

	for i := 0; i < 22; i++ {
		lru.Store(fmt.Sprintf("myKey%d", i), 1234, nil)
	}

	assert.Equal(t, 2, len(evictedKeys))
	assert.Equal(t, 2, len(evictedKeys))
	assert.Equal(t, "myKey0", evictedKeys[0])
	assert.Equal(t, "myKey1", evictedKeys[1])
}

func TestLRULen(t *testing.T) {
	lru := New(1)
	lru.Store("1", 1, nil)

	assert.Equal(t, lru.Len(), 1)

	lru.Clear()
	assert.Equal(t, lru.Len(), 0)
}

func TestLRUClear(t *testing.T) {
	i := 0

	onEvictedFun := func(key string, value interface{}) {
		i++
	}

	lru := New(20)
	lru.OnEvicted = onEvictedFun

	for i := 0; i < 20; i++ {
		lru.Store(fmt.Sprintf("myKey%d", i), 1234, nil)
	}

	lru.Clear()
	assert.Equal(t, 20, i)
}

func TestRemoveOldest(t *testing.T) {
	lru := New(1)
	lru.Store("1", 1, nil)

	assert.Equal(t, lru.Len(), 1)

	lru.RemoveOldest()
	assert.Equal(t, lru.Len(), 0)
}

func TestLRUKeys(t *testing.T) {
	l := New(3)

	l.Store("1", "", nil)
	l.Store("2", "", nil)
	l.Store("3", "", nil)

	assert.ElementsMatch(t, []string{"1", "2", "3"}, l.Keys())
}

func BenchmarkLRU(b *testing.B) {
	cache := New(2)
	benchmarkCache(b, cache)
}
