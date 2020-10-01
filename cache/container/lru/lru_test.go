package lru

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/cache"
)

func TestStore(t *testing.T) {
	lru := New()
	lru.Store(1, 1)
	ok := lru.Contains(1)
	assert.True(t, ok)
}

func TestLoad(t *testing.T) {
	lru := New()
	lru.Store("1", 1)
	v, ok := lru.Load("1")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
}

func TestDelete(t *testing.T) {
	lru := New()
	lru.Store(1, 1)
	lru.Delete(1)
	ok := lru.Contains(1)
	assert.False(t, ok)
}

func TestPeek(t *testing.T) {
	lru := New().(*lru)
	lru.c.Capacity = 3

	lru.Store(1, 0)
	lru.Store(2, 0)
	lru.Store(3, 0)
	v, ok := lru.Peek(1)
	lru.Store(4, 0)
	found := lru.Contains(1)

	assert.Equal(t, 0, v)
	assert.True(t, ok)
	assert.False(t, found, "Peek should not move element")
}

func TestContains(t *testing.T) {
	lru := New().(*lru)
	lru.c.Capacity = 3

	lru.Store(1, 0)
	lru.Store(2, 0)
	lru.Store(3, 0)
	found := lru.Contains(1)
	lru.Store(4, 0)
	_, ok := lru.Load(1)

	assert.True(t, found)
	assert.False(t, ok, "Contains should not move element")
}

func TestUpdate(t *testing.T) {
	lru := New().(*lru)
	lru.c.Capacity = 3

	lru.Store(1, 0)
	lru.Store(2, 0)
	lru.Store(3, 0)
	lru.Update(1, 1)
	v, ok := lru.Peek(1)
	lru.Store(4, 0)
	found := lru.Contains(1)

	assert.Equal(t, 1, v)
	assert.True(t, ok)
	assert.False(t, found, "Update should not move element")
}

func TestPurge(t *testing.T) {
	lru := New().(*lru)
	lru.c.Capacity = 3

	lru.Store(1, 0)
	lru.Store(2, 0)
	lru.Store(3, 0)
	lru.Purge()

	assert.Equal(t, 0, lru.Len())
}

func TestResize(t *testing.T) {
	lru := New().(*lru)
	lru.c.Capacity = 3

	lru.Store(1, 0)
	lru.Store(2, 0)
	lru.Store(3, 0)
	lru.Resize(2)

	assert.Equal(t, 2, lru.Len())
	assert.True(t, lru.Contains(2))
	assert.True(t, lru.Contains(3))
	assert.False(t, lru.Contains(1))
}

func TestKeys(t *testing.T) {
	lru := New()

	lru.Store(1, 0)
	lru.Store(2, 0)
	lru.Store(3, 0)

	assert.ElementsMatch(t, []interface{}{1, 2, 3}, lru.Keys())
}

func TestCap(t *testing.T) {
	lru := New().(*lru)
	lru.c.Capacity = 3
	assert.Equal(t, 3, lru.Cap())
}

func TestOnEvicted(t *testing.T) {
	send := make(chan interface{})
	done := make(chan bool)

	evictedKeys := make([]interface{}, 0, 2)

	onEvictedFun := func(key, value interface{}) {
		send <- key
	}

	lru := New().(*lru)
	lru.c.Capacity = 20
	lru.c.OnEvicted = onEvictedFun

	go func() {
		for {
			key := <-send
			evictedKeys = append(evictedKeys, key)
			if len(evictedKeys) >= 2 {
				done <- true
				return
			}
		}
	}()

	for i := 0; i < 22; i++ {
		lru.Store(fmt.Sprintf("myKey%d", i), 1234)
	}

	select {
	case <-done:
	case <-time.After(time.Second * 2):
		t.Fatal("TestOnEvicted timeout exceeded, expected to receive evicted keys")
	}

	assert.ElementsMatch(t, []interface{}{"myKey0", "myKey1"}, evictedKeys)
}

func TestOnExpired(t *testing.T) {
	send := make(chan interface{})
	done := make(chan bool)

	expiredKeys := make([]interface{}, 0, 2)

	onExpiredFun := func(key interface{}) {
		send <- key
	}

	lru := New().(*lru)
	lru.c.OnExpired = onExpiredFun
	lru.c.TTL = time.Millisecond

	go func() {
		for {
			key := <-send
			expiredKeys = append(expiredKeys, key)
			if len(expiredKeys) >= 2 {
				done <- true
				return
			}
		}
	}()

	lru.Store(1, 1234)
	lru.Store(2, 1234)

	select {
	case <-done:
	case <-time.After(time.Second * 2):
		t.Fatal("TestOnExpired timeout exceeded, expected to receive expired keys")
	}

	assert.ElementsMatch(t, []interface{}{1, 2}, expiredKeys)
}

func BenchmarkLRU(b *testing.B) {
	keys := []interface{}{}
	lru := cache.LRU.New()

	for i := 0; i < 100; i++ {
		keys = append(keys, i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key := keys[rand.Intn(100)]
			_, ok := lru.Load(key)
			if ok {
				lru.Delete(key)
			} else {
				lru.Store(key, struct{}{})
			}
		}
	})
}
