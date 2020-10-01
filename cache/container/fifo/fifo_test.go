package fifo

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/shaj13/go-guardian/v2/cache"
)

func TestStore(t *testing.T) {
	fifo := New()
	fifo.Store(1, 1)
	ok := fifo.Contains(1)
	assert.True(t, ok)
}

func TestLoad(t *testing.T) {
	fifo := New()
	fifo.Store("1", 1)
	v, ok := fifo.Load("1")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
}

func TestDelete(t *testing.T) {
	fifo := New()
	fifo.Store(1, 1)
	fifo.Delete(1)
	ok := fifo.Contains(1)
	assert.False(t, ok)
}

func TestPeek(t *testing.T) {
	fifo := New().(*fifo)
	fifo.c.Capacity = 3

	fifo.Store(1, 0)
	fifo.Store(2, 0)
	fifo.Store(3, 0)
	v, ok := fifo.Peek(1)
	fifo.Store(4, 0)
	found := fifo.Contains(1)

	assert.Equal(t, 0, v)
	assert.True(t, ok)
	assert.False(t, found, "Peek should not move element")
}

func TestContains(t *testing.T) {
	fifo := New().(*fifo)
	fifo.c.Capacity = 3

	fifo.Store(1, 0)
	fifo.Store(2, 0)
	fifo.Store(3, 0)
	found := fifo.Contains(1)
	fifo.Store(4, 0)
	_, ok := fifo.Load(1)

	assert.True(t, found)
	assert.False(t, ok, "Contains should not move element")
}

func TestUpdate(t *testing.T) {
	fifo := New().(*fifo)
	fifo.c.Capacity = 3

	fifo.Store(1, 0)
	fifo.Store(2, 0)
	fifo.Store(3, 0)
	fifo.Update(1, 1)
	v, ok := fifo.Peek(1)
	fifo.Store(4, 0)
	found := fifo.Contains(1)

	assert.Equal(t, 1, v)
	assert.True(t, ok)
	assert.False(t, found, "Update should not move element")
}

func TestPurge(t *testing.T) {
	fifo := New().(*fifo)
	fifo.c.Capacity = 3

	fifo.Store(1, 0)
	fifo.Store(2, 0)
	fifo.Store(3, 0)
	fifo.Purge()

	assert.Equal(t, 0, fifo.Len())
}

func TestResize(t *testing.T) {
	fifo := New().(*fifo)
	fifo.c.Capacity = 3

	fifo.Store(1, 0)
	fifo.Store(2, 0)
	fifo.Store(3, 0)
	fifo.Resize(2)

	assert.Equal(t, 2, fifo.Len())
	assert.True(t, fifo.Contains(2))
	assert.True(t, fifo.Contains(3))
	assert.False(t, fifo.Contains(1))
}

func TestKeys(t *testing.T) {
	fifo := New()

	fifo.Store(1, 0)
	fifo.Store(2, 0)
	fifo.Store(3, 0)

	assert.ElementsMatch(t, []interface{}{1, 2, 3}, fifo.Keys())
}

func TestCap(t *testing.T) {
	fifo := New().(*fifo)
	fifo.c.Capacity = 3
	assert.Equal(t, 3, fifo.Cap())
}

func TestOnEvicted(t *testing.T) {
	send := make(chan interface{})
	done := make(chan bool)

	evictedKeys := make([]interface{}, 0, 2)

	onEvictedFun := func(key, value interface{}) {
		send <- key
	}

	fifo := New().(*fifo)
	fifo.c.Capacity = 20
	fifo.c.OnEvicted = onEvictedFun

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
		fifo.Store(fmt.Sprintf("myKey%d", i), 1234)
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

	fifo := New().(*fifo)
	fifo.c.OnExpired = onExpiredFun
	fifo.c.TTL = time.Millisecond

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

	fifo.Store(1, 1234)
	fifo.Store(2, 1234)

	select {
	case <-done:
	case <-time.After(time.Second * 2):
		t.Fatal("TestOnExpired timeout exceeded, expected to receive expired keys")
	}

	assert.ElementsMatch(t, []interface{}{1, 2}, expiredKeys)
}

func BenchmarkFIFO(b *testing.B) {
	keys := []interface{}{}
	fifo := cache.FIFO.New()

	for i := 0; i < 100; i++ {
		keys = append(keys, i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key := keys[rand.Intn(100)]
			_, ok := fifo.Load(key)
			if ok {
				fifo.Delete(key)
			} else {
				fifo.Store(key, struct{}{})
			}
		}
	})
}
