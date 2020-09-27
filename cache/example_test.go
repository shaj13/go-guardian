package cache_test

import (
	"fmt"
	"time"

	"github.com/shaj13/go-guardian/cache"
	"github.com/shaj13/go-guardian/cache/container/fifo"
	_ "github.com/shaj13/go-guardian/cache/container/idle"
	"github.com/shaj13/go-guardian/cache/container/lru"
)

func Example_idle() {
	//  it can be unsafe, no any race conditions
	c := cache.IDLE.NewUnsafe()
	c.Store(1, 0)
	fmt.Println(c.Contains(1))
	// Output:
	// false
}

func Example_fifo() {
	cap := fifo.Capacity(2)
	c := cache.FIFO.New(cap)
	c.Store(1, 0)
	c.Store(2, 0)
	c.Store(3, 0)
	fmt.Println(c.Contains(1))
	// Output:
	// false
}

func Example_lru() {
	cap := lru.Capacity(2)
	c := cache.LRU.New(cap)
	c.Store(1, 0)
	c.Store(2, 0)
	c.Store(3, 0)
	fmt.Println(c.Contains(1))
	// Output:
	// false
}

func Example_onexpired() {
	// c must be thread safe
	var c cache.Cache

	ttl := lru.TTL(time.Millisecond)
	exp := lru.RegisterOnExpired(func(key interface{}) {
		fmt.Println("")
		// use Peek/Load over delete, perhaps a new entry added with the same key during expiration,
		// or entry refreshed from other thread.
		c.Peek(key)
	})

	c = cache.LRU.New(ttl, exp)

	c.Store(1, 0)

	time.Sleep(time.Millisecond * 5)
	fmt.Println(c.Contains(1))
	// Output:
	// false
}
