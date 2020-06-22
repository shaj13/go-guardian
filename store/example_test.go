package store

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func ExampleNewFIFO() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, _ := http.NewRequest("GET", "/", nil)
	cache := NewFIFO(ctx, time.Minute*5)

	cache.Store("key", "value", r)

	v, ok, _ := cache.Load("key", r)
	fmt.Println(v, ok)

	cache.Delete("key", r)
	v, ok, _ = cache.Load("key", r)
	fmt.Println(v, ok)

	// Output:
	// value true
	// <nil> false
}

func ExampleLRU() {
	r, _ := http.NewRequest("GET", "/", nil)

	cache := New(2)

	cache.Store("key", "value", r)

	v, ok, _ := cache.Load("key", r)
	fmt.Println(v, ok)

	cache.Delete("key", r)
	v, ok, _ = cache.Load("key", r)
	fmt.Println(v, ok)

	// Output:
	// value true
	// <nil> false
}
