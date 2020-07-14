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

func ExampleReplicator() {
	lru := New(20)
	fileSystem := NewFileSystem(context.TODO(), 0, "/tmp")
	replicator := Replicator{
		Persistent: fileSystem,
		InMemory:   lru,
	}

	replicator.Store("key", "value", nil)

	v, _, _ := lru.Load("key", nil)
	fmt.Println(v)

	v, _, _ = fileSystem.Load("key", nil)
	fmt.Println(v)

	// Output:
	// value
	// value
}
