package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/gorilla/sessions"
)

func ExampleSession() {
	r, _ := http.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	store := sessions.NewCookieStore([]byte("key"))
	sessionCache := &Session{
		Name:   "seesion-key",
		GStore: store,
	}

	sessionCache.Store("key", "value", r)
	SetCookie(w, r)

	v, ok, _ := sessionCache.Load("key", r)
	fmt.Println(v, ok)

	sessionCache.Delete("key", r)
	SetCookie(w, r)

	v, ok, _ = sessionCache.Load("key", r)
	fmt.Println(v, ok)

	// Output:
	// value true
	// <nil> false
}

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

	cache := &LRU{
		Cache: lru.New(2),
		MU:    &sync.Mutex{},
	}

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
