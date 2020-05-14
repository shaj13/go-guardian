package bearer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/shaj13/go-passport/auth"
)

// CachedStrategyKey export identifier for the cached bearer strategy,
// commonly used when enable/add strategy to go-passport authenticator.
const CachedStrategyKey = auth.StrategyKey("Bearer.Cached.Strategy")

// NoOpAuthenticate implements Authenticate function, it return nil, NOOP error,
// commonly used when token refreshed/mangaed directly using cache or Append function,
// and there is no need to parse token and authenticate request.
var NoOpAuthenticate = func(ctx context.Context, r *http.Request, token string) (auth.Info, error) { return nil, NOOP }

// NOOP is the error returned by NoOpAuthenticate to indicate there no op,
// and signal authenticator to unauthenticate the request, See NoOpAuthenticate.
var NOOP = errors.New("NOOP")

// ErrCachedExp returned by cache when cached token have expired,
// and no longer living in cache (deleted)
var ErrCachedExp = errors.New("cache: Cached token have expired")

// Authenticate decalre custom function to authenticate request using token.
// The authenticate function invoked by Authenticate Strategy method when
// The token does not exist in the cahce and the invocation result will be cached, unless an error returned.
// Use NoOpAuthenticate instead to refresh/mangae token directly using cache or Append function.
type Authenticate func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

// Cache stores data so that future requests for that data can be served faster.
type Cache interface {
	// Load returns the auth.Info stored in the cache for a token, or nil if no value is present.
	// The ok result indicates whether value was found in the Cache.
	// The error reserved for moderate cache and returned if an error occurs, Otherwise nil.
	Load(token string, r *http.Request) (auth.Info, bool, error)
	// Store sets the auth.Info for a token. The error reserved for moderate cache and returned if an error occurs, Otherwise nil.
	Store(token string, value auth.Info, r *http.Request) error
}

type record struct {
	exp  int64
	key  string
	info auth.Info
}

type defaultCache struct {
	*sync.Map
	gc  chan<- *record
	ttl time.Duration
}

func (d *defaultCache) Load(key string, _ *http.Request) (auth.Info, bool, error) {
	v, ok := d.Map.Load(key)

	if !ok {
		return nil, ok, nil
	}

	record := v.(*record)

	if record.exp > 0 {
		if time.Now().UnixNano() > record.exp {
			// delete record from cache
			d.Map.Delete(key)
			return nil, ok, ErrCachedExp
		}
	}
	return record.info, ok, nil
}

func (d *defaultCache) Store(key string, value auth.Info, _ *http.Request) error {
	exp := time.Now().Add(d.ttl).UnixNano()
	record := &record{
		key:  key,
		exp:  exp,
		info: value,
	}
	d.Map.Store(key, record)
	d.gc <- record
	return nil
}

type cachedToken struct {
	cache    Cache
	authFunc Authenticate
}

func (c *cachedToken) authenticate(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
	info, ok, err := c.cache.Load(token, r)

	if err != nil {
		return nil, err
	}

	// if token not found invoke user authenticate function
	if !ok {
		info, err = c.authFunc(ctx, r, token)
		if err == nil {
			// cache result
			err = c.cache.Store(token, info, r)
		}
	}

	return info, err
}

func (c *cachedToken) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	return authenticateFunc(c.authenticate).authenticate(ctx, r)
}

func (c *cachedToken) append(token string, info auth.Info) error {
	return c.cache.Store(token, info, nil)
}

type garbageCollector struct {
	queue chan *record
	cache *defaultCache
}

func (gc *garbageCollector) run() {
	for {
		record := <-gc.queue
		_, ok, _ := gc.cache.Load(record.key, nil)

		// check if the token exist then wait until it expired
		if ok {
			t := time.Unix(0, record.exp).Add(time.Second)
			d := time.Until(t)
			<-time.After(d)
		}

		// call Load to expire the token
		_, ok, err := gc.cache.Load(record.key, nil)

		// we should never reach this, but check for unexpectedly cache behaves
		if ok && err != ErrCachedExp {
			str := fmt.Sprintf("Default cache gc:: Got unexpected error: %v, && token exists %v", err, ok)
			panic(str)
		}
	}
}

// NewCachedToken return new auth.Strategy.
// The returned strategy caches the invocation result of authenticate function, See Authenticate.
// Use NoOpAuthenticate to refresh/mangae token directly using cache or Append function, See NoOpAuthenticate.
func NewCachedToken(auth Authenticate, c Cache) auth.Strategy {
	if auth == nil {
		panic("Authenticate Function required and can't be nil")
	}

	if c == nil {
		panic("Cache object required and can't be nil")
	}

	return &cachedToken{
		authFunc: auth,
		cache:    c,
	}
}

// NewDefaultCache return a simple Cache instance safe for concurrent usage,
// And spawning a garbage collector goroutine to collect expired tokens.
// The cache send token to garbage collector through a channel when it stored a new one.
// Once the garbage collector received the token it checks if token expired to wait until expiration,
// Otherwise, wait for the next token.
// Since the cache has the same expiration time for all elements the garbage collector will only wait for the first one,
// And the rest of queued tokens in channel will be collected fastly.
// When the all expired token collected the garbage collector will be blocked until new token stored to repeat the process.
func NewDefaultCache(ttl time.Duration) Cache {
	queue := make(chan *record)

	cache := &defaultCache{
		gc:  queue,
		ttl: time.Second,
		Map: new(sync.Map),
	}

	gc := &garbageCollector{
		queue: queue,
		cache: cache,
	}

	go gc.run()

	return cache
}
