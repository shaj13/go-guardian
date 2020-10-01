package basic_test

import (
	"context"
	"crypto"
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
	"github.com/shaj13/go-guardian/v2/cache"
	_ "github.com/shaj13/go-guardian/v2/cache/container/lru"
)

func Example() {
	strategy := basic.New(exampleAuthFunc)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("test", "test")
	user, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(user.GetID(), err)

	req.SetBasicAuth("test", "1234")
	_, err = strategy.Authenticate(req.Context(), req)
	fmt.Println(err)

	// Output:
	// 10 <nil>
	// Invalid credentials
}

func Example_second() {
	// This example show how to caches the result of basic auth.
	// With LRU cache
	cache := cache.LRU.New()
	strategy := basic.NewCached(exampleAuthFunc, cache)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("test", "test")
	user, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(user.GetID(), err)

	req.SetBasicAuth("test", "1234")
	_, err = strategy.Authenticate(req.Context(), req)
	fmt.Println(err)

	// Output:
	// 10 <nil>
	// strategies/basic: Invalid user credentials
}

func ExampleSetHash() {
	opt := basic.SetHash(crypto.SHA256) // import _ crypto/sha256
	cache := cache.LRU.New()
	basic.NewCached(exampleAuthFunc, cache, opt)
}

func exampleAuthFunc(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
	// here connect to db or any other service to fetch user and validate it.
	if userName == "test" && password == "test" {
		return auth.NewDefaultUser("test", "10", nil, nil), nil
	}

	return nil, fmt.Errorf("Invalid credentials")
}
