package basic

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/golang/groupcache/lru"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/errors"
	"github.com/shaj13/go-guardian/store"
)

func Example() {
	strategy := AuthenticateFunc(exampleAuthFunc)
	authenticator := auth.New()
	authenticator.EnableStrategy(StrategyKey, strategy)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("test", "test")
	user, err := authenticator.Authenticate(req)
	fmt.Println(user.ID(), err)

	req.SetBasicAuth("test", "1234")
	_, err = authenticator.Authenticate(req)
	fmt.Println(err.(errors.MultiError)[1])

	// Output:
	// 10 <nil>
	// Invalid credentials
}

func Example_second() {
	// This example show how to caches the result of basic auth.
	// With LRU cache
	cache := &store.LRU{
		Cache: lru.New(2),
		MU:    &sync.Mutex{},
	}

	strategy := New(exampleAuthFunc, cache)
	authenticator := auth.New()
	authenticator.EnableStrategy(StrategyKey, strategy)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("test", "test")
	user, err := authenticator.Authenticate(req)
	fmt.Println(user.ID(), err)

	req.SetBasicAuth("test", "1234")
	_, err = authenticator.Authenticate(req)
	fmt.Println(err.(errors.MultiError)[1])

	// Output:
	// 10 <nil>
	// basic: Invalid user credentials
}

func exampleAuthFunc(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
	// here connect to db or any other service to fetch user and validate it.
	if userName == "test" && password == "test" {
		return auth.NewDefaultUser("test", "10", nil, nil), nil
	}

	return nil, fmt.Errorf("Invalid credentials")
}
