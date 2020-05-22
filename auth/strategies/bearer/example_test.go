package bearer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/store"
)

func ExampleToken() {
	r, _ := http.NewRequest("GET", "/logout", nil)
	r.Header.Set("Authorization", "Bearer 90d64460d14870c08c81352a05dedd3465940a7")
	token, err := Token(r)
	fmt.Println(err, token)

	r.Header.Set("Authorization", "90d64460d14870c08c81352a05dedd3465940a7")
	token, err = Token(r)
	fmt.Println(err, token)

	// Output:
	// <nil> 90d64460d14870c08c81352a05dedd3465940a7
	// bearer: Invalid bearer token
}

func ExampleNewStaticFromFile() {
	strategy, _ := NewStaticFromFile("testdata/valid.csv")
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer testUserToken")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.ID())
	// Output:
	// <nil> 1
}

func ExampleNewStatic() {
	strategy := NewStatic(map[string]auth.Info{
		"90d64460d14870c08c81352a05dedd3465940a7": auth.NewDefaultUser("example", "1", nil, nil),
	})
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer 90d64460d14870c08c81352a05dedd3465940a7")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.ID())
	// Output:
	// <nil> 1
}

func ExampleNewCachedToken() {
	authFunc := Authenticate(func(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
		fmt.Print("authFunc called ")
		if token == "90d64460d14870c08c81352a05dedd3465940a7" {
			return auth.NewDefaultUser("example", "1", nil, nil), nil
		}
		return nil, fmt.Errorf("Invalid user token")
	})

	cache := store.NewFIFO(time.Minute * 5)
	strategy := NewCachedToken(authFunc, cache)

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer 90d64460d14870c08c81352a05dedd3465940a7")

	// first request when authentication decision not cached
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.ID())

	// second request where authentication decision cached and authFunc will not be called
	info, err = strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.ID())
	// Output:
	// authFunc called <nil> 1
	// <nil> 1
}

func ExampleNoOpAuthenticate() {
	cache := store.NewFIFO(time.Microsecond * 500)
	strategy := NewCachedToken(NoOpAuthenticate, cache)

	// demonstrate a user attempt to login
	r, _ := http.NewRequest("GET", "/login", nil)
	// user verified and add the user token to strategy using append or cache
	cache.Store("token", auth.NewDefaultUser("example", "1", nil, nil), r)

	// first request where authentication decision added to cached
	r, _ = http.NewRequest("GET", "/login", nil)
	r.Header.Set("Authorization", "Bearer token")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.ID())

	// second request where authentication decision expired and user must login again
	time.Sleep(time.Second)
	info, err = strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info)
	// Output:
	// <nil> 1
	// NOOP <nil>
}
