package token

import (
	"context"
	"fmt"
	"net/http"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"

	"github.com/shaj13/go-guardian/v2/auth"
)

func ExampleNewStaticFromFile() {
	strategy, _ := NewStaticFromFile("testdata/valid.csv")
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer testUserToken")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.GetID())
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
	fmt.Println(err, info.GetID())
	// Output:
	// <nil> 1
}

func ExampleNew() {
	authFunc := AuthenticateFunc(func(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
		fmt.Print("authFunc called ")
		if token == "90d64460d14870c08c81352a05dedd3465940a7" {
			return auth.NewDefaultUser("example", "1", nil, nil), nil
		}
		return nil, fmt.Errorf("Invalid user token")
	})

	cache := libcache.LRU.New(0)
	strategy := New(authFunc, cache)

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer 90d64460d14870c08c81352a05dedd3465940a7")

	// first request when authentication decision not cached
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.GetID())

	// second request where authentication decision cached and authFunc will not be called
	info, err = strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.GetID())
	// Output:
	// authFunc called <nil> 1
	// <nil> 1
}

func ExampleNoOpAuthenticate() {
	cache := libcache.LRU.New(0)
	strategy := New(NoOpAuthenticate, cache)

	// user verified and add the user token to strategy using append or cache
	cache.Store("token", auth.NewDefaultUser("example", "1", nil, nil))

	// first request where authentication decision added to cached
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token")
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(err, info.GetID())
	// Output:
	// <nil> 1
}

func ExampleAuthorizationParser() {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token")
	parser := AuthorizationParser("Bearer")
	token, err := parser.Token(r)
	fmt.Println(token, err)
	// Output:
	// token <nil>
}

func ExampleQueryParser() {
	r, _ := http.NewRequest("GET", "/something?api_key=token", nil)
	parser := QueryParser("api_key")
	token, err := parser.Token(r)
	fmt.Println(token, err)
	// Output:
	// token <nil>
}

func ExampleXHeaderParser() {
	header := "X-API-TOKE"
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set(header, "token")
	parser := XHeaderParser(header)
	token, err := parser.Token(r)
	fmt.Println(token, err)
	// Output:
	// token <nil>
}

func ExampleCookieParser() {
	name := "api_key"
	r, _ := http.NewRequest("GET", "/", nil)
	cookie := &http.Cookie{Name: name, Value: "token"}
	r.AddCookie(cookie)
	parser := CookieParser(name)
	token, err := parser.Token(r)
	fmt.Println(token, err)
	// Output:
	// token <nil>
}

func ExampleNewStatic_apikey() {
	r, _ := http.NewRequest("GET", "/something?api_key=token", nil)
	parser := QueryParser("api_key")
	opt := SetParser(parser)
	tokens := map[string]auth.Info{
		"token": auth.NewDefaultUser("example", "1", nil, nil),
	}
	strategy := NewStatic(tokens, opt)
	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info.GetUserName(), err)

	// Output:
	// example <nil>
}

func ExampleNew_apikey() {
	r, _ := http.NewRequest("GET", "/something?api_key=token", nil)
	parser := QueryParser("api_key")
	opt := SetParser(parser)

	authFunc := AuthenticateFunc(func(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
		if token == "token" {
			return auth.NewDefaultUser("example", "1", nil, nil), nil
		}
		return nil, fmt.Errorf("Invalid user token")
	})

	cache := libcache.LRU.New(0)
	strategy := New(authFunc, cache, opt)

	info, err := strategy.Authenticate(r.Context(), r)
	fmt.Println(info.GetUserName(), err)
	// Output:
	// example <nil>
}
