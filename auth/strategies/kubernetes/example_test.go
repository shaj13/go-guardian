package kubernetes

import (
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/go-guardian/v2/cache"
	_ "github.com/shaj13/go-guardian/v2/cache/container/idle"
)

func ExampleNew() {
	cache := cache.IDLE.NewUnsafe()
	kube := New(cache)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}

func ExampleGetAuthenticateFunc() {
	cache := cache.IDLE.NewUnsafe()
	fn := GetAuthenticateFunc()
	kube := token.New(fn, cache)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}

func Example() {
	st := SetServiceAccountToken("Service Account Token")
	cache := cache.IDLE.NewUnsafe()
	kube := New(cache, st)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}
