package kubernetes

import (
	"fmt"
	"net/http"

	"github.com/shaj13/go-guardian/auth/strategies/token"
	"github.com/shaj13/go-guardian/store"
)

func ExampleNew() {
	cache := store.New(2)
	kube := New(cache)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}

func ExampleGetAuthenticateFunc() {
	cache := store.New(2)
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
	cache := store.New(2)
	kube := New(cache, st)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}
