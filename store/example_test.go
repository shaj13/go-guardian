package store

import (
	"fmt"
	"net/http"
	"net/http/httptest"

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
