// Copyright 2020 The Go-Guardian. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
	_ "github.com/shaj13/libcache/idle"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
	"github.com/shaj13/go-guardian/v2/auth/strategies/opaque"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/go-guardian/v2/auth/strategies/union"
)

// Usage:
// curl  -k http://127.0.0.1:8080/v1/book/1449311601 -u admin:admin
// curl  -k http://127.0.0.1:8080/v1/auth/token -u admin:admin <obtain a token>
// curl  -k http://127.0.0.1:8080/v1/auth/token -H "Authorization: Bearer <refresh token>"
// curl  -k http://127.0.0.1:8080/v1/book/1449311601 -H "Authorization: Bearer <token>"

func main() {
	a := newAuthenticator()
	router := mux.NewRouter()
	router.HandleFunc("/v1/auth/token", a.middleware(http.HandlerFunc(a.createToken))).Methods("GET")
	router.HandleFunc("/v1/book/{id}", a.middleware(http.HandlerFunc(getBookAuthor))).Methods("GET")
	log.Println("server started and listening on http://127.0.0.1:8080")
	http.ListenAndServe("127.0.0.1:8080", router)
}

func getBookAuthor(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	books := map[string]string{
		"1449311601": "Ryan Boyd",
		"148425094X": "Yvonne Wilson",
		"1484220498": "Prabath Siriwarden",
	}
	body := fmt.Sprintf("Author: %s \n", books[id])
	w.Write([]byte(body))
}

func newAuthenticator() *authenticator {
	cache := libcache.FIFO.New(0)
	db := &db{m: make(map[string]opaque.Token)}
	secret := opaque.StaticSecret([]byte("secret"))

	refreshScope := token.NewScope("refresh", "/v1/auth/token", "GET")
	refreshOpts := []auth.Option{
		opaque.WithExpDuration(time.Hour * 30 * 24),
		opaque.WithTokenPrefix("r"),
		token.SetScopes(refreshScope),
	}

	basicStrategy := basic.NewCached(validateUser, cache)
	accessStrategy := opaque.New(cache, db, secret)
	// Use IDLE to prevent caching one time refresh token.
	refreshStrategy := opaque.New(libcache.IDLE.New(0), db, secret, refreshOpts...)
	union := union.New(accessStrategy, refreshStrategy, basicStrategy)

	return &authenticator{
		union:   union,
		refresh: refreshOpts,
		secret:  secret,
		store:   db,
	}
}

func validateUser(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
	// here connect to db or any other service to fetch user and validate it.
	if userName == "admin" && password == "admin" {
		return auth.NewDefaultUser("admin", "1", nil, nil), nil
	}

	return nil, fmt.Errorf("Invalid credentials")
}

type authenticator struct {
	union   union.Union
	secret  opaque.SecretsKeeper
	store   opaque.TokenStore
	access  []auth.Option
	refresh []auth.Option
}

func (a *authenticator) createToken(w http.ResponseWriter, r *http.Request) {
	user := auth.User(r)
	token.WithNamedScopes(user, "refresh") // limit refresh token usage See newAuthenticator.

	accessToken, err := opaque.IssueToken(r.Context(), user, a.store, a.secret, a.access...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	refreshToken, err := opaque.IssueToken(r.Context(), user, a.store, a.secret, a.refresh...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	resp := struct {
		AccessToken  string
		RefreshToken string
	}{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	buf, _ := json.Marshal(resp)
	w.Write(buf)
}

func (a *authenticator) middleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth Middleware")
		_, user, err := a.union.AuthenticateRequest(r)
		if err != nil {
			log.Println(err)
			code := http.StatusUnauthorized
			http.Error(w, http.StatusText(code), code)
			return
		}
		log.Printf("User %s Authenticated\n", user.GetUserName())
		r = auth.RequestWithUser(user, r)
		next.ServeHTTP(w, r)
	})
}

type db struct {
	mu sync.Mutex
	m  map[string]opaque.Token
}

func (db db) Store(_ context.Context, t opaque.Token) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.m[t.Signature] = t
	return nil
}

func (db db) Lookup(_ context.Context, sig string) (opaque.Token, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	t, ok := db.m[sig]

	if !ok {
		return opaque.Token{}, errors.New("db: token not found")
	}

	if t.Prefix == "r" {
		// Refresh token is one time password so remove it
		// To prevent user use it again.
		delete(db.m, sig)
	}

	return t, nil
}

func (db db) Revoke(ctx context.Context, sig string) error {
	return errors.New("revoke not implemented")
}
