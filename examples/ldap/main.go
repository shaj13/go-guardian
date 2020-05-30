// Copyright 2020 The Go-Guardian. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/ldap"
	"github.com/shaj13/go-guardian/store"
)

// Usage:
// curl  -k http://127.0.0.1:8080/v1/book/1449311601 -u tesla:password

var authenticator auth.Authenticator
var cache store.Cache

func main() {
	setupGoGuardian()
	router := mux.NewRouter()
	router.HandleFunc("/v1/book/{id}", middleware(http.HandlerFunc(getBookAuthor))).Methods("GET")
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

func setupGoGuardian() {
	cfg := &ldap.Config{
		BaseDN:       "dc=example,dc=com",
		BindDN:       "cn=read-only-admin,dc=example,dc=com",
		Port:         "389",
		Host:         "ldap.forumsys.com",
		BindPassword: "password",
		Filter:       "(uid=%s)",
	}
	authenticator = auth.New()
	cache = store.NewFIFO(context.Background(), time.Minute*10)
	strategy := ldap.NewCached(cfg, cache)
	authenticator.EnableStrategy(ldap.StrategyKey, strategy)
}

func middleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth Middleware")
		user, err := authenticator.Authenticate(r)
		if err != nil {
			code := http.StatusUnauthorized
			http.Error(w, http.StatusText(code), code)
			return
		}
		log.Printf("User %s Authenticated\n", user.UserName())
		next.ServeHTTP(w, r)
	})
}
