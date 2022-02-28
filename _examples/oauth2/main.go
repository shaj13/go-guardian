// Copyright 2022 The Go-Guardian. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
	"golang.org/x/oauth2"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2/jwt"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

var strategy auth.Strategy
var oauthConfig = &oauth2.Config{
	RedirectURL:  "http://127.0.0.1:8080/v1/auth/grant",
	ClientID:     os.Getenv("CLIENT_ID"),
	ClientSecret: os.Getenv("CLIENT_SECRET"),
	// OpenID Connect (OIDC) scopes are used by an application during authentication
	// To authorize access to a user's details, like name and picture.
	// Each scope returns a set of user attributes, which are called claims.
	// The scopes an application should request depend on which user attributes the application needs.
	// Once the user authorizes the requested scopes, the claims are returned in an ID Token.
	Scopes: []string{"openid"},
	Endpoint: oauth2.Endpoint{
		AuthURL:   "https://accounts.google.com/o/oauth2/auth",
		TokenURL:  "https://oauth2.googleapis.com/token",
		AuthStyle: 0,
	},
}

func main() {
	setupGoGuardian()
	router := mux.NewRouter()
	router.HandleFunc("/v1/book/{id}", middleware(http.HandlerFunc(getBookAuthor))).Methods("GET")
	router.HandleFunc("/v1/auth/login", http.HandlerFunc(oauth2Login)).Methods("GET")
	router.HandleFunc("/v1/auth/grant", http.HandlerFunc(oauth2Grant)).Methods("GET")
	log.Println("server started and listening on http://127.0.0.1:8080")
	http.ListenAndServe("127.0.0.1:8080", router)
}

func oauth2Login(w http.ResponseWriter, r *http.Request) {
	expiration := time.Now().Add(20 * time.Minute)
	buf := make([]byte, 16)
	rand.Read(buf)
	state := base64.URLEncoding.EncodeToString(buf)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)
	url := oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func oauth2Grant(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("oauthstate")
	code := r.FormValue("code")
	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// use code to get token.
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("successful logon; \n"))
	w.Write([]byte("token: \n"))
	w.Write([]byte(token.Extra("id_token").(string)))
	w.Write([]byte("\n Note: use the granted token in url query (?token=);"))
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
	cache := libcache.FIFO.New(0)
	cache.SetTTL(time.Minute * 5)
	cache.RegisterOnExpired(func(key, _ interface{}) {
		cache.Peek(key)
	})
	parser := token.QueryParser("token")
	opt := token.SetParser(parser)
	// Use jwt.SetClaimResolver()
	// To extract additionals user's details.
	strategy = jwt.New("https://www.googleapis.com/oauth2/v3/certs", cache, opt)
}

func middleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth Middleware")
		user, err := strategy.Authenticate(r.Context(), r)
		if err != nil {
			fmt.Println(err)
			code := http.StatusUnauthorized
			http.Error(w, http.StatusText(code), code)
			return
		}
		log.Printf("User %s Authenticated\n", user.GetUserName())
		r = auth.RequestWithUser(user, r)
		next.ServeHTTP(w, r)
	})
}
