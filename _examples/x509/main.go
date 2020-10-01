// Copyright 2020 The Go-Guardian. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shaj13/go-guardian/v2/auth"
	gx509 "github.com/shaj13/go-guardian/v2/auth/strategies/x509"
)

// Usage:
// curl --cacert ./certs/ca --key ./certs/admin-key --cert ./certs/admin  https://127.0.0.1:8080/v1/book/1449311601

var strategy auth.Strategy

func main() {
	setupGoGuardian()
	router := mux.NewRouter()
	router.HandleFunc("/v1/book/{id}", middleware(http.HandlerFunc(getBookAuthor))).Methods("GET")
	log.Println("server started and listening on http://127.0.0.1:8080")
	server := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: router,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
		},
	}
	server.ListenAndServeTLS("./certs/apiserver", "./certs/apiserver-key")
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
	opts := verifyOptions()
	strategy = gx509.New(opts)
}

func middleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth Middleware")
		user, err := strategy.Authenticate(r.Context(), r)
		if err != nil {
			code := http.StatusUnauthorized
			http.Error(w, http.StatusText(code), code)
			return
		}
		log.Printf("User %s Authenticated\n", user.GetUserName())
		next.ServeHTTP(w, r)
	})
}

func verifyOptions() x509.VerifyOptions {

	file := "./certs/ca"
	data, err := ioutil.ReadFile(file)

	if err != nil {
		log.Fatalf("error reading %s: %v", file, err)
	}

	p, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		log.Fatalf("error parseing certificate %s: %v", file, err)
	}

	opts := x509.VerifyOptions{}
	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(cert)
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	return opts
}
