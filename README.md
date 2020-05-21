[![GoDoc](https://godoc.org/github.com/shaj13/go-guardian?status.svg)](https://godoc.org/github.com/shaj13/go-guardian)
[![Go Report Card](https://goreportcard.com/badge/github.com/shaj13/go-guardian)](https://goreportcard.com/report/github.com/shaj13/go-guardian)
[![Coverage Status](https://coveralls.io/repos/github/shaj13/go-guardian/badge.svg?branch=master)](https://coveralls.io/github/shaj13/go-guardian?branch=master)
[![CircleCI](https://circleci.com/gh/shaj13/go-guardian/tree/master.svg?style=svg)](https://circleci.com/gh/shaj13/go-guardian/tree/master)

# Go-Guardian
Go-Guardian is a golang library that provides a simple, clean, and idiomatic way to create powerful modern API and web authentication.

## Overview 
Go-Guardian sole purpose is to authenticate requests, which it does through an extensible set of authentication methods known as strategies.<br>
Go-Guardian does not mount routes or assume any particular database schema, which maximizes flexibility and allows decisions to be made by the developer.<br>
The API is simple: you provide go-guardian a request to authenticate, and go-guardian invoke strategies to authenticate end-user request.<br>
Strategies provide callbacks for controlling what occurs when authentication `should` succeeds or fails.

## Installing 
Using go-guardian is easy. First, use go get to install the latest version of the library.

```sh
go get github.com/shaj13/go-guardian
```
Next, include go-guardian in your application:
```go
import "github.com/shaj13/go-guardian"
```

## Why Go-Guardian?
When building a modern application, you don't want to implement authentication module from scratch;<br>
you want to focus on building awesome software. go-guardian is here to help with that.

Here are a few bullet point reasons you might like to try it out:
* provides simple, clean, and idiomatic API. 
* provides top trends and traditional authentication methods.
* provides a package to caches the authentication decisions, based on different mechanisms and algorithms.
* provides two-factor authentication and one-time password as defined in [RFC-4226](https://tools.ietf.org/html/rfc4226) and [RFC-6238](https://tools.ietf.org/html/rfc6238)
* provides a mechanism to customize strategies, even enables writing a custom strategy

## Example 
```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/shaj13/go-guardian/auth"
	x509Strategy "github.com/shaj13/go-guardian/auth/strategies/x509"
)

var authenticator auth.Authenticator

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

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Handler!!\n"))
}

func main() {
	opts := x509.VerifyOptions{}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	opts.Roots = x509.NewCertPool()
	// Read Root Ca Certificate
	opts.Roots.AddCert(readCertificate("/<your-path>/<ca-name>"))

	// create strategy and bind it to authenticator.
	strategy := x509Strategy.New(opts)
	authenticator = auth.New()
	authenticator.EnableStrategy(x509Strategy.StrategyKey, strategy)

	r := mux.NewRouter()
	r.HandleFunc("/", middleware(http.HandlerFunc(Handler)))
	log.Fatal(http.ListenAndServeTLS(":8080", "<cert>", "<key>", r))
}

func readCertificate(file string) *x509.Certificate {
	data, err := ioutil.ReadFile(file)

	if err != nil {
		log.Fatalf("error reading %s: %v", file, err)
	}

	p, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		log.Fatalf("error parseing certificate %s: %v", file, err)
	}

	return cert
}
```

# Documentation
More examples and API docs are available on [GoDoc](https://pkg.go.dev/github.com/shaj13/go-guardian).

# Contributing

1. Fork it
2. Download your fork to your PC (`git clone https://github.com/your_username/go-guardian && cd go-guardian`)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Make changes and add them (`git add .`)
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to the branch (`git push origin my-new-feature`)
7. Create new pull request

# License
Go-Guardian is released under the MIT license. See [LICENSE](https://github.com/shaj13/go-guardian/blob/master/LICENSE)