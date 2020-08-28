// Copyright 2020 The Go-Guardian. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

const (
	agentJWT          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	serviceJWT        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoic3lzdGVtOnNlcnZpY2U6YWNjb3VudCIsImlhdCI6MTUxNjIzOTAyMn0.4pHu9y6vJvtOnLhpz7M3Znnvcdpm7GCiHPCPYzyxps8"
	authenticatedUser = `
	{
		"metadata":{
		   "creationTimestamp":null
		},
		"spec":{
	 
		},
		"status":{
		   "authenticated":true,
		   "user":{
			  "username":"system:serviceaccount:curl_agent",
			  "uid":"1"
		   }
		}
	}
	`
	unauthenticatedUser = `
	{
		"metadata":{
		   "creationTimestamp":null
		},
		"spec":{
	 
		},
		"status":{
		   "authenticated":false,
		}
	}
	`
)

func main() {
	log.Printf("JWT service account For auth startegy: %s \n", serviceJWT)
	log.Printf("JWT service account For curl agent: %s \n", agentJWT)

	router := mux.NewRouter()
	router.HandleFunc("/apis/authentication.k8s.io/v1/tokenreviews", http.HandlerFunc(review)).Methods("POST")
	log.Println("Kube Mock API Server started -> http://127.0.0.1:6443")
	http.ListenAndServe("127.0.0.1:6443", router)
}

func review(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	if strings.Contains(string(body), agentJWT) {
		w.WriteHeader(200)
		w.Write([]byte(authenticatedUser))
		return
	}
	w.WriteHeader(401)
	w.Write([]byte(unauthenticatedUser))
	return
}
