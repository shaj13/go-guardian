package auth

import (
	"fmt"
	"net/http"
)

func ExampleAppend() {
	strategy := &mockStrategy{}
	info := NewDefaultUser("1", "2", nil, nil)
	token := "90d64460d14870c08c81352a05dedd3465940a7"
	r, _ := http.NewRequest("POST", "/login", nil)
	// append new token to cached bearer strategy
	err := Append(strategy, token, info, r)
	fmt.Println(err)
	// Output:
	// <nil>
}

func ExampleRevoke() {
	strategy := &mockStrategy{}
	r, _ := http.NewRequest("GET", "/logout", nil)
	// assume token extracted from header
	token := "90d64460d14870c08c81352a05dedd3465940a7"
	err := Revoke(strategy, token, r)
	fmt.Println(err)
	// Output:
	// <nil>
}
