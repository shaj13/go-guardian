package auth

import (
	"context"
	"errors"
	"net/http"
)

// ErrInvalidStrategy is returned by Append/Revoke functions,
// when passed strategy does not implement Append/Revoke.
var ErrInvalidStrategy = errors.New("Invalid strategy")

// StrategyKey define a custom type to expose a strategy identifier.
type StrategyKey string

// Strategy represents an authentication mechanism or method to authenticate users requests.
type Strategy interface {
	// Authenticate users requests and return user information or error.
	Authenticate(ctx context.Context, r *http.Request) (Info, error)
}

// Append new Info to a strategy store.
// if passed strategy does not implement Append type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Append function does not guarantee safe concurrency, It's natively depends on strategy store.
func Append(s Strategy, key string, info Info, r *http.Request) error {
	u, ok := s.(interface {
		Append(key string, info Info, r *http.Request) error
	})

	if ok {
		return u.Append(key, info, r)
	}

	return ErrInvalidStrategy
}

// Revoke delete Info from strategy store.
// if passed strategy does not implement Revoke type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Revoke function does not guarantee safe concurrency, It's natively depends on strategy store.
func Revoke(s Strategy, key string, r *http.Request) error {
	u, ok := s.(interface {
		Revoke(key string, r *http.Request) error
	})

	if ok {
		return u.Revoke(key, r)
	}

	return ErrInvalidStrategy
}

// SetWWWAuthenticate adds a HTTP WWW-Authenticate header to the provided ResponseWriter's headers.
// by consolidating the result of calling Challenge methods on provided strategies.
// if strategy contains an Challenge method call it.
// Otherwise, strategy ignored.
func SetWWWAuthenticate(w http.ResponseWriter, realm string, strategies ...Strategy) {
	str := ""

	if len(strategies) == 0 {
		return
	}

	for _, s := range strategies {
		u, ok := s.(interface {
			Challenge(string) string
		})

		if ok {
			str = str + u.Challenge(realm) + ", "
		}
	}

	if len(str) == 0 {
		return
	}

	// remove ", "
	str = str[0 : len(str)-2]

	w.Header().Set("WWW-Authenticate", str)
}
