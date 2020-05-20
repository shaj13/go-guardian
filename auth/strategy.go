package auth

import (
	"context"
	"errors"
	"net/http"
)

// ErrInvalidStrategy is returned by Append/Revoke function when passed strategy does not implement Append/Revoke.
var ErrInvalidStrategy = errors.New("Invalid strategy")

// StrStrategyKey define a custom type to expose a strategy identifier.
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
func Append(strat Strategy, key string, info Info, r *http.Request) error {
	u, ok := strat.(interface {
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
func Revoke(strat Strategy, key string, r *http.Request) error {
	u, ok := strat.(interface {
		Revoke(key string, r *http.Request) error
	})

	if ok {
		return u.Revoke(key, r)
	}

	return ErrInvalidStrategy
}
