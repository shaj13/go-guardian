package auth

import (
	"context"
	"errors"
	"net/http"
)

// ErrInvalidStrategy is returned by Append/Revoke functions,
// when passed strategy does not implement Append/Revoke.
var ErrInvalidStrategy = errors.New("auth: Invalid strategy")

// Strategy represents an authentication mechanism or method to authenticate users requests.
type Strategy interface {
	// Authenticate users requests and return user information or error.
	Authenticate(ctx context.Context, r *http.Request) (Info, error)
}

// Option configures Strategy using the functional options paradigm popularized by Rob Pike and Dave Cheney.
// If you're unfamiliar with this style,
// see https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html and
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
type Option interface {
	Apply(v interface{})
}

// OptionFunc implements Option interface.
type OptionFunc func(v interface{})

// Apply the configuration to the provided strategy.
func (fn OptionFunc) Apply(v interface{}) {
	fn(v)
}

// Append new Info to a strategy store.
// if passed strategy does not implement Append type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Append function does not guarantee safe concurrency, It's natively depends on strategy store.
func Append(s Strategy, key interface{}, info Info) error {
	u, ok := s.(interface {
		Append(interface{}, Info) error
	})

	if ok {
		return u.Append(key, info)
	}

	return ErrInvalidStrategy
}

// Revoke delete Info from strategy store.
// if passed strategy does not implement Revoke type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Revoke function does not guarantee safe concurrency, It's natively depends on strategy store.
func Revoke(s Strategy, key interface{}) error {
	u, ok := s.(interface {
		Revoke(key interface{}) error
	})

	if ok {
		return u.Revoke(key)
	}

	return ErrInvalidStrategy
}
