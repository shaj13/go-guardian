// Package bearer provides authentication strategy,
// to authenticate HTTP requests based on the bearer token.
package bearer

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/shaj13/go-passport/auth"
)

var (
	// ErrInvalidToken indicate a hit of an invalid bearer token format.
	// And it's returned by Token function.
	ErrInvalidToken = errors.New("bearer: Invalid bearer token")
	// ErrTokenNotFound is returned by authenticating functions for both cached and static bearer strategies when token not found in their store.
	ErrTokenNotFound = errors.New("barer: Token does not exists")
	// ErrInvalidStrategy is returned by Append function when passed strategy does not identified as a bearer strategy type.
	ErrInvalidStrategy = errors.New("bearer: Invalid strategy")
)

type authenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

func (auth authenticateFunc) authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	token, err := Token(r)
	if err != nil {
		return nil, err
	}
	return auth(ctx, r, token)
}

// Append new token to a bearer strategy store.
// if passed strategy does not identified as a bearer strategy type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Append function does not guarantee safe concurrency, It's natively depends on strategy store.
func Append(strat auth.Strategy, token string, info auth.Info, r *http.Request) error {
	v, ok := strat.(interface {
		append(token string, info auth.Info, r *http.Request) error
	})

	if ok {
		return v.append(token, info, r)
	}

	return ErrInvalidStrategy
}

// Revoke delete token from bearer strategy store.
// if passed strategy does not identified as a bearer strategy type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Revoke function does not guarantee safe concurrency, It's natively depends on strategy store.
func Revoke(strat auth.Strategy, token string, r *http.Request) error {
	v, ok := strat.(interface {
		revoke(token string, r *http.Request) error
	})

	if ok {
		return v.revoke(token, r)
	}

	return ErrInvalidStrategy
}

// Token return bearer token from Authorization header, or ErrInvalidToken,
// The returned token will not contain "Bearer" keyword
func Token(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	header = strings.TrimSpace(header)

	if header == "" {
		return "", ErrInvalidToken
	}

	token := strings.Split(header, " ")
	if len(token) < 2 || strings.ToLower(token[0]) != "bearer" {
		return "", ErrInvalidToken
	}

	if len(token[1]) == 0 {
		return "", ErrInvalidToken
	}

	return token[1], nil
}
