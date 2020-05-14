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
	// And it's returned by authenticating functions or by static strategy load token form file.
	ErrInvalidToken = errors.New("bearer: Invalid bearer token")
	// ErrTokenNotFound is returned by authenticating functions for both cached and static bearer strategies when token not found in their store.
	ErrTokenNotFound = errors.New("barer: Token does not exists")
	// ErrInvalidStrategy is returned by Append function when passed strategy does not identified as a bearer strategy type.
	ErrInvalidStrategy = errors.New("bearer: Invalid strategy")
)

type authenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

func (auth authenticateFunc) authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	header := r.Header.Get("Authorization")
	header = strings.TrimSpace(header)

	if header == "" {
		return nil, ErrInvalidToken
	}

	token := strings.Split(header, " ")
	if len(token) < 2 || strings.ToLower(token[0]) != "bearer" {
		return nil, ErrInvalidToken
	}

	if len(token[1]) == 0 {
		return nil, ErrInvalidToken
	}

	return auth(ctx, r, token[1])
}

// Append new token to a bearer strategy store.
// if passed strategy does not identified as a bearer strategy type ErrInvalidStrategy returned,
// Otherwise, nil.
//
// WARNING: Append function does not guarantee concurrent usage safety, It's natively depends on strategy store.
func Append(strat auth.Strategy, token string, info auth.Info) error {
	v, ok := strat.(interface {
		append(token string, info auth.Info) error
	})

	if ok {
		return v.append(token, info)
	}

	return ErrInvalidStrategy
}
