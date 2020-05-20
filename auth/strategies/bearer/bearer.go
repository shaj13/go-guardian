// Package bearer provides authentication strategy,
// to authenticate HTTP requests based on the bearer token.
package bearer

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/shaj13/go-guardian/auth"
)

var (
	// ErrInvalidToken indicate a hit of an invalid bearer token format.
	// And it's returned by Token function.
	ErrInvalidToken = errors.New("bearer: Invalid bearer token")
	// ErrTokenNotFound is returned by authenticating functions for bearer strategies,
	// when token not found in their store.
	ErrTokenNotFound = errors.New("barer: Token does not exists")
)

type authenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

func (auth authenticateFunc) authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	token, err := Token(r)
	if err != nil {
		return nil, err
	}
	return auth(ctx, r, token)
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
