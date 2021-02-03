// Package token provides authentication strategy,
// to authenticate HTTP requests based on token.
package token

import (
	"context"
	"crypto"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
)

var (
	// ErrTokenScopes is returned by token scopes verification when,
	// token scopes do not grant access to the requested resource.
	ErrTokenScopes = errors.New("strategies/token: The access token scopes do not grant access to the requested resource")

	// ErrInvalidToken indicate a hit of an invalid token format.
	// And it's returned by Token Parser.
	ErrInvalidToken = errors.New("strategies/token: Invalid token")

	// ErrTokenNotFound is returned by authenticating functions for token strategies,
	// when token not found in their store.
	ErrTokenNotFound = errors.New("strategies/token: Token does not exists")

	// ErrNOOP is a soft error similar to EOF,
	// returned by NoOpAuthenticate function to indicate there no op,
	// and signal the caller to unauthenticate the request.
	ErrNOOP = errors.New("strategies/token: NOOP")
)

// verify is called on each request after the user authenticated,
// to run additional verification on user toke or info.
type verify func(ctx context.Context, r *http.Request, info auth.Info, token string) error

// Type is Authentication token type or scheme. A common type is Bearer.
type Type string

const (
	// Bearer Authentication token type or scheme.
	Bearer Type = "Bearer"
	// APIKey Authentication token type or scheme.
	APIKey Type = "ApiKey"
)

// SetType sets the authentication token type or scheme,
// used for HTTP WWW-Authenticate header.
//
// Deprecated: No longer used.
func SetType(t Type) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *static:
			v.ttype = t
		case *cachedToken:
			v.typ = t
		}
	})
}

// SetParser sets the strategy token parser.
func SetParser(p Parser) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *static:
			v.parser = p
		case *cachedToken:
			v.parser = p
		}
	})
}

// SetScopes sets the scopes to be used when verifying user access token.
func SetScopes(scopes ...Scope) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *static:
			v.verify = verifyScopes(scopes...)
		case *cachedToken:
			v.verify = verifyScopes(scopes...)
		}
	})
}

// SetHash apply token hashing based on HMAC with h and key,
// To prevent precomputation and length extension attacks,
// and to mitigates hash map DOS attacks via collisions.
func SetHash(h crypto.Hash, key []byte) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *static:
			v.h = internal.NewHMACHasher(h, key)
		case *cachedToken:
			v.h = internal.NewHMACHasher(h, key)
		}
	})
}
