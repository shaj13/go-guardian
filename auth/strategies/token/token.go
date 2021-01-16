// Package token provides authentication strategy,
// to authenticate HTTP requests based on token.
package token

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
)

var (
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

// Verify is called on each request after the user authenticated to verify the user token,
// grants access to the requested resource/endpoint.
// Verify isn't for authorization and it's should be only used to limit the access token.
type Verify func(ctx context.Context, r *http.Request, info auth.Info, token string) error

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

// SetVerify sets the strategy token verify.
func SetVerify(ver Verify) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *static:
			v.verify = ver
		case *cachedToken:
			v.verify = ver
		}
	})
}
