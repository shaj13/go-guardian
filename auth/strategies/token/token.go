package token

import (
	"errors"
	"fmt"

	"github.com/shaj13/go-guardian/auth"
)

var (
	// ErrInvalidToken indicate a hit of an invalid token format.
	// And it's returned by Token Parser.
	ErrInvalidToken = errors.New("strategies/token: Invalid token")
	// ErrTokenNotFound is returned by authenticating functions for token strategies,
	// when token not found in their store.
	ErrTokenNotFound = errors.New("strategies/token: Token does not exists")
)

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
func SetType(t Type) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *Static:
			v.Type = t
		case *cachedToken:
			v.typ = t
		}
	})
}

// SetParser sets the strategy token parser.
func SetParser(p Parser) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		switch v := v.(type) {
		case *Static:
			v.Parser = p
		case *cachedToken:
			v.parser = p
		}
	})
}

func challenge(realm string, t Type) string {
	return fmt.Sprintf(`%s realm="%s", title="%s Token Based Authentication Scheme"`, t, realm, t)
}
