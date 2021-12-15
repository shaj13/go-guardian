// Package token provides authentication strategy,
// to authenticate HTTP requests based on token.
package token

import (
	"context"
	"errors"
	"net/http"

	"github.com/m87carlson/go-guardian/v2/auth"
	"github.com/m87carlson/go-guardian/v2/auth/internal"
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

// strategy represents the underlying token strategy.
type strategy interface {
	authenticate(context.Context, *http.Request, string, string) (auth.Info, error)
	append(string, auth.Info) error
	revoke(string) error
}

type core struct {
	parser   Parser
	strategy strategy
	hasher   internal.Hasher
	verify   verify
}

func (c *core) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	token, err := c.parser.Token(r)
	if err != nil {
		return nil, err
	}

	hash := c.hasher.Hash(token)
	info, err := c.strategy.authenticate(ctx, r, token, hash)
	if err != nil {
		return nil, err
	}

	if err := c.verify(ctx, r, info, token); err != nil {
		return nil, err
	}

	return info, nil
}

func (c *core) Append(token interface{}, info auth.Info) error {
	if str, ok := token.(string); ok {
		hash := c.hasher.Hash(str)
		return c.strategy.append(hash, info)
	}
	return auth.NewTypeError("strategies/token:", "str", token)
}

func (c *core) Revoke(token interface{}) error {
	if str, ok := token.(string); ok {
		hash := c.hasher.Hash(str)
		return c.strategy.revoke(hash)
	}
	return auth.NewTypeError("strategies/token:", "str", token)
}

func newCore(s strategy, opts ...auth.Option) *core {
	c := new(core)
	c.strategy = s
	c.hasher = internal.PlainTextHasher{}
	c.parser = AuthorizationParser(string(Bearer))
	c.verify = func(_ context.Context, _ *http.Request, _ auth.Info, _ string) error {
		return nil
	}

	for _, opt := range opts {
		opt.Apply(c)
	}

	return c
}
