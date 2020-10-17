package token

import (
	"context"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
)

// AuthenticateFunc declare function signature to authenticate request using token.
// Any function that has the appropriate signature can be registered to the token strategy.
// AuthenticateFunc must return authenticated user info and token expiry time, otherwise error.
type AuthenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, time.Time, error)

// New return new token strategy that caches the invocation result of authenticate function.
func New(auth AuthenticateFunc, c auth.Cache, opts ...auth.Option) auth.Strategy {
	cached := &cachedToken{
		authFunc: auth,
		cache:    c,
		typ:      Bearer,
		parser:   AuthorizationParser(string(Bearer)),
	}

	for _, opt := range opts {
		opt.Apply(cached)
	}

	return cached
}

type cachedToken struct {
	parser   Parser
	typ      Type
	cache    auth.Cache
	authFunc AuthenticateFunc
}

func (c *cachedToken) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	token, err := c.parser.Token(r)
	if err != nil {
		return nil, err
	}

	info, ok := c.cache.Load(token)

	// if token not found invoke user authenticate function
	if !ok {
		var t time.Time
		info, t, err = c.authFunc(ctx, r, token)
		if err != nil {
			return nil, err
		}
		c.cache.StoreWithTTL(token, info, time.Until(t))
	}

	if _, ok := info.(auth.Info); !ok {
		return nil, auth.NewTypeError("strategies/token:", (*auth.Info)(nil), info)
	}

	return info.(auth.Info), nil
}

func (c *cachedToken) Append(token interface{}, info auth.Info) error {
	c.cache.Store(token, info)
	return nil
}

func (c *cachedToken) Revoke(token interface{}) error {
	c.cache.Delete(token)
	return nil
}

// NoOpAuthenticate implements AuthenticateFunc, it return nil, time.Time{}, ErrNOOP,
// commonly used when token refreshed/mangaed directly using cache or Append function,
// and there is no need to parse token and authenticate request.
func NoOpAuthenticate(ctx context.Context, r *http.Request, token string) (auth.Info, time.Time, error) {
	return nil, time.Time{}, ErrNOOP
}
