package token

import (
	"context"
	"net/http"

	"github.com/shaj13/go-guardian/auth"
)

// AuthenticateFunc declare custom function to authenticate request using token.
// The authenticate function invoked by Authenticate Strategy method when
// The token does not exist in the cahce and the invocation result will be cached, unless an error returned.
// Use NoOpAuthenticate instead to refresh/mangae token directly using cache or Append function.
type AuthenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

// New return new auth.Strategy.
// The returned strategy, caches the invocation result of authenticate function, See AuthenticateFunc.
// Use NoOpAuthenticate to refresh/mangae token directly using cache or Append function, See NoOpAuthenticate.
func New(auth AuthenticateFunc, c auth.Cache, opts ...auth.Option) auth.Strategy {
	if auth == nil {
		panic("strategies/token: Authenticate Function required and can't be nil")
	}

	if c == nil {
		panic("strategies/token: Cache object required and can't be nil")
	}

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
		info, err = c.authFunc(ctx, r, token)
		if err != nil {
			return nil, err
		}
		c.cache.Store(token, info)
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

// NoOpAuthenticate implements Authenticate function, it return nil, ErrNOOP,
// commonly used when token refreshed/mangaed directly using cache or Append function,
// and there is no need to parse token and authenticate request.
func NoOpAuthenticate(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
	return nil, ErrNOOP
}
