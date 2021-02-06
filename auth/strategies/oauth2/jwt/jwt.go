// Package jwt provides authentication strategy,
// incoming HTTP requests using the oauth2 jwt access token
// or openid IDToken.
// This authentication strategy makes it easy to introduce apps,
// into a oauth2 authorization framework to be used by resource servers or other servers.
package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal/jwt"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

var (
	// ErrMissingKID is returned by Authenticate Strategy method,
	// when failed to retrieve kid from token header.
	ErrMissingKID = jwt.ErrMissingKID

	// ErrInvalidAlg is returned by Authenticate Strategy method,
	// when jwt token alg header does not match key algorithm.
	ErrInvalidAlg = jwt.ErrInvalidAlg
)

// GetAuthenticateFunc return function to authenticate request using oauth2
// jwt access token or openid IDToken.
//
// The underlying AuthenticateFunc cached JWKS based on the cache-control header if exist,
// Otherwise, fallback to an interval duration.
//
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(addr string, opts ...auth.Option) token.AuthenticateFunc {
	return newStrategy(addr, opts...).authenticate
}

// New return strategy authenticate request using oauth2
// jwt token access token or openid IDToken..
//
// New is similar to:
//
// 		fn := jwt.GetAuthenticateFunc(addr, opts...)
// 		token.New(fn, cache, opts...)
//
func New(addr string, c auth.Cache, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(addr, opts...)
	return token.New(fn, c, opts...)
}

func newStrategy(addr string, opts ...auth.Option) *strategy {
	strategy := new(strategy)
	strategy.jwks = newJWKS(addr)
	strategy.claimResolver = new(Claims)
	for _, opt := range opts {
		opt.Apply(strategy)
		opt.Apply(strategy.jwks)
		opt.Apply(strategy.jwks.requester)
	}
	return strategy
}

type strategy struct {
	jwks          *jwks
	opts          claims.VerifyOptions
	claimResolver oauth2.ClaimsResolver
}

func (s *strategy) authenticate(ctx context.Context, r *http.Request, tokenstr string) (auth.Info, time.Time, error) { //nolint:lll
	fail := func(err error) (auth.Info, time.Time, error) {
		return nil, time.Time{}, fmt.Errorf("strategies/oauth2/jwt: %w", err)
	}

	claims := s.claimResolver.New()

	if err := jwt.ParseToken(s.jwks, tokenstr, claims); err != nil {
		return fail(err)
	}

	if err := claims.Verify(s.opts); err != nil {
		return fail(err)
	}

	info := claims.Resolve()
	scope := oauth2.Scope(claims)
	token.WithNamedScopes(info, scope...)

	return info, oauth2.ExpiresAt(claims), nil
}
