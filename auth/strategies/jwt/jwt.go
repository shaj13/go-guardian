// Package jwt provides authentication strategy,
// to authenticate HTTP requests based on jwt token.
package jwt

import (
	"context"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

// GetAuthenticateFunc return function to authenticate request using jwt token.
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(s SecretsKeeper, opts ...auth.Option) token.AuthenticateFunc {
	t := newAccessToken(s, opts...)
	return func(ctx context.Context, r *http.Request, tk string) (auth.Info, time.Time, error) {
		c, info, err := t.parse(tk)
		if err != nil {
			return nil, time.Time{}, err
		}

		if len(c.Scope) > 0 {
			token.WithNamedScopes(info, c.Scope.Split()...)
		}

		return info, time.Time(*c.ExpiresAt), nil
	}
}

// New return strategy authenticate request using jwt token.
//
// New is similar to:
//
// 		fn := jwt.GetAuthenticateFunc(secretsKeeper, opts...)
// 		token.New(fn, cache, opts...)
//
func New(c auth.Cache, s SecretsKeeper, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(s, opts...)
	return token.New(fn, c, opts...)
}
