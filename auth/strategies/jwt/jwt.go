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
	return func(ctx context.Context, r *http.Request, token string) (auth.Info, time.Time, error) {
		c, err := t.parse(token)
		return c.UserInfo, c.Expiration, err
	}
}

// New return strategy authenticate request using jwt token.
// New is similar to token.New().
func New(c auth.Cache, s SecretsKeeper, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(s, opts...)
	return token.New(fn, c, opts...)
}
