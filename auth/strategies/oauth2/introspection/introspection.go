// Package introspection provide auth strategy to authenticate,
// incoming HTTP requests using the oauth2 token introspection endpoint,
// as defined in RFC 7662.
// This authentication strategy makes it easy to introduce apps,
// into a oauth2 authorization framework to be used by resource servers or other internal servers.
package introspection

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

// GetAuthenticateFunc return function to authenticate request using oauth2 token introspection endpoint.
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(addr string, opts ...auth.Option) token.AuthenticateFunc {
	intro := newIntrospection(addr, opts...)
	return intro.authenticate
}

// New return strategy authenticate request using oauth2 token introspection endpoint.
//
// New is similar to:
//
// 		fn := introspection.GetAuthenticateFunc(addr, opts...)
// 		token.New(fn, cache, opts...)
//
func New(addr string, c auth.Cache, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(addr, opts...)
	return token.New(fn, c, opts...)
}

func newIntrospection(addr string, opts ...auth.Option) *introspection {
	r := internal.NewRequester(addr)
	r.KeepUnmarshalling = true
	r.Marshal = func(v interface{}) ([]byte, error) {
		u := v.(url.Values)
		return []byte(u.Encode()), nil
	}
	r.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	r.SetHeader("Accept", "application/json")

	intro := new(introspection)
	intro.claimResolver = new(Claims)
	intro.errorResolver = new(oauth2.ResponseError)
	intro.opts = claims.VerifyOptions{}
	intro.requester = r

	for _, opt := range opts {
		opt.Apply(intro.requester)
		opt.Apply(intro)
	}

	return intro
}

type introspection struct {
	opts          claims.VerifyOptions
	claimResolver oauth2.ClaimsResolver
	errorResolver oauth2.ErrorResolver
	requester     *internal.Requester
}

func (i *introspection) authenticate(ctx context.Context, r *http.Request, tokenstr string) (auth.Info, time.Time, error) { //nolint:lll
	t := time.Time{}
	autherr := i.errorResolver.New()
	authclaims := &claimsResponse{
		ClaimsResolver: i.claimResolver.New(),
	}

	data := url.Values{}
	data.Add("token", tokenstr)

	//nolint:bodyclose
	resp, err := i.requester.Do(ctx, data, authclaims, autherr)

	switch {
	case err != nil:
		return nil, t, fmt.Errorf("strategies/oauth2/introspection: %w", err)
	case resp.StatusCode != http.StatusOK:
		return nil, t, fmt.Errorf("strategies/oauth2/introspection: %w", autherr)
	case !authclaims.Active:
		return nil, t, fmt.Errorf("strategies/oauth2/introspection: Token Unauthorized")
	}

	claims := authclaims.ClaimsResolver

	if err := claims.Verify(i.opts); err != nil {
		return nil, t, fmt.Errorf("strategies/oauth2/introspection: %w", err)
	}
	info := claims.Resolve()
	scope := oauth2.Scope(claims)
	token.WithNamedScopes(info, scope...)
	return info, oauth2.ExpiresAt(claims), nil
}
