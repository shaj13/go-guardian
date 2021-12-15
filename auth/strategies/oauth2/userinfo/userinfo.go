// Package userinfo provide auth strategy to authenticate,
// incoming HTTP requests using the oauth2/openid userinfo endpoint,
// as defined in OpenID Connect https://openid.net/specs/openid-connect-core-1_0.html#UserInfo.
// This authentication strategy makes it easy to introduce apps,
// into a oauth2 authorization framework to be used by resource servers or other internal servers.
package userinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/m87carlson/go-guardian/v2/auth"
	"github.com/m87carlson/go-guardian/v2/auth/claims"
	"github.com/m87carlson/go-guardian/v2/auth/internal"
	"github.com/m87carlson/go-guardian/v2/auth/internal/header"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/oauth2"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/token"
)

const wwwauth = "WWW-Authenticate"

// GetAuthenticateFunc return function to authenticate request using oauth2/openid userinfo endpoint.
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(addr string, opts ...auth.Option) token.AuthenticateFunc {
	return newUserInfo(addr, opts...).authenticate
}

// New return strategy authenticate request using oauth2/openid userinfo endpoint.
//
// New is similar to:
//
// 		fn := userinfo.GetAuthenticateFunc(addr, opts...)
// 		token.New(fn, cache, opts...)
//
func New(addr string, c auth.Cache, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(addr, opts...)
	return token.New(fn, c, opts...)
}

func newUserInfo(addr string, opts ...auth.Option) *userinfo {
	r := internal.NewRequester(addr)
	r.KeepUnmarshalling = true
	r.Method = http.MethodGet
	r.SetHeader("Accept", "application/json")

	uinfo := new(userinfo)
	uinfo.requester = r
	uinfo.claimResolver = new(Claims)
	uinfo.errorResolver = new(oauth2.ResponseError)
	uinfo.opts = claims.VerifyOptions{}

	for _, opt := range opts {
		opt.Apply(uinfo.requester)
		opt.Apply(uinfo)
	}

	return uinfo
}

type userinfo struct {
	opts          claims.VerifyOptions
	claimResolver oauth2.ClaimsResolver
	errorResolver oauth2.ErrorResolver
	requester     *internal.Requester
}

func (i *userinfo) authenticate(ctx context.Context, r *http.Request, tokenstr string) (auth.Info, time.Time, error) { //nolint:lll
	autherr := i.errorResolver.New()
	authclaims := i.claimResolver.New()
	f := func(r *http.Request) {
		r.Header.Set("Authorization", string(token.Bearer)+" "+tokenstr)
	}
	fail := func(err error) (auth.Info, time.Time, error) {
		return nil, time.Time{}, fmt.Errorf("strategies/oauth2/userinfo: %w", err)
	}

	//nolint:bodyclose
	resp, err := i.requester.DoWithf(ctx, f, nil, authclaims, autherr)

	switch {
	case err != nil:
		return fail(err)
	case resp.StatusCode != http.StatusOK && resp.Body != http.NoBody:
		return fail(autherr)
	case resp.StatusCode != http.StatusOK && len(resp.Header.Get(wwwauth)) > len(token.Bearer):
		return fail(
			errorFromHeader(resp.Header, autherr),
		)
	case resp.StatusCode != http.StatusOK:
		err := fmt.Errorf("Authorization server returned %v status code", resp.StatusCode)
		return fail(err)
	}

	if err := authclaims.Verify(i.opts); err != nil {
		return fail(err)
	}
	info := authclaims.Resolve()
	scope := oauth2.Scope(authclaims)
	token.WithNamedScopes(info, scope...)
	return info, oauth2.ExpiresAt(authclaims), nil
}

func errorFromHeader(h http.Header, autherr oauth2.ErrorResolver) error {
	result := header.ParsePairs(h, wwwauth)

	buf, err := json.Marshal(&result)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(buf, autherr); err != nil {
		return err
	}

	return autherr
}
