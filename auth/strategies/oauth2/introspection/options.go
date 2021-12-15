package introspection

import (
	"crypto/tls"
	"net/http"

	"github.com/m87carlson/go-guardian/v2/auth"
	"github.com/m87carlson/go-guardian/v2/auth/claims"
	"github.com/m87carlson/go-guardian/v2/auth/internal"
	"github.com/m87carlson/go-guardian/v2/auth/strategies/oauth2"
)

// SetBasicAuth sets the introspection request's Authorization header to use
// HTTP Basic Authentication with the provided clientid and clientsecret.
func SetBasicAuth(clientid, clinetsecret string) auth.Option {
	return internal.SetRequesterBasicAuth(clientid, clinetsecret)
}

// SetAuthorizationToken sets the introspection request's Authorization header to use
// HTTP Bearer Authentication with the provided token.
func SetAuthorizationToken(token string) auth.Option {
	return internal.SetRequesterBearerToken(token)
}

// SetHTTPClient sets underlying http client.
func SetHTTPClient(c *http.Client) auth.Option {
	return internal.SetRequesterHTTPClient(c)
}

// SetTLSConfig ssets underlying http client tls.
func SetTLSConfig(tls *tls.Config) auth.Option {
	return internal.SetRequesterTLSConfig(tls)
}

// SetClientTransport sets underlying http client transport.
func SetClientTransport(rt http.RoundTripper) auth.Option {
	return internal.SetRequesterClientTransport(rt)
}

// SetClaimResolver sets the introspection strategy ClaimResolver to resolve
// the authorization claim response.
// Default: introspection.Claim
func SetClaimResolver(c oauth2.ClaimsResolver) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*introspection); ok {
			k.claimResolver = c
		}
	})
}

// SetErrorResolver sets the introspection strategy ErrorResolver to resolve
// the authorization error response.
// Default: oauth2.ResponseError
func SetErrorResolver(e oauth2.ErrorResolver) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*introspection); ok {
			k.errorResolver = e
		}
	})
}

// SetVerifyOptions sets the introspection strategy to
// verify authorization response.
func SetVerifyOptions(opts claims.VerifyOptions) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*introspection); ok {
			k.opts = opts
		}
	})
}
