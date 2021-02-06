package userinfo

import (
	"crypto/tls"
	"net/http"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

// SetHTTPMethod sets http request's method.
// Default Get.
func SetHTTPMethod(method string) auth.Option {
	return internal.SetRequesterMethod(method)
}

// SetHTTPClient sets underlying http client.
func SetHTTPClient(c *http.Client) auth.Option {
	return internal.SetRequesterHTTPClient(c)
}

// SetTLSConfig sets underlying http client tls.
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
		if k, ok := v.(*userinfo); ok {
			k.claimResolver = c
		}
	})
}

// SetErrorResolver sets the introspection strategy ErrorResolver to resolve
// the authorization error response.
// Default: oauth2.ResponseError
func SetErrorResolver(e oauth2.ErrorResolver) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*userinfo); ok {
			k.errorResolver = e
		}
	})
}

// SetVerifyOptions sets the introspection strategy to
// verify authorization response.
func SetVerifyOptions(opts claims.VerifyOptions) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if k, ok := v.(*userinfo); ok {
			k.opts = opts
		}
	})
}
