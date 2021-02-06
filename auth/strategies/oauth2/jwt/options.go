package jwt

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
)

// SetHTTPClient sets the underlying http client that used to get JWKS.
func SetHTTPClient(c *http.Client) auth.Option {
	return internal.SetRequesterHTTPClient(c)
}

// SetTLSConfig sets tls config underlying http client tls that used to get JWKS.
func SetTLSConfig(tls *tls.Config) auth.Option {
	return internal.SetRequesterTLSConfig(tls)
}

// SetClientTransport sets underlying http client transport that used to get JWKS.
func SetClientTransport(rt http.RoundTripper) auth.Option {
	return internal.SetRequesterClientTransport(rt)
}

// SetClaimResolver sets the jwt strategy ClaimResolver
// to resolve the jwt claims.
// Default: jwt.Claim
func SetClaimResolver(c oauth2.ClaimsResolver) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*strategy); ok {
			s.claimResolver = c
		}
	})
}

// SetVerifyOptions sets the jwt strategy
// to verify the jwt claims.
func SetVerifyOptions(opts claims.VerifyOptions) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*strategy); ok {
			s.opts = opts
		}
	})
}

// SetInterval sets the fallback interval duration to refresh JWKS occasionally.
// Default: 5 min.
func SetInterval(d time.Duration) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*jwks); ok {
			s.interval = d
		}
	})
}
