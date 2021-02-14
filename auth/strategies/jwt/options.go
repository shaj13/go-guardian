package jwt

import (
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
)

// SetAudience sets token audience(aud),
// no default value.
func SetAudience(aud string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if t, ok := v.(*accessToken); ok {
			t.aud = aud
		}
	})
}

// SetIssuer sets token issuer(iss),
// no default value.
func SetIssuer(iss string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if t, ok := v.(*accessToken); ok {
			t.iss = iss
		}
	})
}

// SetExpDuration sets token exp duartion,
// Default Value 5 min.
func SetExpDuration(d time.Duration) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if t, ok := v.(*accessToken); ok {
			t.dur = d
		}
	})
}

// SetNamedScopes sets the access token scopes,
func SetNamedScopes(scp ...string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if t, ok := v.(*accessToken); ok {
			t.scp = scp
		}
	})
}
