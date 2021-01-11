package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"

	"github.com/shaj13/go-guardian/v2/auth"
)

// SetAudience sets token audience(aud),
// no default value.
func SetAudience(aud string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if t, ok := v.(*accessToken); ok {
			t.aud = jwt.ClaimStrings{aud}
		}
	})
}

// SetIssuer sets token issuer(iss),
// Default Value "go-guardian".
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
			t.d = d
		}
	})
}
