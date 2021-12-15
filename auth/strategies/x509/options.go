package x509

import (
	"regexp"

	"github.com/m87carlson/go-guardian/v2/auth"
)

// SetInfoBuilder sets x509 info builder.
func SetInfoBuilder(ib InfoBuilder) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*strategy); ok {
			s.builder = ib
		}
	})
}

// SetAllowEmptyCN prevent strategy from return ErrMissingCN
// when client certificate subject CN missing or empty.
func SetAllowEmptyCN() auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*strategy); ok {
			s.emptyCN = true
		}
	})
}

// SetAllowedCN sets the common names which a verified certificate is allowed to have.
func SetAllowedCN(cns ...string) auth.Option {
	allowedCNS := map[string]struct{}{}
	for _, cn := range cns {
		allowedCNS[cn] = struct{}{}
	}

	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*strategy); ok {
			s.allowedCN = func(cn string) bool {
				_, ok := allowedCNS[cn]
				return ok
			}
		}
	})
}

// SetAllowedCNRegex sets the common names regex which a verified certificate is allowed to have.
func SetAllowedCNRegex(str string) auth.Option {
	regex := regexp.MustCompile(str)
	return auth.OptionFunc(func(v interface{}) {
		if s, ok := v.(*strategy); ok {
			s.allowedCN = func(cn string) bool {
				return regex.MatchString(cn)
			}
		}
	})
}
