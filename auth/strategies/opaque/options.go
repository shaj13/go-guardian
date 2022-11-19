package opaque

import (
	"crypto"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
)

// WithTokenLength is the size of tokens to generate.
//
// Default is 24.
func WithTokenLength(length int) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if o, ok := v.(*opaque); ok {
			o.tokenLength = length
		}
	})
}

// WithExpDuration sets token exp duartion,
//
// Default is 24h.
func WithExpDuration(dur time.Duration) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if o, ok := v.(*opaque); ok {
			o.exp = dur
		}
	})
}

// WithTokenPrefix sets token prefix.
//
// Default is "s".
func WithTokenPrefix(prefix string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if o, ok := v.(*opaque); ok {
			o.prefix = prefix
		}
	})
}

// WithHash sets HMAC hash function.
//
// Default is crypto.SHA512_256.
func WithHash(h crypto.Hash) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if o, ok := v.(*opaque); ok {
			o.h = h
		}
	})
}
