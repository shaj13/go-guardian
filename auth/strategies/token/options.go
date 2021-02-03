package token

import (
	"crypto"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
)

// SetType sets the authentication token type or scheme,
// used for HTTP WWW-Authenticate header.
//
// Deprecated: No longer used.
func SetType(t Type) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
	})
}

// SetParser sets the strategy token parser.
func SetParser(p Parser) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*core); ok {
			v.parser = p
		}
	})
}

// SetScopes sets the scopes to be used when verifying user access token.
func SetScopes(scopes ...Scope) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*core); ok {
			v.verify = verifyScopes(scopes...)
		}
	})
}

// SetHash apply token hashing based on HMAC with h and key,
// To prevent precomputation and length extension attacks,
// and to mitigates hash map DOS attacks via collisions.
func SetHash(h crypto.Hash, key []byte) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*core); ok {
			v.hasher = internal.NewHMACHasher(h, key)
		}
	})
}
