package basic

import (
	"crypto"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/internal"
)

// SetHash apply password hashing using h,
// SetHash only used when caching the auth decision,
// to mitigates brute force attacks.
func SetHash(h crypto.Hash) auth.Option {
	b := basicHashing{h}
	return SetComparator(b)
}

// SetComparator set password comparator,
// to be used when caching the auth decision.
func SetComparator(c Comparator) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*cachedBasic); ok {
			v.comparator = c
		}
	})
}

// SetParser set credentials parser.
func SetParser(p Parser) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*basic); ok {
			v.parser = p
		}
	})
}

// SetUserNameHash apply username hashing based on HMAC with h and key,
// SetUserNameHash only used when caching the auth decision,
// to prevent precomputation and length extension attacks,
// and to mitigates hash map DOS attacks via collisions.
func SetUserNameHash(h crypto.Hash, key []byte) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if v, ok := v.(*cachedBasic); ok {
			v.hasher = internal.NewHMACHasher(h, key)
		}
	})
}
