package digest

import (
	"crypto"

	"github.com/shaj13/go-guardian/auth"
)

// SetHash set the hashing algorithm to hash the user password.
// Default md5
//
//	SetHash(crypto.SHA1, "sha1")
//
func SetHash(h crypto.Hash, algorithm string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if d, ok := v.(*Digest); ok {
			d.chash = h
			d.h.SetAlgorithm(algorithm)
		}
	})
}

// SetRealm set digest authentication realm.
// Default "Users".
func SetRealm(realm string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if d, ok := v.(*Digest); ok {
			d.h.SetRealm(realm)
		}
	})
}

// SetOpaque set digest opaque.
// Default random generated key.
func SetOpaque(opaque string) auth.Option {
	return auth.OptionFunc(func(v interface{}) {
		if d, ok := v.(*Digest); ok {
			d.h.SetOpaque(opaque)
		}
	})
}
