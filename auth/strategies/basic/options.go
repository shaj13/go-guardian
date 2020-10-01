package basic

import (
	"crypto"

	"github.com/shaj13/go-guardian/v2/auth"
)

// SetHash set the hashing algorithm to hash the user password.
func SetHash(h crypto.Hash) auth.Option {
	b := basicHashing{h}
	return SetComparator(b)
}

// SetComparator set password comparator.
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
