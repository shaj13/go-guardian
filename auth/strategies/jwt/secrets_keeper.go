package jwt

import (
	"errors"
)

// SecretsKeeper hold all secrets/keys to sign and parse JWT token
type SecretsKeeper interface {
	// KID return's secret/key id.
	// KID must return the most recently used id if more than one secret/key exists.
	// https://tools.ietf.org/html/rfc7515#section-4.1.4
	KID() string
	// Get return's secret/key and the corresponding sign algorithm.
	Get(kid string) (key interface{}, algorithm string, err error)
}

// StaticSecret implements the SecretsKeeper and holds only a single secret.
type StaticSecret struct {
	Secret    interface{}
	ID        string
	Algorithm string
}

// KID return's secret/key id.
func (s StaticSecret) KID() string {
	return s.ID
}

// Get return's secret/key and the corresponding sign algorithm.
func (s StaticSecret) Get(kid string) (key interface{}, algorithm string, err error) {
	if kid != s.ID {
		msg := "strategies/jwt: Invalid " + kid + " KID"
		return nil, "", errors.New(msg)
	}

	return s.Secret, s.Algorithm, nil
}
