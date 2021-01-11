package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go/v4"
)

// SecretsKeeper hold all secrets/keys to sign and parse JWT token
type SecretsKeeper interface {
	// KID return's secret/key id.
	// KID must return the least recently used id if more than one secret/key exists.
	// https://tools.ietf.org/html/rfc7515#section-4.1.4
	KID() string
	// Get return's secret/key and the corresponding sign method.
	Get(kid string) (key interface{}, m jwt.SigningMethod, err error)
}

// StaticSecret implements the SecretsKeeper and holds only a single secret.
type StaticSecret struct {
	Secret interface{}
	ID     string
	Method jwt.SigningMethod
}

// KID return's secret/key id.
func (s StaticSecret) KID() string {
	return s.ID
}

// Get return's secret/key and the corresponding sign method.
func (s StaticSecret) Get(kid string) (key interface{}, m jwt.SigningMethod, err error) {
	if kid != s.ID {
		msg := "strategies/basic: Invalid " + kid + " KID"
		return nil, nil, errors.New(msg)
	}

	return s.Secret, s.Method, nil
}
