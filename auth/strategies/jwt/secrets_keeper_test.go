package jwt

import (
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
)

func TestStaticSecretGet(t *testing.T) {
	t.Run("StaticSecretGet always return same secret", func(t *testing.T) {
		method := jwt.SigningMethodHS256
		kid := "test-kid"
		secret := []byte("test-secret")
		s := StaticSecret{
			ID:     kid,
			Method: method,
			Secret: secret,
		}
		for i := 0; i < 10; i++ {
			gotSecret, gotMethod, err := s.Get(kid)
			assert.NoError(t, err)
			assert.Equal(t, secret, gotSecret)
			assert.Equal(t, method, gotMethod)
		}
	})

	t.Run("StaticSecretGet return error when kid invalid", func(t *testing.T) {
		s := StaticSecret{}
		secret, method, err := s.Get("kid")
		assert.Error(t, err)
		assert.Nil(t, secret)
		assert.Nil(t, method)
	})
}
