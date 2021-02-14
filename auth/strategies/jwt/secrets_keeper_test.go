package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticSecretGet(t *testing.T) {
	t.Run("StaticSecretGet always return same secret", func(t *testing.T) {
		kid := "test-kid"
		secret := []byte("test-secret")
		s := StaticSecret{
			ID:        kid,
			Algorithm: HS256,
			Secret:    secret,
		}
		for i := 0; i < 10; i++ {
			gotSecret, gotAlg, err := s.Get(kid)
			assert.NoError(t, err)
			assert.Equal(t, secret, gotSecret)
			assert.Equal(t, HS256, gotAlg)
		}
	})

	t.Run("StaticSecretGet return error when kid invalid", func(t *testing.T) {
		s := StaticSecret{}
		secret, alg, err := s.Get("kid")
		assert.Error(t, err)
		assert.Nil(t, secret)
		assert.Empty(t, alg)
	})
}
