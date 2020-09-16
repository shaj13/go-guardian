package basic

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicHashing(t *testing.T) {
	b := basicHashing{h: crypto.SHA256}
	pass := "password"
	hash, err := b.Hash(pass)
	match := b.Verify(hash, pass)
	missmatch := b.Verify(hash, "pass")

	assert.NoError(t, err)
	assert.NotEqual(t, hash, pass)
	assert.NoError(t, match)
	assert.Equal(t, ErrInvalidCredentials, missmatch)
}

func TestPlainText(t *testing.T) {
	p := plainText{}
	pass := "password"
	hash, err := p.Hash(pass)
	match := p.Verify(hash, pass)
	missmatch := p.Verify(hash, "pass")

	assert.NoError(t, err)
	assert.Equal(t, hash, pass)
	assert.NoError(t, match)
	assert.Equal(t, ErrInvalidCredentials, missmatch)
}
