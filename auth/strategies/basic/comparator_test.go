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
	match := b.Compare(hash, pass)
	missmatch := b.Compare(hash, "pass")

	assert.NoError(t, err)
	assert.NotEqual(t, hash, pass)
	assert.NoError(t, match)
	assert.Equal(t, ErrInvalidCredentials, missmatch)
}

func TestPlainText(t *testing.T) {
	p := plainText{}
	pass := "password"
	hash, err := p.Hash(pass)
	match := p.Compare(hash, pass)
	missmatch := p.Compare(hash, "pass")

	assert.NoError(t, err)
	assert.Equal(t, hash, pass)
	assert.NoError(t, match)
	assert.Equal(t, ErrInvalidCredentials, missmatch)
}
