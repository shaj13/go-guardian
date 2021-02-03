package token

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetParser(t *testing.T) {
	c := new(core)
	p := XHeaderParser("")
	opt := SetParser(p)
	opt.Apply(c)
	assert.True(t, c.parser != nil)
}

func TestSetScopes(t *testing.T) {
	c := new(core)
	opt := SetScopes(NewScope("admin", "", ""))
	opt.Apply(c)
	assert.True(t, c.verify != nil)
}

func TestSetHash(t *testing.T) {
	const token = "token"
	c := new(core)
	opt := SetHash(crypto.SHA256, []byte("key"))
	opt.Apply(c)
	assert.True(t, c.hasher != nil)
	assert.NotEqual(t, token, c.hasher.Hash(token))
}
