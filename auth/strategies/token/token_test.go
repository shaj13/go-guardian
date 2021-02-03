package token

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetType(t *testing.T) {
	cached := new(cachedToken)
	static := new(static)
	typ := Type("test")

	opt := SetType(typ)

	opt.Apply(cached)
	opt.Apply(static)

	assert.Equal(t, cached.typ, typ)
	assert.Equal(t, static.ttype, typ)
}

func TestSetParser(t *testing.T) {
	cached := new(cachedToken)
	static := new(static)
	p := XHeaderParser("")

	opt := SetParser(p)

	opt.Apply(cached)
	opt.Apply(static)

	assert.True(t, cached.parser != nil)
	assert.True(t, static.parser != nil)
}

func TestSetScopes(t *testing.T) {

	cached := new(cachedToken)
	static := new(static)

	opt := SetScopes(NewScope("admin", "", ""))

	opt.Apply(cached)
	opt.Apply(static)

	assert.True(t, cached.verify != nil)
	assert.True(t, static.verify != nil)
}

func TestSetHash(t *testing.T) {
	const token = "token"
	cached := new(cachedToken)
	static := new(static)
	opt := SetHash(crypto.SHA256, []byte("key"))
	opt.Apply(cached)
	opt.Apply(static)
	assert.True(t, cached.h != nil)
	assert.NotEqual(t, token, cached.h.Hash(token))
	assert.True(t, static.h != nil)
	assert.NotEqual(t, token, static.h.Hash(token))
}
