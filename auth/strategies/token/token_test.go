package token

import (
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
