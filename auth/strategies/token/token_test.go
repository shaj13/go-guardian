package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetType(t *testing.T) {
	cached := new(cachedToken)
	static := new(Static)
	typ := Type("test")

	opt := SetType(typ)

	opt.Apply(cached)
	opt.Apply(static)

	assert.Equal(t, cached.typ, typ)
	assert.Equal(t, static.Type, typ)
}

func TestSetParser(t *testing.T) {
	cached := new(cachedToken)
	static := new(Static)
	p := XHeaderParser("")

	opt := SetParser(p)

	opt.Apply(cached)
	opt.Apply(static)

	assert.True(t, cached.parser != nil)
	assert.True(t, static.Parser != nil)
}
